"""ABDM Health Information User (HIU): requesting and receiving patients' records from other providers.

Sections, in order:
- Received records: sealing at rest, reading FHIR bundles into facts, lab trends.
- AI assistance: request suggestions and source-cited summaries (suggestions only).
- HIU workflow: consent request -> artefact -> health-information request -> encrypted push -> storage.
- Simulator: consent manager and patient decisions for the HIU workflow (simulation mode only).
- API routes: HIU staff API (/api/hiu/...), the data push endpoint and the HIU callbacks (/api/v3/hiu/...).

Builds on app.hip for the gateway client, transaction log and encryption.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import uuid
from datetime import date, datetime, time, timedelta, timezone
from typing import Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import ai, fhir, hip
from app.ai import AIError
from app.config import settings
from app.database import SessionLocal, get_db
from app.fhir import (ClinicalContent, Coding, ConditionData, EncounterData, LOINC, MedicationData, ReportData,
                      ResultData, build_bundle)
from app.hip import accept, after_change, facility_names, hospital_for, parse_time, record, utc
from app.models import (Doctor, Encounter, HipTransaction, HiuConsentArtefact, HiuConsentRequest, HiuDataRequest,
                        HiuPatientSummary, Hospital, Patient, Prescription, RetrievedRecord, User, utcnow)
from app.schemas import ORMModel, Page, PatientSummary, UTCDateTime
from app.security import require
from app.services import audit, current_doctor, get_or_404, paginate


# ====================================================================================================================
# Received records: sealing at rest and reading FHIR bundles (formerly app/hiu/records.py)
# ====================================================================================================================

NRCES = "https://nrces.in/ndhm/fhir/r4/StructureDefinition/"
CATEGORIES = {"OPConsultRecord": "OPD consultation", "PrescriptionRecord": "Prescription",
              "DiagnosticReportRecord": "Laboratory report", "DischargeSummaryRecord": "Discharge summary",
              "ImmunizationRecord": "Immunization", "WellnessRecord": "Wellness record",
              "HealthDocumentRecord": "Health document"}
SNOMED_TYPES = {"371530004": "OPConsultRecord", "440545006": "PrescriptionRecord", "721981007": "DiagnosticReportRecord",
                "373942005": "DischargeSummaryRecord", "41000179103": "ImmunizationRecord", "419891008": "HealthDocumentRecord"}


# ---------- sealing (encryption at rest) ----------
# Sealed values look like "v2.<key id>.<base64(nonce + AES-GCM ciphertext)>"; the key id says which
# RECORD_SEALING_KEY encrypted it, so keys can be rotated (old keys stay readable via RECORD_SEALING_OLD_KEYS,
# and scripts/reseal_records.py moves everything to the active key). Values without a prefix were sealed with
# the legacy key derived from JWT_SECRET.

SEALED_V2 = "v2"


def _derive(secret: str, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(secret.encode())

def _legacy_key() -> bytes:
    return _derive(settings.jwt_secret, b"abdm-hospital-hiu-storage", b"v1")

def _sealing_key(secret: str) -> tuple[str, bytes]:
    key = _derive(secret, b"abdm-hospital-record-sealing", b"v2")
    return hashlib.sha256(key).hexdigest()[:12], key

class SealingKeyMissing(RuntimeError):
    """A sealed value names a key that is not configured (neither RECORD_SEALING_KEY nor an old key)."""

def active_key_id() -> str | None:
    return _sealing_key(settings.record_sealing_key)[0] if settings.record_sealing_key else None

def seal(text: str) -> str:
    nonce = os.urandom(12)
    if not settings.record_sealing_key:  # legacy mode: unchanged format and key
        return base64.b64encode(nonce + AESGCM(_legacy_key()).encrypt(nonce, text.encode(), None)).decode()
    key_id, key = _sealing_key(settings.record_sealing_key)
    body = base64.b64encode(nonce + AESGCM(key).encrypt(nonce, text.encode(), None)).decode()
    return f"{SEALED_V2}.{key_id}.{body}"

def unseal(sealed: str) -> str:
    if sealed.startswith(SEALED_V2 + "."):
        _, key_id, body = sealed.split(".", 2)
        secrets = [k for k in [settings.record_sealing_key, *settings.record_sealing_old_key_list] if k]
        key = next((k for kid, k in map(_sealing_key, secrets) if kid == key_id), None)
        if key is None:
            raise SealingKeyMissing(f"Sealed with key {key_id}, which is not configured")
    else:
        key, body = _legacy_key(), sealed
    raw = base64.b64decode(body)
    return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode()


def needs_reseal(sealed: str) -> bool:
    """True when `sealed` is not encrypted with the active key."""
    key_id = active_key_id()
    return key_id is not None and not sealed.startswith(f"{SEALED_V2}.{key_id}.")


# ---------- normalised, read-only view ----------

def _text(concept: dict | None) -> str | None:
    if not concept:
        return None
    return concept.get("text") or next((c.get("display") for c in concept.get("coding", []) if c.get("display")), None)


def _code(concept: dict | None, system: str) -> str | None:
    return next((c.get("code") for c in (concept or {}).get("coding", []) if c.get("system") == system), None)


def _narrative(resource: dict) -> str:
    return " ".join(re.sub(r"<[^>]+>", " ", (resource.get("text") or {}).get("div", "")).split())


def _time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00") if len(value) > 10 else value + "T00:00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo is None else parsed.astimezone(timezone.utc).replace(tzinfo=None)


def record_type(bundle: dict) -> str | None:
    composition = next((e["resource"] for e in bundle.get("entry", []) if e.get("resource", {}).get("resourceType") == "Composition"), {})
    for profile in (composition.get("meta") or {}).get("profile", []):
        if profile.startswith(NRCES) and profile.removeprefix(NRCES) in CATEGORIES:
            return profile.removeprefix(NRCES)
    code = _code(composition.get("type"), "http://snomed.info/sct")
    if code in SNOMED_TYPES:
        return SNOMED_TYPES[code]
    return "WellnessRecord" if (composition.get("type") or {}).get("text") == "Wellness Record" else None


def describe(bundle: dict) -> dict:
    """Facts shown to doctors and given to the AI: copied from the bundle, never inferred."""
    resources = [e.get("resource", {}) for e in bundle.get("entry", [])]
    by_type = lambda t: [r for r in resources if r.get("resourceType") == t]  # noqa: E731
    composition = (by_type("Composition") or [{}])[0]
    kind = record_type(bundle)
    when = composition.get("date")
    observations = []
    for o in by_type("Observation"):
        quantity = o.get("valueQuantity") or {}
        ref = (o.get("referenceRange") or [{}])[0]
        category = _code((o.get("category") or [{}])[0], "http://terminology.hl7.org/CodeSystem/observation-category")
        observations.append({
            "name": _text(o.get("code")), "loinc": _code(o.get("code"), "http://loinc.org"), "category": category,
            "value": quantity.get("value"), "unit": quantity.get("unit") or quantity.get("code"),
            "value_text": o.get("valueString"), "date": o.get("effectiveDateTime") or when,
            "reference_range": ref.get("text") or " – ".join(str(ref[k]["value"]) for k in ("low", "high") if k in ref) or None,
            "interpretation": _code((o.get("interpretation") or [{}])[0], "http://terminology.hl7.org/CodeSystem/v3-ObservationInterpretation"),
            "components": [{"name": _text(c.get("code")), "value": (c.get("valueQuantity") or {}).get("value"),
                            "unit": (c.get("valueQuantity") or {}).get("unit")} for c in o.get("component", [])] or None,
        })
    return {
        "record_type": kind, "category": CATEGORIES.get(kind, "Other record"), "date": when,
        "title": composition.get("title"),
        "source": next((o.get("name") for o in by_type("Organization")), None),
        "authors": [a.get("display") for a in composition.get("author", []) if a.get("display")],
        "conditions": [{"text": _text(c.get("code")), "icd10": _code(c.get("code"), "http://hl7.org/fhir/sid/icd-10"),
                        "status": _code(c.get("clinicalStatus"), "http://terminology.hl7.org/CodeSystem/condition-clinical")}
                       for c in by_type("Condition")],
        "medications": [{"name": _text(m.get("medicationCodeableConcept")),
                         "dosage": ((m.get("dosageInstruction") or [{}])[0]).get("text"), "status": m.get("status")}
                        for m in by_type("MedicationRequest")],
        "observations": observations,
        "reports": [{"name": _text(d.get("code")), "conclusion": d.get("conclusion")} for d in by_type("DiagnosticReport")],
        "immunizations": [{"vaccine": _text(i.get("vaccineCode")), "date": i.get("occurrenceDateTime")} for i in by_type("Immunization")],
        "allergies": [_text(a.get("code")) for a in by_type("AllergyIntolerance")],
        "sections": [{"title": s.get("title"), "text": _narrative(s)} for s in composition.get("section", []) if _narrative(s)],
        "attachments": [d.get("content", [{}])[0].get("attachment", {}).get("title") for d in by_type("DocumentReference")],
    }


def timeline(records: list[tuple[int, dict]]) -> list[dict]:
    """[(record id, describe() facts)] -> chronological entries, newest first."""
    entries = [{"record_id": rid, "date": f["date"], "category": f["category"], "source": f["source"],
                "highlights": [c["text"] for c in f["conditions"] if c["text"]][:3]
                + [m["name"] for m in f["medications"] if m["name"]][:3]
                + [r["name"] for r in f["reports"] if r["name"]][:2]} for rid, f in records]
    return sorted(entries, key=lambda e: _time(e["date"]) or datetime.min, reverse=True)


def lab_trends(records: list[tuple[int, dict]]) -> list[dict]:
    """Laboratory tests seen more than once. Values are compared only for the same test (LOINC code, else the
    exact name) in the same unit; otherwise the repeat is listed without comparison."""
    groups: dict[tuple, dict] = {}
    for rid, f in records:
        for o in f["observations"]:
            if o["category"] != "laboratory" or not o["name"]:
                continue
            key = ("loinc", o["loinc"]) if o["loinc"] else ("name", o["name"].strip().lower())
            group = groups.setdefault(key, {"test": o["name"], "loinc": o["loinc"], "points": []})
            group["points"].append({"record_id": rid, "date": o["date"], "value": o["value"], "value_text": o["value_text"],
                                    "unit": o["unit"], "interpretation": o["interpretation"],
                                    "reference_range": o["reference_range"]})
    trends = []
    for group in groups.values():
        if len(group["points"]) < 2:
            continue
        points = sorted(group["points"], key=lambda p: _time(p["date"]) or datetime.min)
        units = {p["unit"] for p in points}
        comparable = len(units) == 1 and all(isinstance(p["value"], (int, float)) for p in points)
        trend = {**group, "points": points, "comparable": comparable,
                 "note": None if comparable else "Not compared: units differ or values are not numeric"}
        if comparable:
            first, last = points[0]["value"], points[-1]["value"]
            trend["change"] = round(last - first, 3)
        trends.append(trend)
    return sorted(trends, key=lambda t: t["test"].lower())


def bundle_json(record) -> dict:
    return json.loads(unseal(record.content))


# ====================================================================================================================
# AI assistance (formerly app/hiu/ai.py)
# ====================================================================================================================
# AI assistance for the HIU: suggest a request and summarise retrieved records.
#
# AI never creates, approves or submits a consent request, never decides what may be decrypted, and only
# summarises facts copied from received records; every statement must cite those records (checked below).

PURPOSES = {"CAREMGT": "Care Management", "BTG": "Break the Glass", "PUBHLTH": "Public Health",
            "HPAYMT": "Healthcare Payment", "DSRCH": "Disease Specific Healthcare Research", "PATRQT": "Self Requested"}
HI_TYPES = ["OPConsultation", "Prescription", "DiagnosticReport", "DischargeSummary", "ImmunizationRecord",
            "HealthDocumentRecord", "WellnessRecord"]
Purpose = Literal["CAREMGT", "BTG", "PUBHLTH", "HPAYMT", "DSRCH", "PATRQT"]
HiType = Literal["OPConsultation", "Prescription", "DiagnosticReport", "DischargeSummary", "ImmunizationRecord",
                 "HealthDocumentRecord", "WellnessRecord"]


class RequestSuggestion(BaseModel):
    purpose_code: Purpose
    hi_types: list[HiType]
    date_from: str | None = Field(description="YYYY-MM-DD, or null when no range is needed")
    date_to: str | None = Field(description="YYYY-MM-DD, or null for today")
    missing_information: list[str] = Field(description="Information staff should add or confirm before submitting")
    explanation: str = Field(description="Two or three sentences on why these records may help, based only on the context")


class SummaryItem(BaseModel):
    text: str
    source_record_ids: list[int] = Field(description="Ids of the records this statement is taken from")


class RecordsSummary(BaseModel):
    overview: list[SummaryItem]
    consultations: list[SummaryItem]
    prescriptions: list[SummaryItem]
    laboratory: list[SummaryItem]


SUGGEST_PROMPT = """You help hospital staff prepare a request for a patient's records from other providers under India's
ABDM consent framework. Suggest the purpose of use, the record categories (hiTypes) and a date range that are
proportionate to the stated clinical reason; ask for less rather than more. Base the explanation only on the context
given. List missing information (e.g. an unclear reason). You do not create, submit or approve anything: staff review
every suggestion and the patient decides on consent."""

SUMMARY_PROMPT = """You summarise health records a hospital received from other providers, for the treating doctor.
Use only the facts in the records provided. Never add diagnoses, interpretations, causes or recommendations that are not
written in the records. Every item must list the ids of the records it comes from in source_record_ids. Keep items short.
Write "overview" (key documented conditions and events), "consultations", "prescriptions" (medicines over time) and
"laboratory" (repeated tests and documented values, quoting units). Leave a list empty when there is nothing to say."""


def call_model(system: str, payload: dict, output_format):
    """The model call; replaced by a fake in tests."""
    return ai.structured(system, [{"type": "text", "text": json.dumps(payload, default=str)}], output_format, max_tokens=8000)


def suggest_request(context: dict) -> dict:
    suggestion = call_model(SUGGEST_PROMPT, context, RequestSuggestion)
    result = suggestion.model_dump()
    for key in ("date_from", "date_to"):  # drop unusable dates rather than guessing
        try:
            if result[key] and date.fromisoformat(result[key]) > date.today():
                result[key] = None
        except ValueError:
            result[key] = None
    result["hi_types"] = sorted(set(result["hi_types"]))
    return result


def summarize_records(records: list[dict]) -> dict:
    """records: [{"record_id", ...facts}]. Items citing no or unknown records are removed."""
    known = {r["record_id"] for r in records}
    summary = call_model(SUMMARY_PROMPT, {"records": records}, RecordsSummary).model_dump()
    removed = 0
    for section, items in summary.items():
        kept = [i for i in items if i["source_record_ids"] and set(i["source_record_ids"]) <= known]
        removed += len(items) - len(kept)
        summary[section] = kept
    summary["removed_unsupported_items"] = removed
    return summary


# ====================================================================================================================
# HIU workflow (formerly app/hiu/service.py)
# ====================================================================================================================
# HIU workflow (ABDM Milestone 3): consent request -> notification -> artefact fetch and validation ->
# health-information request -> asynchronous encrypted push -> decryption, storage and status notification.
#
# Every step is a separate callback; nothing proceeds without a GRANTED artefact that validates against the
# request. Reuses the HIP gateway client, transaction log and Fidelius-compatible crypto.

PURPOSE_REF_URI = "www.abdm.gov.in"  # as in NHA's consent request example
REQUESTER_SYSTEM = "https://www.mciindia.org"


class HiuError(Exception):
    pass


def iso(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds") + "Z"


def push_url(token: str) -> str:
    return f"{settings.abdm_bridge_url or 'sim://hiu'}/api/hiu/data-push/{token}"


def hiu_headers(hospital: Hospital, request_id: str | None = None) -> dict:
    """Headers of an HIU call made for one hospital (its own HIU ID)."""
    return {"X-HIU-ID": hip.hospital_hiu_id(hospital), **({"REQUEST-ID": request_id} if request_id else {})}


# ---------- 1. consent request ----------

def create_consent_request(db: Session, user: User, patient: Patient, doctor: Doctor, purpose: str, hi_types: list[str],
                           date_from: datetime, date_to: datetime, erase_at: datetime, reason: str | None,
                           ai_suggestion: dict | None) -> HiuConsentRequest:
    if not (patient.abha_verified and patient.abha_address):
        raise HiuError("The patient's ABHA address must be verified with ABDM first (ABDM HIP page)")
    if purpose not in PURPOSES:
        raise HiuError("Unknown purpose of use")
    if not hi_types or not set(hi_types) <= set(HI_TYPES):
        raise HiuError("Choose at least one supported record category")
    if not date_from <= date_to <= utcnow() + timedelta(days=1):
        raise HiuError("The date range must end today or earlier and start before it ends")
    if erase_at <= utcnow():
        raise HiuError("The data erase date must be in the future")
    if not doctor.is_active or doctor.hospital_id != patient.hospital_id:
        raise HiuError("Choose an active doctor of this hospital as the requester")
    hospital = db.get(Hospital, patient.hospital_id)
    request_id = str(uuid.uuid4())
    request = HiuConsentRequest(
        hospital_id=patient.hospital_id, patient_id=patient.id, requested_by_id=user.id, requester_doctor_id=doctor.id,
        abha_address=patient.abha_address, purpose_code=purpose, hi_types=sorted(hi_types), date_from=date_from,
        date_to=date_to, data_erase_at=erase_at, reason=reason, ai_suggestion=ai_suggestion, request_id=request_id,
        status="requested", status_message="Sent to the consent manager; waiting for acknowledgement",
        mode=settings.abdm_mode)
    db.add(request)
    body = {"consent": {
        "purpose": {"text": PURPOSES[purpose], "code": purpose, "refUri": PURPOSE_REF_URI},
        "patient": {"id": patient.abha_address},
        "hiu": {"id": hip.hospital_hiu_id(hospital)},
        "requester": {"name": doctor.full_name,
                      "identifier": {"type": "REGNO", "value": doctor.registration_number, "system": REQUESTER_SYSTEM}},
        "hiTypes": sorted(hi_types),
        "permission": {"accessMode": "VIEW", "dateRange": {"from": iso(date_from), "to": iso(date_to)},
                       "dataEraseAt": iso(erase_at), "frequency": {"unit": "DAY", "value": 0, "repeats": 0}}}}
    db.flush()
    tx = record(db, patient.hospital_id, "hiu_consent_init", "outbound", "pending", "Consent request sent",
                request_id=request_id, patient_id=patient.id,
                details={"purpose": purpose, "hiTypes": hi_types, "requestRecordId": request.id})
    audit(db, user, "hiu.consent_request", "patient", patient.id, {"purpose": purpose, "hi_types": hi_types,
                                                                   "requester": doctor.full_name})
    db.commit()
    status, data, _ = hip.call(hip.CONSENT_INIT_PATH, body, hiu_headers(hospital, request_id))
    tx.http_status = status
    if 200 <= status < 300:
        tx.message = "Accepted by the consent manager; waiting for on-init"
    else:
        error = (data or {}).get("error") or data or {}
        request.status, tx.status = "failed", "failed"
        request.status_message = tx.message = f"Consent manager refused the request (HTTP {status}): {error.get('message', '')}"
    db.commit()
    return request


def on_init(db: Session, hospital: Hospital, headers: dict, body: dict) -> str:
    request = db.scalar(select(HiuConsentRequest).where(
        HiuConsentRequest.hospital_id == hospital.id,
        HiuConsentRequest.request_id == (body.get("response") or {}).get("requestId")))
    if request is None:
        return "Unknown consent request acknowledgement"
    if body.get("error") or not (body.get("consentRequest") or {}).get("id"):
        request.status = "failed"
        request.status_message = f"Consent request rejected: {(body.get('error') or {}).get('message', 'no id returned')}"
    else:
        request.consent_request_id = body["consentRequest"]["id"]
        request.status, request.status_message = "pending_consent", "Waiting for the patient to grant or deny consent"
    return request.status_message


def check_consent_status(db: Session, request: HiuConsentRequest) -> str:
    if not request.consent_request_id:
        raise HiuError("The consent manager has not acknowledged this request yet")
    status, data, request_id = hip.call(hip.CONSENT_STATUS_PATH, {"consentRequestId": request.consent_request_id},
                                        hiu_headers(request.hospital))
    record(db, request.hospital_id, "hiu_consent_status", "outbound", "success" if 200 <= status < 300 else "failed",
           "Consent status requested" if 200 <= status < 300 else f"Status request refused (HTTP {status})",
           request_id=request_id, patient_id=request.patient_id, http_status=status)
    db.commit()
    return "Status requested from the consent manager"


def on_status(db: Session, hospital: Hospital, headers: dict, body: dict) -> str:
    info = body.get("consentRequest") or {}
    request = db.scalar(select(HiuConsentRequest).where(HiuConsentRequest.hospital_id == hospital.id,
                                                        HiuConsentRequest.consent_request_id == info.get("id")))
    if request is None:
        return "Status for an unknown consent request"
    status = (info.get("status") or "").upper()
    if status in ("DENIED", "EXPIRED", "REVOKED") and request.status in ("requested", "pending_consent", "granted"):
        request.status, request.status_message = status.lower(), f"Consent manager reports the request is {status}"
    return f"Consent request status: {status or 'unknown'}"


# ---------- 2. notification and artefact fetch ----------

def notify(db: Session, hospital: Hospital, headers: dict, body: dict) -> str:
    n = body.get("notification") or {}
    status, artefact_ids = (n.get("status") or "").upper(), [a.get("id") for a in n.get("consentArtefacts") or [] if a.get("id")]
    request = db.scalar(select(HiuConsentRequest).where(HiuConsentRequest.hospital_id == hospital.id,
                                                        HiuConsentRequest.consent_request_id == n.get("consentRequestId")))
    ack = {"acknowledgement": [{"status": "OK", "consentId": a} for a in artefact_ids],
           "response": {"requestId": headers.get("request-id")}}
    message = "Notification for an unknown consent request"
    if request is not None:
        if status == "GRANTED":
            request.status, request.status_message = "granted", "Consent granted; fetching the consent artefact(s)"
            for artefact_id in artefact_ids:
                if not db.scalar(select(HiuConsentArtefact).where(HiuConsentArtefact.artefact_id == artefact_id)):
                    db.add(HiuConsentArtefact(consent_request=request, artefact_id=artefact_id))
        elif status in ("DENIED", "EXPIRED", "REVOKED"):
            request.status, request.status_message = status.lower(), f"Consent {status.lower()}" + (
                f": {n.get('reason')}" if n.get("reason") else "")
            for artefact in request.artefacts:
                if not artefact_ids or artefact.artefact_id in artefact_ids:
                    artefact.status, artefact.status_message = status.lower(), "Notified by the consent manager"
                    erase_records(db, artefact.artefact_id)  # data may not be used once consent ends
        message = request.status_message
    db.commit()
    hip.call(hip.CONSENT_HIU_ON_NOTIFY_PATH, ack, hiu_headers(hospital))
    if request is not None and status == "GRANTED":
        for artefact in request.artefacts:
            if artefact.status == "notified":
                fetch_artefact(db, artefact)
    return message


def fetch_artefact(db: Session, artefact: HiuConsentArtefact) -> None:
    request_id = str(uuid.uuid4())
    artefact.fetch_request_id, artefact.status_message = request_id, "Fetching the artefact"
    db.commit()
    status, _, _ = hip.call(hip.CONSENT_FETCH_PATH, {"consentId": artefact.artefact_id},
                            hiu_headers(artefact.consent_request.hospital, request_id))
    record(db, artefact.consent_request.hospital_id, "hiu_consent_fetch", "outbound",
           "pending" if 200 <= status < 300 else "failed",
           "Artefact requested" if 200 <= status < 300 else f"Artefact fetch refused (HTTP {status}); retry from the request",
           request_id=request_id, consent_id=artefact.artefact_id, patient_id=artefact.consent_request.patient_id,
           http_status=status)
    db.commit()


def artefact_problem(request: HiuConsentRequest, artefact_id: str, status: str, detail: dict) -> str | None:
    """The artefact must be granted to this hospital's HIU and exactly within what it asked for."""
    permission = detail.get("permission") or {}
    if status != "GRANTED":
        return f"Artefact status is {status or 'missing'}"
    if detail.get("consentId") != artefact_id:
        return "Artefact id does not match"
    if (detail.get("hiu") or {}).get("id") != hip.hospital_hiu_id(request.hospital):
        return "Artefact is for a different HIU"
    if ((detail.get("patient") or {}).get("id") or "").lower() != request.abha_address.lower():
        return "Artefact is for a different patient"
    if not (detail.get("hip") or {}).get("id"):
        return "Artefact names no health information provider"
    if not detail.get("hiTypes") or not set(detail["hiTypes"]) <= set(request.hi_types):
        return "Artefact covers record types that were not requested"
    if (detail.get("purpose") or {}).get("code") != request.purpose_code:
        return "Artefact purpose differs from the request"
    if permission.get("accessMode") != "VIEW":
        return "Artefact access mode is not VIEW"
    try:
        start, end = (parse_time((permission.get("dateRange") or {}).get(k)) for k in ("from", "to"))
        erase_at = parse_time(permission.get("dataEraseAt"))
    except ValueError:
        return "Artefact dates are invalid"
    if not (start and end and erase_at) or start > end:
        return "Artefact has no valid date range or erase date"
    if start < request.date_from - timedelta(seconds=1) or end > request.date_to + timedelta(seconds=1):
        return "Artefact date range is wider than requested"
    if erase_at <= utcnow():
        return "Artefact has already expired"
    if not detail.get("careContexts"):
        return "Artefact lists no care contexts"
    return None


def on_fetch(db: Session, hospital: Hospital, headers: dict, body: dict) -> str:
    artefact = db.scalar(select(HiuConsentArtefact).where(
        HiuConsentArtefact.fetch_request_id == (body.get("response") or {}).get("requestId")))
    if artefact is None or artefact.consent_request.hospital_id != hospital.id:
        return "Artefact for an unknown fetch"
    consent, request = body.get("consent") or {}, artefact.consent_request
    if body.get("error"):
        artefact.status, artefact.status_message = "invalid", f"Fetch failed: {body['error'].get('message')}"
        return artefact.status_message
    detail = consent.get("consentDetail") or {}
    problem = artefact_problem(request, artefact.artefact_id, (consent.get("status") or "").upper(), detail)
    artefact.detail, artefact.fetched_at = detail, utcnow()
    if problem:
        artefact.status, artefact.status_message = "invalid", f"Artefact not accepted: {problem}"
        if all(a.status == "invalid" for a in request.artefacts):
            request.status, request.status_message = "failed", artefact.status_message
        return artefact.status_message
    permission = detail["permission"]
    artefact.status, artefact.hip_id = "valid", detail["hip"]["id"]
    artefact.hi_types, artefact.care_contexts = detail["hiTypes"], detail["careContexts"]
    artefact.date_from = parse_time(permission["dateRange"]["from"])
    artefact.date_to = parse_time(permission["dateRange"]["to"])
    artefact.data_erase_at = parse_time(permission["dataEraseAt"])
    source = db.scalar(select(Hospital.name).where(Hospital.abdm_hip_id == artefact.hip_id))
    artefact.status_message = (f"Valid consent from {source + ' (' + artefact.hip_id + ')' if source else artefact.hip_id} "
                               f"for {', '.join(artefact.hi_types)}")
    db.commit()
    request_data(db, artefact)  # permitted automation: a valid artefact is exactly what the patient approved
    return artefact.status_message


# ---------- 3. health information request and data reception ----------

def request_data(db: Session, artefact: HiuConsentArtefact) -> HiuDataRequest:
    if artefact.status != "valid" or not artefact.data_erase_at or artefact.data_erase_at <= utcnow():
        raise HiuError("A valid, unexpired consent artefact is required")
    busy = db.scalar(select(HiuDataRequest).where(HiuDataRequest.artefact_id == artefact.id,
                                                  HiuDataRequest.status.in_(("requested", "acknowledged"))))
    if busy:
        raise HiuError("A data request for this consent is already in progress")
    keys = hip.generate_key_material()
    request_id, token = str(uuid.uuid4()), secrets.token_urlsafe(32)
    data_request = HiuDataRequest(
        artefact_id=artefact.id, request_id=request_id, push_token=token, status="requested",
        key_material=seal(json.dumps({"private": str(keys["private"]), "nonce": hip.b64(keys["nonce"])})),
        expires_at=utcnow() + timedelta(hours=24), status_message="Waiting for the provider to send data")
    db.add(data_request)
    body = {"hiRequest": {
        "consent": {"id": artefact.artefact_id},
        "dateRange": {"from": iso(artefact.date_from), "to": iso(artefact.date_to)},
        "dataPushUrl": push_url(token),
        "keyMaterial": {"cryptoAlg": hip.CRYPTO_ALG, "curve": hip.CURVE,
                        "dhPublicKey": {"expiry": iso(data_request.expires_at), "parameters": hip.PARAMETERS,
                                        "keyValue": hip.b64(keys["public"])},
                        "nonce": hip.b64(keys["nonce"])}}}
    request = artefact.consent_request
    request.status, request.status_message = "retrieving", "Health information requested; waiting for data"
    tx = record(db, request.hospital_id, "hiu_data_request", "outbound", "pending", "Health information requested",
                request_id=request_id, consent_id=artefact.artefact_id, patient_id=request.patient_id)
    db.commit()
    status, data, _ = hip.call(hip.HI_REQUEST_PATH, body, hiu_headers(request.hospital, request_id))
    tx.http_status = status
    if not 200 <= status < 300:
        data_request.status = tx.status = "failed"
        data_request.status_message = tx.message = f"Data request refused (HTTP {status}); retry from the request"
        data_request.key_material = None
        request.status_message = data_request.status_message
    db.commit()
    return data_request


def on_request(db: Session, hospital: Hospital, headers: dict, body: dict) -> str:
    data_request = db.scalar(select(HiuDataRequest).where(
        HiuDataRequest.request_id == (body.get("response") or {}).get("requestId")))
    if data_request is None or data_request.artefact.consent_request.hospital_id != hospital.id:
        return "Acknowledgement for an unknown data request"
    if body.get("error") or not (body.get("hiRequest") or {}).get("transactionId"):
        data_request.status, data_request.key_material = "failed", None
        data_request.status_message = f"Data request rejected: {(body.get('error') or {}).get('message', 'no transaction')}"
        data_request.artefact.consent_request.status_message = data_request.status_message
    else:
        data_request.transaction_id = body["hiRequest"]["transactionId"]
        if data_request.status == "requested":
            data_request.status = "acknowledged"
        data_request.status_message = f"Acknowledged ({body['hiRequest'].get('sessionStatus')}); waiting for data"
    return data_request.status_message


def receive_push(db: Session, token: str, body: dict) -> tuple[int, str, list[int]]:
    """Data pushed by the HIP to the one-time dataPushUrl: decrypt, store sealed, then notify the CM."""
    data_request = db.scalar(select(HiuDataRequest).where(HiuDataRequest.push_token == token))
    if data_request is None:
        return 404, "Unknown push URL", []
    artefact, request = data_request.artefact, data_request.artefact.consent_request
    if data_request.key_material is None or data_request.status not in ("requested", "acknowledged"):
        return 409, "This push URL is closed", []
    if data_request.expires_at < utcnow() or artefact.status != "valid":
        data_request.status, data_request.key_material = "expired", None
        db.commit()
        return 410, "The data request or consent has expired", []
    if data_request.transaction_id and body.get("transactionId") != data_request.transaction_id:
        return 400, "Transaction id does not match", []
    keys = json.loads(unseal(data_request.key_material))
    material = body.get("keyMaterial") or {}
    allowed = {c["careContextReference"] for c in artefact.care_contexts or []}
    statuses, stored = [], []
    for entry in body.get("entries") or []:
        reference = entry.get("careContextReference")
        try:
            if reference not in allowed:
                raise ValueError("care context not covered by the consent")
            content = hip.decrypt(entry["content"], int(keys["private"]), hip.unb64(keys["nonce"]),
                                  hip.unb64(material["dhPublicKey"]["keyValue"]), hip.unb64(material["nonce"]))
            bundle = json.loads(content)
            if bundle.get("resourceType") != "Bundle":
                raise ValueError("content is not a FHIR Bundle")
        except Exception as exc:  # any undecryptable or invalid entry is reported, never stored
            statuses.append({"careContextReference": reference, "hiStatus": "ERRORED",
                             "description": f"Could not accept: {type(exc).__name__}"})
            continue
        facts = describe(bundle)
        stored.append(RetrievedRecord(
            hospital_id=request.hospital_id, patient_id=request.patient_id, data_request_id=data_request.id,
            consent_artefact_id=artefact.artefact_id, source_hip_id=artefact.hip_id, source_name=facts["source"],
            care_context_reference=reference, record_type=facts["record_type"], category=facts["category"],
            record_date=parse_time(facts["date"]) if facts["date"] else None, content=seal(content),
            checksum_ok=hashlib.md5(content.encode()).hexdigest() == entry.get("checksum"),
            validation_issues=fhir.prechecks(bundle), erase_at=artefact.data_erase_at, mode=settings.abdm_mode))
        db.add(stored[-1])
        statuses.append({"careContextReference": reference, "hiStatus": "OK", "description": "Received"})
    data_request.pages_expected = int(body.get("pageCount") or 1)
    data_request.pages_received += 1
    data_request.transaction_id = data_request.transaction_id or body.get("transactionId")
    received = sum(s["hiStatus"] == "OK" for s in statuses)
    done = data_request.pages_received >= data_request.pages_expected
    if done:
        data_request.status, data_request.key_material = "received", None  # key destroyed: no reuse of the push URL
        data_request.status_message = f"{received} record(s) received and stored"
        db.flush()
        # A consent can cover several providers (one artefact each): the request is complete when all have sent.
        waiting = db.scalar(select(func.count()).select_from(HiuDataRequest).join(HiuConsentArtefact).where(
            HiuConsentArtefact.consent_request_id == request.id, HiuDataRequest.status.in_(("requested", "acknowledged"))))
        artefact_ids = [a.artefact_id for a in request.artefacts]
        total, providers = db.execute(select(func.count(), func.count(RetrievedRecord.source_hip_id.distinct())).where(
            RetrievedRecord.consent_artefact_id.in_(artefact_ids))).one()
        summary = f"{total} record(s) received from {providers} provider(s)" if providers > 1 else data_request.status_message
        if waiting:
            request.status_message = f"{summary} so far; waiting for {waiting} more provider(s)"
        else:
            request.status, request.status_message = "received", summary
    record(db, request.hospital_id, "hiu_data_push", "inbound", "success" if received else "failed",
           f"Page {data_request.pages_received}/{data_request.pages_expected}: {received} of {len(statuses)} record(s) accepted",
           transaction_id=data_request.transaction_id, consent_id=artefact.artefact_id, patient_id=request.patient_id,
           details={"statusResponses": statuses})
    audit(db, None, "hiu.data_received", "patient", request.patient_id,
          {"consent": artefact.artefact_id, "records": received}, hospital_id=request.hospital_id)
    db.commit()
    notification = {"notification": {
        "consentId": artefact.artefact_id, "transactionId": data_request.transaction_id, "doneAt": hip.timestamp(),
        "notifier": {"type": "HIU", "id": hip.hospital_hiu_id(request.hospital)},
        "statusNotification": {"sessionStatus": "TRANSFERRED" if received else "FAILED", "hipId": artefact.hip_id,
                               "statusResponses": statuses}}}
    hip.call(hip.HI_NOTIFY_PATH, notification, hiu_headers(request.hospital))
    ids = [r.id for r in stored]
    if ids and settings.hiu_auto_validate and fhir.validator_available():
        threading.Thread(target=lambda: [validate_record(i) for i in ids], daemon=True).start()
    return 202, data_request.status_message or "Accepted", ids


# ---------- retention ----------

def erase_records(db: Session, artefact_id: str) -> int:
    rows = db.scalars(select(RetrievedRecord).where(RetrievedRecord.consent_artefact_id == artefact_id)).all()
    for row in rows:
        db.delete(row)
    return len(rows)


def enforce_retention(db: Session) -> None:
    """Erase records past the consent's dataEraseAt; close data requests that never received data."""
    now = utcnow()
    for row in db.scalars(select(RetrievedRecord).where(RetrievedRecord.erase_at <= now)):
        db.delete(row)
    for artefact in db.scalars(select(HiuConsentArtefact).where(HiuConsentArtefact.status == "valid",
                                                                HiuConsentArtefact.data_erase_at <= now)):
        artefact.status, artefact.status_message = "expired", "Consent expired (dataEraseAt passed); data erased"
    for data_request in db.scalars(select(HiuDataRequest).where(HiuDataRequest.status.in_(("requested", "acknowledged")),
                                                                HiuDataRequest.expires_at <= now)):
        data_request.status, data_request.key_material = "expired", None
        data_request.status_message = "No data arrived before the request expired; retry if consent is still valid"
    db.commit()


def validate_record(record_id: int) -> None:
    """HL7 FHIR validation of a received bundle (background)."""
    with SessionLocal() as db:
        row = db.get(RetrievedRecord, record_id)
        if row is None:
            return
        status, issues, _ = fhir.validate(bundle_json(row))
        row.validation_status, row.validation_issues = status, issues
        db.commit()


# ---------- inbound dispatch ----------

INBOUND = {"hiu_on_init": on_init, "hiu_on_status": on_status, "hiu_notify": notify, "hiu_on_fetch": on_fetch,
           "hiu_on_request": on_request}


def handle_inbound(kind: str, headers: dict, body: dict):
    headers = {k.lower(): v for k, v in headers.items()}
    with SessionLocal() as db:
        hospital = hospital_for(db, headers.get("x-hiu-id"), "hiu")
        if hospital is None:
            raise HiuError(f"No hospital uses HIU ID {headers.get('x-hiu-id')}")
        try:
            message = INBOUND[kind](db, hospital, headers, body)
            status = "failed" if body.get("error") else "success"
        except (hip.GatewayError, HiuError) as exc:
            db.rollback()
            message, status = f"Could not complete: {exc}", "failed"
        tx = record(db, hospital.id, kind, "inbound", status, message, request_id=(body.get("response") or {}).get("requestId"),
                    consent_id=((body.get("notification") or {}).get("consentRequestId")),
                    details={"error": body.get("error")})  # artefacts carry patient identifiers: not logged
        db.commit()
        return tx


# ====================================================================================================================
# Simulator (ABDM_MODE=simulation) (formerly app/hiu/simulator.py)
# ====================================================================================================================
# Simulation (ABDM_MODE=simulation) of the consent manager and the patient's consent decision for the HIU workflow.
#
# Where the records come from:
# - Several hospitals in this database: the consent manager looks for care contexts that the *other* hospitals have
#   linked to the patient's ABHA address (e.g. surya@abdm). Each such hospital becomes a HIP of the exchange: it is
#   sent the consent artefact, receives the health information request and encrypts and pushes its own validated
#   records to the requesting hospital, all through the same HIP code that handles real ABDM requests.
# - A single hospital: an external HIP ("Sunrise Clinic (SIMULATED)") sends synthetic records, built with the FHIR
#   engine, filtered to the consent's scope and encrypted exactly as a real HIP would.
# Calls arrive through the shared gateway client; callbacks go through the HIP simulator's queue (app.hip) (signed and
# verified like real ones). The consent manager's state is in memory and starts empty after a restart.

EXTERNAL_HIP = "SIM_EXT_HIP_01"
consent_requests: dict[str, dict] = {}  # consent request id -> {"consent": body, "status", "artefacts", "hiu_id"}
artefacts: dict[str, dict] = {}  # artefact id -> consentDetail
local_hips: dict[str, str] = {}  # artefact id -> HIP ID of the hospital in this database that holds the records
pushes: list[dict] = []  # what the simulated external HIP pushed to the HIU (metadata only)

HI_TYPE_OF = {"OPConsultRecord": "OPConsultation", "PrescriptionRecord": "Prescription",
              "DiagnosticReportRecord": "DiagnosticReport", "DischargeSummaryRecord": "DischargeSummary"}


class NoSources(ValueError):
    pass


def reset() -> None:
    consent_requests.clear(), artefacts.clear(), local_hips.clear(), pushes.clear()


def queue(kind: str, body: dict, hiu_id: str | None = None) -> None:
    """A consent manager callback to an HIU."""
    headers = hip.callback_headers()
    headers["X-HIU-ID"] = hiu_id or hip.hospital_hiu_id()
    hip._callbacks.append((kind, headers, body))


def queue_hip(kind: str, body: dict, hip_id: str) -> None:
    """A consent manager request to a HIP (consent notification, health information request)."""
    hip._callbacks.append((kind, hip.callback_headers(hip_id), body))


def receive(path: str, body: dict, headers: dict) -> tuple[int, dict | None]:
    request_id, hiu_id = headers.get("REQUEST-ID"), headers.get("X-HIU-ID")
    if path == hip.CONSENT_INIT_PATH:
        consent_id = str(uuid.uuid4())
        consent_requests[consent_id] = {"consent": body["consent"], "status": "REQUESTED", "artefacts": [], "hiu_id": hiu_id}
        queue("hiu_on_init", {"consentRequest": {"id": consent_id}, "error": None, "response": {"requestId": request_id}},
              hiu_id)
    elif path == hip.CONSENT_STATUS_PATH:
        item = consent_requests.get(body.get("consentRequestId"))
        queue("hiu_on_status", {"consentRequest": {"id": body.get("consentRequestId"), "status": item["status"] if item else None},
                                "error": None if item else {"code": "ABDM-1039", "message": "Invalid Consent request id"},
                                "response": {"requestId": request_id}}, hiu_id)
    elif path == hip.CONSENT_FETCH_PATH:
        detail = artefacts.get(body.get("consentId"))
        if detail and detail["hiu"]["id"] != hiu_id:
            detail = None  # an artefact is only given to the HIU it was granted to
        reply = {"consent": {"status": "GRANTED", "consentDetail": detail, "signature": "simulated"} if detail else None,
                 "error": None if detail else {"code": "ABDM-1080", "message": "Invalid Consent artefact id"},
                 "response": {"requestId": request_id}}
        queue("hiu_on_fetch", reply, hiu_id)
    elif path == hip.HI_REQUEST_PATH:
        transaction_id, artefact_id = str(uuid.uuid4()), body["hiRequest"]["consent"]["id"]
        queue("hiu_on_request", {"hiRequest": {"transactionId": transaction_id, "sessionStatus": "REQUESTED"},
                                 "error": None, "response": {"requestId": request_id}}, hiu_id)
        if artefact_id in local_hips:  # forward to the hospital holding the records; it pushes to the HIU itself
            queue_hip("health_information", {"transactionId": transaction_id, "hiRequest": body["hiRequest"]},
                      local_hips[artefact_id])
        else:
            queue("hiu_push", {"transactionId": transaction_id, "hiRequest": body["hiRequest"]}, hiu_id)
    return 202, None


def local_sources(consent: dict, hi_types: list[str]) -> list[tuple[str, str, list[dict]]] | None:
    """Care contexts that other hospitals of this database linked to the patient's ABHA address, within the
    requested types and dates: [(HIP ID, hospital name, careContexts)]. None when this database has one hospital."""
    from sqlalchemy import func, select

    from app.database import SessionLocal
    from app.models import CareContext
    address = (consent["patient"]["id"] or "").lower()
    date_range = consent["permission"]["dateRange"]
    start, end = parse_time(date_range["from"]), parse_time(date_range["to"])
    with SessionLocal() as db:
        if db.scalar(select(func.count(Hospital.id))) < 2:
            return None
        requester = hospital_for(db, consent["hiu"]["id"], "hiu")
        rows = db.execute(select(CareContext, Patient).join(Patient, Patient.id == CareContext.patient_id).where(
            CareContext.link_status == "linked", func.lower(CareContext.linked_abha_address) == address)
            .order_by(CareContext.hospital_id, CareContext.id)).all()
        sources: dict[str, tuple[str, list[dict]]] = {}
        for context, patient in rows:
            if requester is not None and context.hospital_id == requester.id:
                continue  # the HIU's own records are already in its own system
            if context.hi_type not in hi_types or not start <= context.record_date <= end:
                continue
            hospital = db.get(Hospital, context.hospital_id)
            hip_id = hip.hospital_hip_id(hospital)
            owner = hospital_for(db, hip_id, "hip")
            if owner is None or owner.id != hospital.id:
                continue  # this hospital has no HIP ID of its own, so ABDM could not route to it
            sources.setdefault(hip_id, (hospital.name, []))[1].append(
                {"patientReference": patient.patient_code, "careContextReference": context.reference})
        return [(hip_id, name, contexts) for hip_id, (name, contexts) in sources.items()]


def decide(consent_request_id: str, grant: bool, hi_types: list[str] | None = None, reason: str | None = None) -> dict:
    """The patient's decision in their ABHA app (simulated). A grant may narrow the requested record types.
    A grant creates one consent artefact per HIP holding matching records, as ABDM's consent manager does."""
    item = consent_requests.get(consent_request_id)
    if item is None:
        raise ValueError("Unknown consent request (the simulator restarts empty)")
    consent = item["consent"]
    if not grant:
        item["status"] = "DENIED"
        notification = {"consentRequestId": consent_request_id, "status": "DENIED", "reason": reason, "consentArtefacts": []}
    else:
        granted_types = sorted(set(hi_types or consent["hiTypes"]) & set(consent["hiTypes"]))
        sources = local_sources(consent, granted_types)
        if sources is None:  # a single hospital: the synthetic external provider
            sources = [(EXTERNAL_HIP, "Sunrise Clinic (SIMULATED)",
                        [{"patientReference": "SUN-000777", "careContextReference": f"SUN-CC-{i}"} for i in range(1, 6)])]
        elif not sources:
            raise NoSources(f"No other hospital has records linked to {consent['patient']['id']} of the requested "
                            "types and dates. Link them first on that hospital's ABDM HIP page.")
        item["status"] = "GRANTED"
        ids = []
        for hip_id, _, contexts in sources:
            artefact_id = str(uuid.uuid4())
            detail = {
                "consentId": artefact_id, "schemaVersion": "v3", "createdAt": hip.timestamp(),
                "hip": {"id": hip_id}, "hiu": consent["hiu"], "patient": consent["patient"], "hiTypes": granted_types,
                "purpose": consent["purpose"], "requester": consent["requester"], "permission": consent["permission"],
                "careContexts": contexts, "consentManager": {"id": "sbx"}, "lastUpdated": hip.timestamp()}
            artefacts[artefact_id] = detail
            item["artefacts"].append(artefact_id)
            ids.append({"id": artefact_id})
            if hip_id != EXTERNAL_HIP:  # the HIP learns of the consent before the HIU asks it for data
                local_hips[artefact_id] = hip_id
                queue_hip("consent_notify", {"notification": {"status": "GRANTED", "consentId": artefact_id,
                                                              "consentDetail": detail, "signature": "simulated"}}, hip_id)
        notification = {"consentRequestId": consent_request_id, "status": "GRANTED", "reason": None,
                        "consentArtefacts": ids}
    queue("hiu_notify", {"notification": notification}, item["hiu_id"])
    hip.flush()
    return notification


def revoke(consent_request_id: str) -> None:
    item = consent_requests.get(consent_request_id)
    if item is None:
        raise ValueError("Unknown consent request (the simulator restarts empty)")
    item["status"] = "REVOKED"
    for artefact_id in item["artefacts"]:  # the HIPs stop sharing at once
        if artefact_id in local_hips:
            queue_hip("consent_notify", {"notification": {"status": "REVOKED", "consentId": artefact_id}},
                      local_hips[artefact_id])
    ids = [{"id": a} for a in item["artefacts"]]
    queue("hiu_notify", {"notification": {"consentRequestId": consent_request_id, "status": "REVOKED", "consentArtefacts": ids}},
          item["hiu_id"])
    hip.flush()


# ---------- the simulated external HIP ----------

def synthetic_records(patient: Patient) -> list[tuple[str, dict, datetime]]:
    """Five SYNTHETIC records at Sunrise Clinic (care context reference, bundle, record date)."""
    clinic = Hospital(id=900, name="Sunrise Clinic (SIMULATED)", code="SUN", city="Pune", state="Maharashtra")
    doctor = Doctor(id=901, full_name="Dr. Kavya Menon (simulated)", registration_number="SIM-55555",
                    qualification="MBBS, MD", specialization="Internal Medicine")
    external = Patient(id=902, patient_code="SUN-000777", full_name=patient.full_name, gender=patient.gender,
                       date_of_birth=patient.date_of_birth, year_of_birth=patient.year_of_birth, mobile=patient.mobile,
                       abha_verified=False)
    hba1c = Coding(system=LOINC, code="4548-4", display="Hemoglobin A1c/Hemoglobin.total in Blood")
    contents = [
        ("SUN-CC-1", ClinicalContent(record_type="OPConsultRecord", key="sim-op-1", title="OP consultation (synthetic)",
                                     date=datetime(2025, 6, 10, 10), encounter=EncounterData(start=datetime(2025, 6, 10, 9, 30)),
                                     chief_complaint="Follow-up of type 2 diabetes", plan="Continue metformin",
                                     conditions=[ConditionData(text="Type 2 diabetes mellitus", verification="confirmed")])),
        ("SUN-CC-2", ClinicalContent(record_type="PrescriptionRecord", key="sim-rx-1", title="Prescription (synthetic)",
                                     date=datetime(2025, 6, 10, 10, 15),
                                     medications=[MedicationData(name="Metformin 500 mg tablet", dosage="1 tablet", route="oral",
                                                                 frequency="BD", duration_days=90)])),
        ("SUN-CC-3", ClinicalContent(record_type="DiagnosticReportRecord", key="sim-lab-1", title="HbA1c (synthetic)",
                                     date=datetime(2025, 6, 10, 12), reports=[ReportData(
                                         name="HbA1c", results=[ResultData(name="HbA1c", loinc=hba1c, value="8.1", value_num=8.1,
                                                                           unit="%", ref_high=5.7, interpretation="H")],
                                         conclusion="Raised HbA1c", issued=datetime(2025, 6, 10, 12), interpreter=901)])),
        ("SUN-CC-4", ClinicalContent(record_type="DiagnosticReportRecord", key="sim-lab-2", title="HbA1c (synthetic)",
                                     date=datetime(2025, 12, 1, 12), reports=[ReportData(
                                         name="HbA1c", results=[ResultData(name="HbA1c", loinc=hba1c, value="7.2", value_num=7.2,
                                                                           unit="%", ref_high=5.7, interpretation="H")],
                                         conclusion="HbA1c improved but above target", issued=datetime(2025, 12, 1, 12),
                                         interpreter=901)])),
        ("SUN-CC-5", ClinicalContent(record_type="DischargeSummaryRecord", key="sim-ds-1", title="Discharge summary (synthetic)",
                                     date=datetime(2024, 11, 22, 11), encounter=EncounterData(
                                         start=datetime(2024, 11, 20), end=datetime(2024, 11, 22), inpatient=True),
                                     chief_complaint="Fever and cough", hospital_course="Treated with antibiotics; recovered",
                                     conditions=[ConditionData(text="Community acquired pneumonia", verification="confirmed",
                                                               clinical_status="resolved")])),
    ]
    return [(ref, build_bundle(c, external, clinic, doctor, [doctor]), c.date) for ref, c in contents]


def sim_push(db, transaction_id: str, hi_request: dict) -> None:
    """Act as the external HIP: send only consented, in-range records, encrypted for the HIU's key."""
    from sqlalchemy import select
    artefact = artefacts.get(hi_request["consent"]["id"])
    patient = db.scalar(select(Patient).where(Patient.abha_address == artefact["patient"]["id"]))
    start = datetime.fromisoformat(hi_request["dateRange"]["from"].replace("Z", ""))
    end = datetime.fromisoformat(hi_request["dateRange"]["to"].replace("Z", ""))
    material, own = hi_request["keyMaterial"], hip.generate_key_material()
    receiver_key, receiver_nonce = hip.unb64(material["dhPublicKey"]["keyValue"]), hip.unb64(material["nonce"])
    entries = []
    for reference, bundle, when in synthetic_records(patient):
        if HI_TYPE_OF[bundle["entry"][0]["resource"]["meta"]["profile"][0].rsplit("/", 1)[-1]] not in artefact["hiTypes"]:
            continue
        if not start <= when <= end:
            continue
        content = json.dumps(bundle)
        entries.append({"content": hip.encrypt(content, own["private"], own["nonce"], receiver_key, receiver_nonce),
                        "media": "application/fhir+json", "checksum": hashlib.md5(content.encode()).hexdigest(),
                        "careContextReference": reference})
    body = {"pageNumber": 0, "pageCount": 1, "transactionId": transaction_id, "entries": entries,
            "keyMaterial": {"cryptoAlg": "ECDH", "curve": "Curve25519",
                            "dhPublicKey": {"expiry": material["dhPublicKey"]["expiry"], "parameters": hip.PARAMETERS,
                                            "keyValue": hip.b64(own["x509"])},
                            "nonce": hip.b64(own["nonce"])}}
    pushes.append({"transaction_id": transaction_id, "entries": [e["careContextReference"] for e in entries]})
    token = hi_request["dataPushUrl"].rsplit("/", 1)[-1]
    return receive_push(db, token, body)


# ====================================================================================================================
# API routes (formerly app/hiu/routes.py)
# ====================================================================================================================
# HIU staff API (/api/hiu/...), the data push endpoint and the HIU callbacks (/api/v3/hiu/...).

staff = APIRouter(prefix="/hiu", tags=["hiu"])
push = APIRouter(tags=["hiu-data-push"])
callbacks = APIRouter(tags=["abdm-callbacks"])


class RequestOut(ORMModel):
    id: int
    patient: PatientSummary
    abha_address: str
    purpose_code: str
    hi_types: list
    date_from: UTCDateTime
    date_to: UTCDateTime
    data_erase_at: UTCDateTime
    reason: str | None
    status: str
    status_message: str | None
    consent_request_id: str | None
    mode: str
    created_at: UTCDateTime
    updated_at: UTCDateTime


class RecordOut(ORMModel):
    id: int
    patient_id: int
    source_hip_id: str | None
    source_name: str | None
    category: str
    record_type: str | None
    record_date: UTCDateTime | None
    received_at: UTCDateTime
    consent_artefact_id: str
    care_context_reference: str
    checksum_ok: bool
    validation_status: str
    erase_at: UTCDateTime
    mode: str


def run(action):
    try:
        result = action()
    except HiuError as exc:
        raise HTTPException(422, str(exc))
    except hip.GatewayError as exc:
        raise HTTPException(502, exc.message)
    after_change()
    return result


# ---------- dashboard and request preparation ----------

@staff.get("/dashboard")
def dashboard(user: User = Depends(require("hiu:read")), db: Session = Depends(get_db)):
    enforce_retention(db)
    rows = db.execute(select(HiuConsentRequest.status, func.count()).where(HiuConsentRequest.hospital_id == user.hospital_id)
                      .group_by(HiuConsentRequest.status)).all()
    counts = {status: n for status, n in rows}
    today = datetime.combine(date.today(), time.min)
    return {
        "mode": settings.abdm_mode, "hiu_id": hip.hospital_hiu_id(user.hospital), "hospital": user.hospital.name,
        "counts": {"new_today": db.scalar(select(func.count()).select_from(HiuConsentRequest).where(
                       HiuConsentRequest.hospital_id == user.hospital_id, HiuConsentRequest.created_at >= today)),
                   "pending_consent": counts.get("pending_consent", 0) + counts.get("requested", 0),
                   "granted": counts.get("granted", 0), "denied": counts.get("denied", 0),
                   "retrieving": counts.get("retrieving", 0), "received": counts.get("received", 0),
                   "failed": counts.get("failed", 0) + counts.get("expired", 0) + counts.get("revoked", 0),
                   "records": db.scalar(select(func.count()).select_from(RetrievedRecord).where(
                       RetrievedRecord.hospital_id == user.hospital_id))},
        "purposes": PURPOSES, "hi_types": HI_TYPES,
    }


class SuggestIn(BaseModel):
    patient_id: int
    reason: str = Field(min_length=3, max_length=500)


@staff.post("/suggest")
def suggest(body: SuggestIn, user: User = Depends(require("hiu:request")), db: Session = Depends(get_db)):
    """AI suggestion for purpose, categories and dates. Nothing is created or sent."""
    patient = get_or_404(db, Patient, body.patient_id, user.hospital_id)
    encounters = db.scalars(select(Encounter).where(Encounter.patient_id == patient.id, Encounter.status == "approved")
                            .order_by(Encounter.visit_at.desc()).limit(5)).all()
    prescriptions = db.scalars(select(Prescription).where(Prescription.patient_id == patient.id,
                                                          Prescription.status == "approved").limit(5)).all()
    context = {"today": date.today().isoformat(), "clinical_reason": body.reason,
               "patient": {"age_years": date.today().year - patient.year_of_birth, "gender": patient.gender},
               "this_hospital_records": {
                   "recent_visits": [{"date": e.visit_at.date().isoformat(), "chief_complaint": e.chief_complaint,
                                      "diagnoses": [c.display for c in e.conditions]} for e in encounters],
                   "medicines": sorted({i.medicine_name for p in prescriptions for i in p.items})},
               "allowed_purposes": PURPOSES, "allowed_hi_types": HI_TYPES}
    try:
        suggestion = suggest_request(context)
    except AIError as exc:
        raise HTTPException(503, f"AI suggestions unavailable: {exc}. Fill in the request manually.")
    audit(db, user, "hiu.ai_suggestion", "patient", patient.id, {"purpose": suggestion["purpose_code"]})
    db.commit()
    return suggestion


class RequestIn(BaseModel):
    patient_id: int
    requester_doctor_id: int | None = None
    purpose_code: str
    hi_types: list[str]
    date_from: date
    date_to: date
    erase_at: date | None = None
    reason: str | None = Field(None, max_length=500)
    ai_suggestion: dict | None = None


@staff.post("/requests", response_model=RequestOut, status_code=201)
def create_request(body: RequestIn, user: User = Depends(require("hiu:request")), db: Session = Depends(get_db)):
    """Staff submit the request (possibly after reviewing AI suggestions). The patient decides on consent."""
    patient = get_or_404(db, Patient, body.patient_id, user.hospital_id)
    doctor = get_or_404(db, Doctor, body.requester_doctor_id, user.hospital_id) if body.requester_doctor_id \
        else current_doctor(db, user)
    erase_at = datetime.combine(body.erase_at or date.today() + timedelta(days=30), time.max.replace(microsecond=0))
    request = run(lambda: create_consent_request(
        db, user, patient, doctor, body.purpose_code, body.hi_types, datetime.combine(body.date_from, time.min),
        datetime.combine(body.date_to, time.max.replace(microsecond=0)), erase_at, body.reason, body.ai_suggestion))
    db.refresh(request)  # acknowledgements may already have arrived
    return request


@staff.get("/requests", response_model=Page[RequestOut])
def list_requests(status: str | None = None, patient_id: int | None = None, page: int = Query(1, ge=1),
                  page_size: int = Query(20, ge=1, le=100), user: User = Depends(require("hiu:read")),
                  db: Session = Depends(get_db)):
    enforce_retention(db)
    query = select(HiuConsentRequest).where(HiuConsentRequest.hospital_id == user.hospital_id) \
        .order_by(HiuConsentRequest.id.desc())
    if status:
        query = query.where(HiuConsentRequest.status.in_(status.split(",")))
    if patient_id:
        query = query.where(HiuConsentRequest.patient_id == patient_id)
    return paginate(db, query, page, page_size)


@staff.get("/requests/{request_id}")
def get_request(request_id: int, user: User = Depends(require("hiu:read")), db: Session = Depends(get_db)):
    request = get_or_404(db, HiuConsentRequest, request_id, user.hospital_id)
    hip_names = facility_names(db, "hip")
    artefact_ids = [a.artefact_id for a in request.artefacts]
    data_requests = db.scalars(select(HiuDataRequest).where(
        HiuDataRequest.artefact_id.in_([a.id for a in request.artefacts])).order_by(HiuDataRequest.id)).all()
    transactions = db.scalars(select(HipTransaction).where(
        (HipTransaction.request_id.in_([request.request_id] + [a.fetch_request_id for a in request.artefacts if a.fetch_request_id]
                                       + [d.request_id for d in data_requests]))
        | HipTransaction.consent_id.in_(artefact_ids + ([request.consent_request_id] if request.consent_request_id else [])))
        .order_by(HipTransaction.id)).all()
    return {
        "request": RequestOut.model_validate(request).model_dump(),
        "requester": request.requester_doctor.full_name, "ai_suggestion": request.ai_suggestion,
        "artefacts": [{"id": a.id, "artefact_id": a.artefact_id, "status": a.status, "status_message": a.status_message,
                       "hip_id": a.hip_id, "hip_name": hip_names.get(a.hip_id), "hi_types": a.hi_types, "care_contexts": len(a.care_contexts or []),
                       "date_from": utc(a.date_from), "date_to": utc(a.date_to), "data_erase_at": utc(a.data_erase_at)}
                      for a in request.artefacts],
        "data_requests": [{"id": d.id, "artefact_id": d.artefact.artefact_id, "status": d.status,
                           "status_message": d.status_message, "transaction_id": d.transaction_id,
                           "pages": f"{d.pages_received}/{d.pages_expected or '?'}", "created_at": utc(d.created_at),
                           "expires_at": utc(d.expires_at)} for d in data_requests],
        "timeline": [{"kind": t.kind, "direction": t.direction, "status": t.status, "message": t.message,
                      "mode": t.mode, "at": utc(t.created_at)} for t in transactions],
    }


@staff.post("/requests/{request_id}/check-status")
def check_status(request_id: int, user: User = Depends(require("hiu:request")), db: Session = Depends(get_db)):
    request = get_or_404(db, HiuConsentRequest, request_id, user.hospital_id)
    return {"message": run(lambda: check_consent_status(db, request))}


@staff.post("/artefacts/{artefact_id}/fetch")
def refetch(artefact_id: int, user: User = Depends(require("hiu:request")), db: Session = Depends(get_db)):
    artefact = db.get(HiuConsentArtefact, artefact_id)
    if artefact is None or artefact.consent_request.hospital_id != user.hospital_id:
        raise HTTPException(404, "Artefact not found")
    if artefact.status not in ("notified", "invalid"):
        raise HTTPException(409, "This artefact does not need to be fetched again")
    run(lambda: fetch_artefact(db, artefact))
    return {"message": "Artefact fetch requested"}


@staff.post("/artefacts/{artefact_id}/request-data")
def retry_data(artefact_id: int, user: User = Depends(require("hiu:request")), db: Session = Depends(get_db)):
    """Retry a health-information request under the same, still valid consent (new keys, new push URL)."""
    artefact = db.get(HiuConsentArtefact, artefact_id)
    if artefact is None or artefact.consent_request.hospital_id != user.hospital_id:
        raise HTTPException(404, "Artefact not found")
    enforce_retention(db)
    data_request = run(lambda: request_data(db, artefact))
    audit(db, user, "hiu.data_request_retry", "patient", artefact.consent_request.patient_id, {"consent": artefact.artefact_id})
    db.commit()
    return {"message": data_request.status_message}


# ---------- retrieved records (clinical data: hiu:records, every view audited) ----------

def visible_records(db: Session, user: User, patient_id: int) -> list[RetrievedRecord]:
    enforce_retention(db)
    return db.scalars(select(RetrievedRecord).where(RetrievedRecord.hospital_id == user.hospital_id,
                                                    RetrievedRecord.patient_id == patient_id)
                      .order_by(RetrievedRecord.record_date.desc())).all()


@staff.get("/patients/{patient_id}/records")
def patient_records(patient_id: int, request: Request, user: User = Depends(require("hiu:records")),
                    db: Session = Depends(get_db)):
    patient = get_or_404(db, Patient, patient_id, user.hospital_id)
    rows = visible_records(db, user, patient.id)
    facts = [(r.id, describe(bundle_json(r))) for r in rows]
    summary = db.scalar(select(HiuPatientSummary).where(HiuPatientSummary.patient_id == patient.id))
    audit(db, user, "hiu.records_view", "patient", patient.id, {"records": [r.id for r in rows]}, request)
    db.commit()
    return {"patient": PatientSummary.model_validate(patient).model_dump(),
            "records": [RecordOut.model_validate(r).model_dump() for r in rows],
            "timeline": timeline(facts), "lab_trends": lab_trends(facts),
            "summary": summary and {**json.loads(unseal(summary.content)), "model": summary.model,
                                    "generated_at": summary.generated_at.isoformat() + "Z",
                                    "outdated": set(summary.record_ids) != {r.id for r in rows}}}


@staff.get("/records/{record_id}")
def get_record(record_id: int, request: Request, user: User = Depends(require("hiu:records")), db: Session = Depends(get_db)):
    enforce_retention(db)
    row = get_or_404(db, RetrievedRecord, record_id, user.hospital_id)
    bundle = bundle_json(row)
    audit(db, user, "hiu.record_view", "retrieved_record", row.id, {"consent": row.consent_artefact_id}, request)
    db.commit()
    return {"record": RecordOut.model_validate(row).model_dump(), "facts": describe(bundle),
            "validation_issues": row.validation_issues, "original": bundle}


@staff.post("/records/{record_id}/validate")
def validate(record_id: int, user: User = Depends(require("hiu:records")), db: Session = Depends(get_db)):
    row = get_or_404(db, RetrievedRecord, record_id, user.hospital_id)
    validate_record(row.id)
    db.refresh(row)
    return RecordOut.model_validate(row).model_dump()


@staff.post("/patients/{patient_id}/summary")
def summarize(patient_id: int, request: Request, user: User = Depends(require("hiu:records")), db: Session = Depends(get_db)):
    patient = get_or_404(db, Patient, patient_id, user.hospital_id)
    rows = visible_records(db, user, patient.id)
    if not rows:
        raise HTTPException(422, "No retrieved records to summarise")
    facts = [{"record_id": r.id, "source": r.source_name, **describe(bundle_json(r))} for r in rows]
    try:
        summary = summarize_records(facts)
    except AIError as exc:
        raise HTTPException(503, f"AI summary unavailable: {exc}")
    row = db.scalar(select(HiuPatientSummary).where(HiuPatientSummary.patient_id == patient.id)) or \
        HiuPatientSummary(patient_id=patient.id)
    row.content, row.record_ids, row.model, row.generated_at = seal(json.dumps(summary)), [r.id for r in rows], \
        settings.ai_model, utcnow()
    db.add(row)
    audit(db, user, "hiu.ai_summary", "patient", patient.id, {"records": row.record_ids}, request)
    db.commit()
    return {**summary, "model": row.model, "generated_at": row.generated_at.isoformat() + "Z", "outdated": False}


# ---------- simulation: the patient's decision (ABDM_MODE=simulation only) ----------

class Decision(BaseModel):
    grant: bool
    hi_types: list[str] | None = None
    reason: str | None = None


@staff.post("/simulate/requests/{request_id}/decide")
def simulate_decision(request_id: int, body: Decision, user: User = Depends(require("hiu:request")),
                      db: Session = Depends(get_db)):
    if not hip.simulation():
        raise HTTPException(409, "Simulation actions are disabled in sandbox mode")
    request = get_or_404(db, HiuConsentRequest, request_id, user.hospital_id)
    if request.status != "pending_consent":
        raise HTTPException(409, "The request is not waiting for consent")
    try:
        decide(request.consent_request_id, body.grant, body.hi_types, body.reason)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    db.refresh(request)
    return RequestOut.model_validate(request).model_dump()


@staff.post("/simulate/requests/{request_id}/revoke")
def simulate_revoke(request_id: int, user: User = Depends(require("hiu:request")), db: Session = Depends(get_db)):
    if not hip.simulation():
        raise HTTPException(409, "Simulation actions are disabled in sandbox mode")
    request = get_or_404(db, HiuConsentRequest, request_id, user.hospital_id)
    try:
        revoke(request.consent_request_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    db.refresh(request)
    return RequestOut.model_validate(request).model_dump()


# ---------- data push from HIPs and ABDM callbacks ----------

@push.post("/hiu/data-push/{token}", status_code=202)
async def data_push(token: str, request: Request, db: Session = Depends(get_db)):
    """HIPs post encrypted data here; the unguessable token identifies one open data request."""
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, "Body must be JSON")
    status, message, _ = receive_push(db, token, body)
    if status != 202:
        raise HTTPException(status, message)
    return {"message": message}


HIU_REQUIRED = {"hiu_on_init": ["response.requestId"], "hiu_on_status": ["response.requestId"],
                "hiu_notify": ["notification.consentRequestId", "notification.status"],
                "hiu_on_fetch": ["response.requestId"], "hiu_on_request": ["response.requestId"]}
for kind, path in {"hiu_on_init": "/v3/hiu/consent/request/on-init", "hiu_on_status": "/v3/hiu/consent/request/on-status",
                   "hiu_notify": "/v3/hiu/consent/request/notify", "hiu_on_fetch": "/v3/hiu/consent/on-fetch",
                   "hiu_on_request": "/v3/hiu/health-information/on-request"}.items():
    callbacks.add_api_route(path, accept(kind, HIU_REQUIRED[kind], handle_inbound, "hiu"),
                            methods=["POST"], status_code=202, name=f"abdm_{kind}")
