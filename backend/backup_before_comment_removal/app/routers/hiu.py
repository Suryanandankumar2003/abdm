"""HIU staff API (/api/hiu/...): consent requests, their artefacts and the retrieved records (clinical data needs
hiu:records and every view is audited). Also the simulated consent manager: the patient grants, denies or revokes
consent in their ABHA app, and the records come from other hospitals on this server (or, when there is only one
hospital, from a synthetic outside clinic)."""

import hashlib
import json
import uuid
from datetime import date, datetime, time, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import hip, hiu
from app.database import get_db
from app.fhir import LOINC, ClinicalContent, build_bundle
from app.models import CareContext, Doctor, HiuConsentRequest, HiuDataRequest, Hospital, Patient, RetrievedRecord, User
from app.schemas import ORMModel, Page, PatientSummary, UTCDateTime
from app.security import require
from app.services import audit, current_doctor, get_or_404, paginate

router = APIRouter(prefix="/hiu", tags=["hiu"])
iso = lambda value: value.isoformat(timespec="seconds") + "Z"  # noqa: E731  (ABDM date-times)


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
    created_at: UTCDateTime


class RecordOut(ORMModel):
    id: int
    source_hip_id: str | None
    source_name: str | None
    category: str
    record_date: UTCDateTime | None
    received_at: UTCDateTime
    care_context_reference: str
    checksum_ok: bool
    validation_status: str
    erase_at: UTCDateTime


class RequestIn(BaseModel):
    patient_id: int
    requester_doctor_id: int | None = None  # default: the signed-in doctor
    purpose_code: str
    hi_types: list[str]
    date_from: date
    date_to: date
    erase_at: date | None = None  # default: in 30 days
    reason: str | None = Field(None, max_length=500)


@router.get("/dashboard")
def dashboard(user: User = Depends(require("hiu:read")), db: Session = Depends(get_db)):
    hiu.enforce_retention(db)
    by_status = db.execute(select(HiuConsentRequest.status, func.count()).where(
        HiuConsentRequest.hospital_id == user.hospital_id).group_by(HiuConsentRequest.status)).all()
    records = db.scalar(select(func.count()).select_from(RetrievedRecord).where(RetrievedRecord.hospital_id == user.hospital_id))
    return {"mode": hip.MODE, "hiu_id": hip.hiu_id(user.hospital), "requests": dict(by_status), "records": records,
            "purposes": hiu.PURPOSES, "hi_types": hiu.HI_TYPES}


@router.post("/requests", response_model=RequestOut, status_code=201)
def create_request(body: RequestIn, user: User = Depends(require("hiu:request")), db: Session = Depends(get_db)):
    """Staff submit the request; the patient then decides on consent in their ABHA app."""
    patient = get_or_404(db, Patient, body.patient_id, user.hospital_id)
    doctor = get_or_404(db, Doctor, body.requester_doctor_id, user.hospital_id) if body.requester_doctor_id \
        else current_doctor(db, user)
    end_of = lambda day: datetime.combine(day, time.max.replace(microsecond=0))  # noqa: E731
    try:
        request = hiu.create_consent_request(db, user, patient, doctor, body.purpose_code, body.hi_types,
                                             datetime.combine(body.date_from, time.min), end_of(body.date_to),
                                             end_of(body.erase_at or date.today() + timedelta(days=30)), body.reason)
    except hiu.HiuError as exc:
        raise HTTPException(422, str(exc))
    db.commit()
    return request


@router.get("/requests", response_model=Page[RequestOut])
def list_requests(status: str | None = None, patient_id: int | None = None, page: int = Query(1, ge=1),
                  page_size: int = Query(20, ge=1, le=100), user: User = Depends(require("hiu:read")),
                  db: Session = Depends(get_db)):
    hiu.enforce_retention(db)
    query = select(HiuConsentRequest).where(HiuConsentRequest.hospital_id == user.hospital_id).order_by(HiuConsentRequest.id.desc())
    query = query.where(HiuConsentRequest.status.in_(status.split(","))) if status else query
    return paginate(db, query.where(HiuConsentRequest.patient_id == patient_id) if patient_id else query, page, page_size)


@router.get("/requests/{request_id}")
def get_request(request_id: int, user: User = Depends(require("hiu:read")), db: Session = Depends(get_db)):
    request = get_or_404(db, HiuConsentRequest, request_id, user.hospital_id)
    names = hip.hospital_names(db, "hip")
    return {"request": RequestOut.model_validate(request).model_dump(), "requester": request.requester_doctor.full_name,
            "artefacts": [{"id": a.id, "artefact_id": a.artefact_id, "status": a.status, "status_message": a.status_message,
                           "hip_id": a.hip_id, "hip_name": names.get(a.hip_id), "hi_types": a.hi_types} for a in request.artefacts],
            "data_requests": [{"artefact_id": d.artefact.artefact_id, "status": d.status, "status_message": d.status_message}
                              for d in db.scalars(select(HiuDataRequest).where(
                                  HiuDataRequest.artefact_id.in_([a.id for a in request.artefacts])))]}


@router.get("/patients/{patient_id}/records")
def patient_records(patient_id: int, request: Request, user: User = Depends(require("hiu:records")),
                    db: Session = Depends(get_db)):
    patient = get_or_404(db, Patient, patient_id, user.hospital_id)
    hiu.enforce_retention(db)  # expired or revoked external data is never shown
    rows = db.scalars(select(RetrievedRecord).where(RetrievedRecord.hospital_id == user.hospital_id,
                                                    RetrievedRecord.patient_id == patient.id)
                      .order_by(RetrievedRecord.record_date.desc())).all()
    facts = [(r.id, hiu.describe(hiu.bundle_json(r))) for r in rows]
    audit(db, user, "hiu.records_view", "patient", patient.id, {"records": [r.id for r in rows]}, request)
    db.commit()
    return {"patient": PatientSummary.model_validate(patient).model_dump(), "timeline": hiu.timeline(facts),
            "records": [RecordOut.model_validate(r).model_dump() for r in rows], "lab_trends": hiu.lab_trends(facts)}


@router.get("/records/{record_id}")
def get_record(record_id: int, request: Request, user: User = Depends(require("hiu:records")), db: Session = Depends(get_db)):
    hiu.enforce_retention(db)
    row = get_or_404(db, RetrievedRecord, record_id, user.hospital_id)
    bundle = hiu.bundle_json(row)
    audit(db, user, "hiu.record_view", "retrieved_record", row.id, {"consent": row.consent_artefact_id}, request)
    db.commit()
    return {"record": RecordOut.model_validate(row).model_dump(), "facts": hiu.describe(bundle),
            "validation_issues": row.validation_issues, "original": bundle}


@router.post("/records/{record_id}/validate", response_model=RecordOut)
def validate_record(record_id: int, user: User = Depends(require("hiu:records")), db: Session = Depends(get_db)):
    """Run the HL7 FHIR validator on a received record (takes about a minute)."""
    row = get_or_404(db, RetrievedRecord, record_id, user.hospital_id)
    hiu.validate_record(row.id)
    db.refresh(row)
    return row


# ---------- simulated consent manager: the patient's decision in their ABHA app ----------

def sources(db: Session, request: HiuConsentRequest, hi_types: list[str]) -> list[tuple[Hospital | None, list[dict]]]:
    """Care contexts that other hospitals here linked to the patient's ABHA address, within the requested types and
    dates: [(HIP hospital, careContexts)]. A server with one hospital uses the synthetic clinic (hospital None)."""
    if db.scalar(select(func.count(Hospital.id))) < 2:
        return [(None, [{"patientReference": "SUN-000777", "careContextReference": f"SUN-CC-{i}"} for i in range(1, 6)])]
    found: dict[int, list[dict]] = {}
    for context, patient in db.execute(select(CareContext, Patient).join(Patient, Patient.id == CareContext.patient_id).where(
            CareContext.link_status == "linked", CareContext.hospital_id != request.hospital_id,
            func.lower(CareContext.linked_abha_address) == request.abha_address.lower(), CareContext.hi_type.in_(hi_types),
            CareContext.record_date.between(request.date_from, request.date_to)).order_by(CareContext.id)):
        found.setdefault(context.hospital_id, []).append(
            {"patientReference": patient.patient_code, "careContextReference": context.reference})
    return [(db.get(Hospital, hospital_id), contexts) for hospital_id, contexts in found.items()]


def synthetic_clinic(patient: Patient, detail: dict, keys: dict) -> dict:
    """'Sunrise Clinic (SIMULATED)' answers like a HIP: SYNTHETIC records, only the consented types inside the consent's
    dates, encrypted for the HIU's keys."""
    clinic = Hospital(id=900, name="Sunrise Clinic (SIMULATED)", code="SUN", city="Pune", state="Maharashtra")
    doctor = Doctor(id=901, full_name="Dr. Kavya Menon (simulated)", registration_number="SIM-55555", qualification="MBBS, MD")
    external = Patient(id=902, patient_code="SUN-000777", full_name=patient.full_name, gender=patient.gender,
                       date_of_birth=patient.date_of_birth, year_of_birth=patient.year_of_birth, mobile=patient.mobile)
    hba1c = {"system": LOINC, "code": "4548-4", "display": "Hemoglobin A1c/Hemoglobin.total in Blood"}
    lab = lambda key, when, value, conclusion: ClinicalContent(  # noqa: E731
        record_type="DiagnosticReportRecord", key=key, title="HbA1c (synthetic)", date=when, reports=[
            {"name": "HbA1c", "conclusion": conclusion, "issued": when, "interpreter": 901, "results": [
                {"name": "HbA1c", "loinc": hba1c, "value": str(value), "value_num": value, "unit": "%", "ref_high": 5.7,
                 "interpretation": "H"}]}])
    records = {
        "SUN-CC-1": ("OPConsultation", ClinicalContent(
            record_type="OPConsultRecord", key="sim-op-1", title="OP consultation (synthetic)", date=datetime(2025, 6, 10, 10),
            encounter={"start": datetime(2025, 6, 10, 9, 30)}, conditions=[{"text": "Type 2 diabetes mellitus",
                                                                            "verification": "confirmed"}],
            text={"chief_complaint": "Follow-up of type 2 diabetes", "plan": "Continue metformin"})),
        "SUN-CC-2": ("Prescription", ClinicalContent(
            record_type="PrescriptionRecord", key="sim-rx-1", title="Prescription (synthetic)", date=datetime(2025, 6, 10, 10, 15),
            medications=[{"name": "Metformin 500 mg tablet", "dosage": "1 tablet", "route": "oral", "frequency": "BD",
                          "duration_days": 90}])),
        "SUN-CC-3": ("DiagnosticReport", lab("sim-lab-1", datetime(2025, 6, 10, 12), 8.1, "Raised HbA1c")),
        "SUN-CC-4": ("DiagnosticReport", lab("sim-lab-2", datetime(2025, 12, 1, 12), 7.2, "HbA1c improved but above target")),
        "SUN-CC-5": ("DischargeSummary", ClinicalContent(
            record_type="DischargeSummaryRecord", key="sim-ds-1", title="Discharge summary (synthetic)",
            date=datetime(2024, 11, 22, 11), encounter={"start": datetime(2024, 11, 20), "end": datetime(2024, 11, 22),
                                                        "inpatient": True},
            conditions=[{"text": "Community acquired pneumonia", "verification": "confirmed", "clinical_status": "resolved"}],
            text={"chief_complaint": "Fever and cough", "hospital_course": "Treated with antibiotics; recovered"}))}
    own, dates, entries = hip.new_keys(), detail["permission"]["dateRange"], []
    for reference, (hi_type, content) in records.items():
        if hi_type in detail["hiTypes"] and hip.parse_time(dates["from"]) <= content.date <= hip.parse_time(dates["to"]):
            text = json.dumps(build_bundle(content, external, clinic, doctor, [doctor]))
            entries.append({"content": hip.encrypt(text, own, keys["public"], keys["nonce"]), "careContextReference": reference,
                            "checksum": hashlib.md5(text.encode()).hexdigest()})
    return {"transactionId": str(uuid.uuid4()), "entries": entries,
            "keyMaterial": {"dhPublicKey": {"keyValue": own["public"]}, "nonce": own["nonce"]}}


class Decision(BaseModel):
    grant: bool
    hi_types: list[str] | None = None  # a grant may narrow the requested record types
    reason: str | None = None


@router.post("/simulate/requests/{request_id}/decide", response_model=RequestOut)
def simulate_decision(request_id: int, body: Decision, user: User = Depends(require("hiu:request")),
                      db: Session = Depends(get_db)):
    """The patient grants or denies the request. A grant gives one consent artefact per provider holding matching
    records; each provider (HIP) checks it, and the records are then requested, decrypted and stored."""
    request = get_or_404(db, HiuConsentRequest, request_id, user.hospital_id)
    if request.status != "pending_consent":
        raise HTTPException(409, "The request is not waiting for consent")
    if not body.grant:
        request.status, request.status_message = "denied", "Consent denied" + (f": {body.reason}" if body.reason else "")
        db.commit()
        return request
    hi_types = sorted(set(body.hi_types or request.hi_types) & set(request.hi_types))
    if not (found := sources(db, request, hi_types)):
        raise HTTPException(409, f"No other hospital has records linked to {request.abha_address} of the requested types and "
                                 "dates. Link them first on that hospital's ABDM HIP page.")
    dates = {"from": iso(request.date_from), "to": iso(request.date_to)}
    for hospital, contexts in found:
        detail = {"consentId": str(uuid.uuid4()), "hip": {"id": hip.hip_id(hospital) if hospital else "SIM_EXT_HIP_01"},
                  "hiu": {"id": hip.hiu_id(request.hospital)}, "patient": {"id": request.abha_address}, "hiTypes": hi_types,
                  "purpose": {"code": request.purpose_code, "text": hiu.PURPOSES[request.purpose_code]}, "careContexts": contexts,
                  "permission": {"accessMode": "VIEW", "dateRange": dates, "dataEraseAt": iso(request.data_erase_at)}}
        if hospital:  # the HIP learns of the consent before it is asked for data
            hip.consent_notify(db, hospital, detail["consentId"], "GRANTED", detail)
        artefact = hiu.accept_artefact(db, request, detail, hospital.name if hospital else "Sunrise Clinic (SIMULATED)")
        db.flush()
        if artefact.status == "valid":
            hiu.request_data(db, artefact, lambda keys, h=hospital, d=detail: hip.share(db, h, d["consentId"], dates["from"],
                             dates["to"], keys) if h else synthetic_clinic(request.patient, d, keys))
    db.flush()
    received = db.scalar(select(func.count()).select_from(RetrievedRecord).where(
        RetrievedRecord.consent_artefact_id.in_([a.artefact_id for a in request.artefacts])))
    valid = sum(a.status == "valid" for a in request.artefacts)
    request.status = "received" if valid else "failed"
    request.status_message = f"{received} record(s) received from {valid} provider(s)" if valid else "No valid consent artefact"
    db.commit()
    return request


@router.post("/simulate/requests/{request_id}/revoke", response_model=RequestOut)
def simulate_revoke(request_id: int, user: User = Depends(require("hiu:request")), db: Session = Depends(get_db)):
    """The patient revokes the consent: the providers stop sharing at once and the received copies are erased."""
    request = get_or_404(db, HiuConsentRequest, request_id, user.hospital_id)
    for artefact in request.artefacts:
        if provider := db.scalar(select(Hospital).where(Hospital.abdm_hip_id == artefact.hip_id)):
            hip.consent_notify(db, provider, artefact.artefact_id, "REVOKED")
        artefact.status, artefact.status_message = "revoked", "Consent revoked by the patient"
        for row in db.scalars(select(RetrievedRecord).where(RetrievedRecord.consent_artefact_id == artefact.artefact_id)):
            db.delete(row)  # data may not be used once consent ends
    request.status, request.status_message = "revoked", "Consent revoked by the patient; received records erased"
    db.commit()
    return request
