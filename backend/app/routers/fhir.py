"""FHIR records: approved consultations, prescriptions, lab reports and reviewed documents become ClinicalContent, are
built into ABDM document Bundles (app.fhir), checked, stored, validated with the HL7 validator and downloaded.
Conversions are conservative: what cannot be read unambiguously stays as text and is reported as a warning."""

import base64
import json
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request
from datetime import date, datetime
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import fhir
from app.config import settings
from app.database import get_db
from app.extraction import ReviewedRecord, value
from app.fhir import ICD10, VITAL_SIGNS, ClinicalContent
from app.models import ClinicalDocument, Encounter, FhirRecord, LabOrder, Prescription, User, utcnow
from app.schemas import FhirGenerate, FhirRecordOut, FhirRecordSummary, Page
from app.security import require
from app.services import audit, get_or_404, paginate

router = APIRouter(prefix="/fhir", tags=["fhir"])

DOCUMENT_TYPES = {"prescription": "PrescriptionRecord", "lab_report": "DiagnosticReportRecord", "opd_consultation": "OPConsultRecord",
                  "discharge_summary": "DischargeSummaryRecord", "immunization": "ImmunizationRecord", "wellness": "WellnessRecord"}
FLAGS = {"H": "H", "HIGH": "H", "↑": "H", "L": "L", "LOW": "L", "↓": "L", "*": "A", "A": "A", "ABNORMAL": "A", "N": "N", "NORMAL": "N"}
ROUTE_WORDS = {"po": "oral", "by mouth": "oral", "intravenous": "iv", "intramuscular": "im", "s/c": "sc", "subcutaneous": "sc",
               "local application": "topical", "sl": "sublingual", "inhaled": "inhalation", "eye": "ophthalmic",
               "ear": "otic", "pr": "rectal"}  # plus the route keys themselves (oral, iv, im, ...)
FREQUENCY_WORDS = {**{k.lower(): k for k in fhir.FREQUENCIES}, **{v[0].lower(): k for k, v in fhir.FREQUENCIES.items()},
                   "once a day": "OD", "1-0-0": "OD", "0-0-1": "HS", "bid": "BD", "twice a day": "BD", "1-0-1": "BD",
                   "tid": "TDS", "thrice daily": "TDS", "three times a day": "TDS", "1-1-1": "TDS", "four times a day": "QID",
                   "1-1-1-1": "QID", "weekly": "WEEKLY", "prn": "SOS", "as needed": "SOS"}


@lru_cache(maxsize=2000)
def terminology_display(system: str, code: str) -> str | None:
    """Official display of a code from the terminology server (FHIR $lookup); None if unknown or unreachable."""
    url = f"{settings.fhir_tx_server}/r4/CodeSystem/$lookup?" + urllib.parse.urlencode({"system": system, "code": code})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/fhir+json"}), timeout=20) as r:
            parameters = json.load(r).get("parameter", [])
    except (OSError, ValueError):  # unreachable, or FHIR_TX_SERVER=n/a
        return None
    return next((p.get("valueString") for p in parameters if p.get("name") == "display"), None)


def condition(text: str, code: str | None, warnings: list[str], **fields) -> dict:
    """A diagnosis; ICD-10 coded only with the official title from the terminology server, else text only."""
    display = terminology_display(ICD10, code) if code else None
    if code and display is None:
        warnings.append(f"{text}: ICD-10 code {code} could not be verified on the terminology server, "
                        "so the diagnosis is exported as text only")
    return {"text": text, "icd10": (code, display) if display else None, **fields}


# ---------- approved records -> ClinicalContent (returns content, patient, author, other doctors, warnings) ----------

def medication(i) -> dict:
    return {"name": i.medicine_name, "dosage": i.dosage, "route": i.route, "frequency": i.frequency,
            "duration_days": i.duration_days, "quantity": i.quantity, "instructions": i.instructions}


def consultation_source(e: Encounter, prescriptions: list[Prescription], orders: list[LabOrder]):
    # Only the consulting doctor's prescriptions/orders belong to this note; others export on their own.
    warnings = []
    follow_up = " ".join(filter(None, [e.follow_up_instructions,
                                       f"Review on {e.follow_up_date.isoformat()}." if e.follow_up_date else None]))
    content = ClinicalContent(
        record_type="OPConsultRecord", key=f"consultation-{e.id}", title="Consultation record", date=e.approved_at,
        encounter={"start": e.visit_at, "reason": e.chief_complaint},
        conditions=[condition(c.display, c.code, warnings, clinical_status=c.clinical_status, onset=c.onset_date,
                              verification=c.verification_status, note=c.note) for c in e.conditions],
        observations=[{"name": VITAL_SIGNS[k][0], "key": k, "value": v} for k, v in (e.vitals or {}).items()
                      if v is not None and k in VITAL_SIGNS],
        medications=[medication(i) for p in prescriptions if p.doctor_id == e.doctor_id for i in p.items],
        orders=[{"name": o.test.name, "status": "completed" if o.status == "completed" else "active", "priority": o.priority,
                 "authored": o.created_at, "note": o.clinical_notes} for o in orders if o.doctor_id == e.doctor_id],
        text={"chief_complaint": e.chief_complaint, "history": e.history_present_illness, "findings": e.clinical_findings,
              "plan": e.treatment_plan, "follow_up": follow_up})  # doctor_notes are internal and never exported
    return content, e.patient, e.doctor, [], warnings


def prescription_source(p: Prescription):
    content = ClinicalContent(
        record_type="PrescriptionRecord", key=f"prescription-{p.id}", title="Prescription", date=p.approved_at,
        encounter={"start": p.encounter.visit_at, "status": "finished" if p.encounter.status == "approved" else "in-progress"},
        medications=[medication(i) for i in p.items], text={"notes": p.notes})
    return content, p.patient, p.doctor, [], []


def lab_order_source(o: LabOrder):
    r = o.report
    results = [{"name": x.name, "value": x.value, "value_num": x.value_numeric, "unit": x.unit, "ref_low": x.ref_low,
                "ref_high": x.ref_high, "ref_text": x.ref_text, "interpretation": x.interpretation} for x in r.results]
    content = ClinicalContent(
        record_type="DiagnosticReportRecord", key=f"lab-order-{o.id}", title=f"Laboratory report: {o.test.name}",
        date=r.approved_at, encounter={"start": o.created_at},
        orders=[{"name": o.test.name, "status": "completed", "priority": o.priority, "authored": o.created_at,
                 "note": o.clinical_notes, "requester": o.doctor_id}],
        reports=[{"name": o.test.name, "results": results, "conclusion": r.conclusion, "issued": r.approved_at,
                  "effective": o.sample_collected_at, "interpreter": r.approved_by_doctor_id}])
    return content, o.patient, r.approved_by_doctor, [o.doctor], []


def number(text: str | None) -> float | None:
    try:
        return float(text.replace(",", "").strip()) if text else None
    except ValueError:
        return None


def document_source(doc: ClinicalDocument):
    """A reviewed, approved document. Its own file is always attached; reviewed fields become structured entries."""
    record, warnings = ReviewedRecord.model_validate(doc.data), []
    kind, enc = DOCUMENT_TYPES.get(doc.document_type, "HealthDocumentRecord"), record.encounter
    v = value  # the reviewed value of a field, or None

    def day(label: str, raw: str | None) -> datetime | None:
        try:
            return datetime.combine(date.fromisoformat(raw.strip()), datetime.min.time()) if raw else None
        except ValueError:
            warnings.append(f"{label} '{raw}' is not in YYYY-MM-DD format, so it was not used")

    visit = day("Visit/document date", v(enc.visit_date) or v(record.document_date))
    admitted, discharged = day("Admission date", v(enc.admission_date)), day("Discharge date", v(enc.discharge_date))
    encounter = ({"start": admitted, "end": discharged, "inpatient": True} if kind == "DischargeSummaryRecord" and admitted
                 else {"start": visit, "reason": v(enc.chief_complaint)} if kind == "OPConsultRecord" and visit else None)

    medications = []
    for m in record.medications:
        if not v(m.name):
            continue
        duration, quantity, route = v(m.duration), number(v(m.quantity)), " ".join((v(m.route) or "").lower().split())
        weeks = re.fullmatch(r"\s*(?:x\s*)?(\d+)\s*(d|days?|w|wks?|weeks?)\s*", duration or "", re.I)
        days = int(weeks[1]) * (7 if weeks[2].lower().startswith("w") else 1) if weeks else None
        route = ROUTE_WORDS.get(route, route)
        medications.append({"name": v(m.name), "dosage": v(m.dosage), "route": route if route in fhir.ROUTES else None,
                            "frequency": FREQUENCY_WORDS.get(" ".join((v(m.frequency) or "").lower().split())),
                            "frequency_text": v(m.frequency), "duration_days": days, "duration_text": None if days else duration,
                            "quantity": int(quantity) if quantity and quantity.is_integer() else None,
                            "instructions": v(m.instructions)})

    results = []
    for r in record.lab_results:
        if v(r.test_name) and v(r.value) is not None:
            limits = re.fullmatch(r"\s*([\d.]+)\s*(?:-|–|to)\s*([\d.]+)\s*\S*\s*", v(r.reference_range) or "")
            results.append({"name": v(r.test_name), "value": v(r.value), "value_num": number(v(r.value)), "unit": v(r.unit),
                            "ref_low": float(limits[1]) if limits else None, "ref_high": float(limits[2]) if limits else None,
                            "ref_text": None if limits else v(r.reference_range),
                            "interpretation": FLAGS.get((v(r.flag) or "").strip().upper())})
    panels = {v(r.panel_name) for r in record.lab_results if v(r.panel_name)}
    reports = [{"name": panels.pop() if len(panels) == 1 else "Laboratory report", "results": results,
                "conclusion": v(record.report_conclusion), "issued": doc.approved_at, "effective": visit,
                "interpreter": doc.approved_by_doctor_id}] if results else []

    partial_date = lambda d: d.strip() if d and re.fullmatch(r"\s*\d{4}(-\d{2}(-\d{2})?)?\s*", d) else None  # noqa: E731
    immunizations = [{"vaccine": v(im.vaccine), "occurrence": partial_date(v(im.date)), "lot_number": v(im.lot_number),
                      "dose_number": int(n) if (n := number(v(im.dose_number))) and n.is_integer() else None}
                     for im in record.immunizations if v(im.vaccine)]  # a missing or unusable date is reported by prechecks

    data = (settings.upload_dir / doc.storage_name).read_bytes()
    content = ClinicalContent(
        record_type=kind, key=f"document-{doc.id}", title=doc.file_name, date=doc.approved_at, encounter=encounter,
        conditions=[condition(v(d.text), (v(d.icd10_code) or "").strip().upper() or None, warnings)
                    for d in record.diagnoses if v(d.text)],
        allergies=[{"text": v(a.substance), "reaction": v(a.reaction)} for a in record.allergies if v(a.substance)],
        observations=[{"name": v(x.name), "value": number(v(x.value)), "value_text": v(x.value), "unit": v(x.unit)}
                      for x in record.vitals if v(x.name) and v(x.value)],
        medications=medications, reports=reports, immunizations=immunizations,
        text={"chief_complaint": v(enc.chief_complaint), "history": v(enc.history_of_present_illness),
              "findings": v(enc.examination_findings), "plan": v(enc.treatment_plan), "follow_up": v(enc.follow_up),
              "hospital_course": v(enc.hospital_course),
              "notes": "\n".join(filter(None, [v(enc.instructions), v(record.notes)])) or None},
        attachment={"content_type": doc.content_type, "data": base64.b64encode(data).decode(), "title": doc.file_name})
    return content, doc.patient, doc.author_doctor, [doc.approved_by_doctor] if doc.approved_by_doctor else [], warnings


# Checking. Elements the ABDM profiles require that depend on the source data rather than on the engine.
REQUIRED = {"DiagnosticReport": [("result", "at least one result"), ("conclusion", "a conclusion"),
                                 ("resultsInterpreter", "an approving doctor (results interpreter)")],
            "MedicationRequest": [("dosageInstruction", "dosage instructions"), ("requester", "a prescriber")],
            "Immunization": [("occurrenceDateTime", "a vaccination date as YYYY, YYYY-MM or YYYY-MM-DD")],
            "Composition": [("section", "at least one section with content"), ("author", "an author")]}


def issue(severity: str, category: str, message: str, location: str | None = None) -> dict:
    return {"severity": severity, "category": category, "message": message, "location": location}


def describe(entry: dict) -> str:
    """Readable name of a bundle entry, e.g. 'Observation (Haemoglobin)'."""
    r = entry.get("resource", {})
    label = (r.get("code") or r.get("medicationCodeableConcept") or r.get("vaccineCode") or {}).get("text") or r.get("title")
    return f"{r.get('resourceType', '?')} ({label})" if isinstance(label, str) else r.get("resourceType", "?")


def prechecks(bundle: dict, warnings: list[str] = ()) -> list[dict]:
    """Fast local checks of structure, references and required data: useful feedback, not profile validation."""
    issues, entries = [issue("warning", "data", w) for w in warnings], bundle.get("entry", [])
    if bundle.get("type") != "document" or not entries or entries[0]["resource"].get("resourceType") != "Composition":
        return issues + [issue("error", "structure", "A document Bundle must be of type 'document' and start with its Composition")]
    known = {e.get("fullUrl") for e in entries}
    for i, entry in enumerate(entries):
        r = entry["resource"]
        issues += [issue("error", "reference", f"{describe(entry)} refers to {target}, which is not in the bundle", f"entry[{i}]")
                   for target in re.findall(r'"reference": "(urn:uuid:[^"]+)"', json.dumps(r)) if target not in known]
        issues += [issue("error", "required", f"{describe(entry)} needs {what}", f"entry[{i}]")
                   for element, what in REQUIRED.get(r["resourceType"], []) if not r.get(element)]
    return issues


def validator_available() -> bool:
    return settings.fhir_validator_jar.exists()


def validate(bundle: dict) -> tuple[str, list[dict], str]:
    """The HL7 validator with FHIR 4.0.1, the ABDM IG and terminology checks: (valid|invalid|error, issues, validator)."""
    if not validator_available():
        return "error", [issue("error", "validator", "HL7 FHIR validator is not installed (run scripts\\setup_validator.ps1)")], ""
    tools = settings.fhir_validator_jar.parent  # bundled JDK (tools/jdk-*), else JAVA_PATH, else `java` on PATH
    java = settings.java_path or next(iter([*tools.glob("jdk-*/bin/java.exe"), *tools.glob("jdk-*/bin/java")]), "java")
    with tempfile.TemporaryDirectory() as tmp:
        source, output = Path(tmp) / "bundle.json", Path(tmp) / "outcome.json"
        source.write_text(json.dumps(bundle), encoding="utf-8")
        try:
            run = subprocess.run([str(java), "-jar", str(settings.fhir_validator_jar), str(source), "-version", fhir.FHIR_VERSION,
                                  "-ig", fhir.IG_PACKAGE, "-tx", settings.fhir_tx_server, "-output", str(output)],
                                 capture_output=True, text=True, timeout=900)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return "error", [issue("error", "validator", f"The validator could not run: {exc}")], ""
        if not output.exists():
            return "error", [issue("error", "validator", "The validator produced no result: " + run.stdout[-500:])], ""
        outcome = json.loads(output.read_text(encoding="utf-8"))
    version = next((line.strip() for line in run.stdout.splitlines() if "FHIR Validation tool" in line), "HL7 FHIR Validator")
    entries, issues = bundle.get("entry", []), []
    for i in outcome.get("issue", []):
        where = (i.get("expression") or i.get("location") or [None])[0]
        n = re.match(r"Bundle\.entry\[(\d+)\]", where or "")  # e.g. "Observation (Hb): Bundle.entry[3].code"
        place = f"{describe(entries[int(n[1])])}: {where}" if n and int(n[1]) < len(entries) else where
        severity = "error" if i["severity"] in ("error", "fatal") else i["severity"]
        issues.append(issue(severity, "hl7", (i.get("details") or {}).get("text") or i.get("diagnostics") or "", place))
    status = "invalid" if any(x["severity"] == "error" for x in issues) else "valid"
    return status, issues, f"{version} · FHIR {fhir.FHIR_VERSION} · {fhir.IG_PACKAGE} · terminology: {settings.fhir_tx_server}"


def load_source(db: Session, user: User, source_type: str, source_id: int):
    """Load an approved record of this hospital and convert it to engine input."""
    model = {"consultation": Encounter, "prescription": Prescription, "lab_order": LabOrder}.get(source_type, ClinicalDocument)
    item = get_or_404(db, model, source_id, user.hospital_id)
    approved = (item.report is not None and item.report.status == "approved") if source_type == "lab_order" \
        else item.status == "approved"
    if not approved:
        raise HTTPException(409, "Only approved records can be converted to FHIR")
    if source_type == "consultation":
        prescriptions = db.scalars(select(Prescription).where(Prescription.encounter_id == item.id,
                                                              Prescription.status == "approved")).all()
        orders = db.scalars(select(LabOrder).where(LabOrder.encounter_id == item.id, LabOrder.status != "cancelled")).all()
        return consultation_source(item, prescriptions, orders)
    return {"prescription": prescription_source, "lab_order": lab_order_source}.get(source_type, document_source)(item)


def store_record(db: Session, user: User, source_type: str, source_id: int, request: Request | None = None) -> FhirRecord:
    """Generate (or regenerate, as a new version) and save the Bundle; any earlier validation no longer applies."""
    content, patient, author, doctors, warnings = load_source(db, user, source_type, source_id)
    if author is None:
        raise HTTPException(422, "The record has no responsible doctor, so it cannot be authored in FHIR")
    record = db.scalar(select(FhirRecord).where(FhirRecord.source_type == source_type, FhirRecord.source_id == source_id))
    record = record or FhirRecord(hospital_id=user.hospital_id, source_type=source_type, source_id=source_id, version=0)
    record.version += 1
    record.bundle = fhir.build_bundle(content, patient, user.hospital, author, doctors, record.version)
    record.patient_id, record.record_type, record.title = patient.id, content.record_type, content.title
    record.prechecks = prechecks(record.bundle, warnings)
    record.validation_status, record.validation_issues, record.validator, record.validated_at = "not_validated", None, None, None
    record.generated_by_id, record.generated_at = user.id, utcnow()
    db.add(record)
    db.flush()
    audit(db, user, "fhir.generate", "fhir_record", record.id,
          {"source": f"{source_type}/{source_id}", "record_type": record.record_type, "version": record.version}, request)
    return record


@router.get("/records", response_model=Page[FhirRecordSummary])
def list_records(patient_id: int | None = None, validation_status: str | None = None, source_type: str | None = None,
                 page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                 user: User = Depends(require("fhir:read")), db: Session = Depends(get_db)):
    query = select(FhirRecord).where(FhirRecord.hospital_id == user.hospital_id).order_by(FhirRecord.generated_at.desc())
    for column, wanted in ((FhirRecord.patient_id, patient_id), (FhirRecord.validation_status, validation_status),
                           (FhirRecord.source_type, source_type)):
        query = query.where(column == wanted) if wanted else query
    return paginate(db, query, page, page_size)


@router.post("/records", response_model=FhirRecordOut, status_code=201)
def generate_record(body: FhirGenerate, request: Request, user: User = Depends(require("fhir:generate")),
                    db: Session = Depends(get_db)):
    """Generate the FHIR record of an approved source; generating again creates the next version."""
    record = store_record(db, user, body.source_type, body.source_id, request)
    db.commit()
    return record


@router.get("/records/{record_id}", response_model=FhirRecordOut)
def get_record(record_id: int, user: User = Depends(require("fhir:read")), db: Session = Depends(get_db)):
    return get_or_404(db, FhirRecord, record_id, user.hospital_id)


@router.post("/records/{record_id}/validate", response_model=FhirRecordOut)
def validate_record(record_id: int, request: Request, user: User = Depends(require("fhir:generate")),
                    db: Session = Depends(get_db)):
    """Run the official HL7 validator (takes about a minute). Only valid records can be shared through ABDM."""
    record = get_or_404(db, FhirRecord, record_id, user.hospital_id)
    record.validation_status, record.validation_issues, record.validator = validate(record.bundle)
    record.validated_at = utcnow()
    audit(db, user, "fhir.validate", "fhir_record", record.id, {"status": record.validation_status, "version": record.version,
          "errors": sum(i["severity"] == "error" for i in record.validation_issues)}, request)
    db.commit()
    return record


@router.get("/records/{record_id}/download")
def download_record(record_id: int, request: Request, user: User = Depends(require("fhir:read")),
                    db: Session = Depends(get_db)):
    record = get_or_404(db, FhirRecord, record_id, user.hospital_id)
    audit(db, user, "fhir.download", "fhir_record", record.id, {"version": record.version}, request)
    db.commit()
    name = f"{record.record_type}-{record.source_type}-{record.source_id}-v{record.version}.json"
    return JSONResponse(record.bundle, media_type="application/fhir+json", headers={"Content-Disposition": f'attachment; filename="{name}"'})
