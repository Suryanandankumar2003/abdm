"""FHIR R4 (4.0.1) for the ABDM implementation guide `ndhm.in` 6.5.0 (NRCES), in three parts.

1. Engine (pure mapping): takes neutral clinical content (built by part 2 from Phase 2 records or from
   approved documents) plus the registry's patient, doctor and hospital, and returns a document Bundle.
   Profile URLs, fixed codes, section slices and required elements follow the IG's StructureDefinitions;
   every hard-coded SNOMED/LOINC code below was checked against tx.fhir.org. Conformance is checked by
   part 3 with the official HL7 validator, not here.

2. Sources: turn approved records into neutral engine input (ClinicalContent). The only part that knows both
   the database models and the engine's input; the engine (part 1) stays free of business logic. Conversions
   are conservative: anything that cannot be read unambiguously (a date that is not YYYY-MM-DD, an unknown
   route) stays as text and is reported as a warning instead of being guessed. Laboratory tests are identified by
   name only (no LOINC coding), which the ABDM lab profiles allow.

3. Validation, in two clearly separated layers:
   - prechecks(): fast local checks of Bundle structure, references and data the ABDM profiles require.
     Useful feedback, NOT profile validation.
   - validate(): the official HL7 FHIR Validator (Java) with FHIR 4.0.1 and the ABDM IG package, including
     terminology checks against FHIR_TX_SERVER. Only this result decides whether a record is valid.
"""

import base64
import json
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from functools import lru_cache
from html import escape
from pathlib import Path
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel

from app.config import settings
from app.extraction import ReviewedRecord, value
from app.models import (ClinicalDocument, Doctor, Encounter, Hospital, LabOrder, Patient, Prescription,
                        PrescriptionItem)

# ==============================================================================================================
# Part 1. Engine: neutral clinical content -> ABDM FHIR document Bundle (pure mapping)
# ==============================================================================================================

FHIR_VERSION = "4.0.1"
IG_PACKAGE = "ndhm.in#6.5.0"
NRCES = "https://nrces.in/ndhm/fhir/r4/StructureDefinition/"
SNOMED = "http://snomed.info/sct"
LOINC = "http://loinc.org"
ICD10 = "http://hl7.org/fhir/sid/icd-10"
UCUM = "http://unitsofmeasure.org"
V2_ID = "http://terminology.hl7.org/CodeSystem/v2-0203"
NDHM_ID = "https://nrces.in/ndhm/fhir/r4/CodeSystem/ndhm-identifier-type-code"
# Identifier systems as used in the IG's own examples.
ABHA_SYSTEM = "https://healthid.ndhm.gov.in"
HPR_SYSTEM = "https://doctor.ndhm.gov.in"
HFR_SYSTEM = "https://facility.ndhm.gov.in"

RecordType = Literal["OPConsultRecord", "PrescriptionRecord", "DiagnosticReportRecord", "DischargeSummaryRecord",
                     "ImmunizationRecord", "WellnessRecord", "HealthDocumentRecord"]

# ---------- terminology shared with the application forms ----------

# key: (label, LOINC code, UCUM unit, min, max)
VITAL_SIGNS = {
    "temperature": ("Body temperature", "8310-5", "Cel", 30, 45),
    "pulse": ("Heart rate", "8867-4", "/min", 20, 250),
    "respiratory_rate": ("Respiratory rate", "9279-1", "/min", 4, 80),
    "systolic_bp": ("Systolic blood pressure", "8480-6", "mm[Hg]", 50, 260),
    "diastolic_bp": ("Diastolic blood pressure", "8462-4", "mm[Hg]", 30, 160),
    "spo2": ("Oxygen saturation", "2708-6", "%", 50, 100),
    "weight": ("Body weight", "29463-7", "kg", 0.3, 400),
    "height": ("Body height", "8302-2", "cm", 20, 250),
}
LOINC_DISPLAY = {"2708-6": "Oxygen saturation in Arterial blood", "85354-9": "Blood pressure panel with all children optional"}
BODY_MEASUREMENTS = {"weight", "height"}  # WellnessRecord puts these under "Body Measurement"

# key: (label, SNOMED CT code, SNOMED preferred term)
ROUTES = {
    "oral": ("Oral", "26643006", "Oral route"),
    "iv": ("Intravenous", "47625008", "Intravenous route"),
    "im": ("Intramuscular", "78421000", "Intramuscular route"),
    "sc": ("Subcutaneous", "34206005", "Subcutaneous route"),
    "topical": ("Topical", "6064005", "Topical route"),
    "sublingual": ("Sublingual", "37839007", "Sublingual route"),
    "inhalation": ("Inhalation", "447694001", "Respiratory tract route"),
    "nasal": ("Nasal", "46713006", "Nasal route"),
    "ophthalmic": ("Eye", "54485002", "Ophthalmic route"),
    "otic": ("Ear", "10547007", "Otic route"),
    "rectal": ("Rectal", "37161004", "Rectal route"),
}

# key: (label, FHIR Timing.repeat or None for "as needed")
FREQUENCIES = {
    "OD": ("Once daily", {"frequency": 1, "period": 1, "periodUnit": "d"}),
    "BD": ("Twice daily", {"frequency": 2, "period": 1, "periodUnit": "d"}),
    "TDS": ("Three times daily", {"frequency": 3, "period": 1, "periodUnit": "d"}),
    "QID": ("Four times daily", {"frequency": 4, "period": 1, "periodUnit": "d"}),
    "Q6H": ("Every 6 hours", {"frequency": 1, "period": 6, "periodUnit": "h"}),
    "Q8H": ("Every 8 hours", {"frequency": 1, "period": 8, "periodUnit": "h"}),
    "HS": ("At bedtime", {"frequency": 1, "period": 1, "periodUnit": "d", "when": ["HS"]}),
    "WEEKLY": ("Once a week", {"frequency": 1, "period": 1, "periodUnit": "wk"}),
    "SOS": ("When required", None),
    "STAT": ("Immediately, once", {"count": 1}),
}


# ---------- neutral clinical content (engine input) ----------

class Coding(BaseModel):
    system: str
    code: str
    display: str


class ConditionData(BaseModel):
    text: str
    icd10: Coding | None = None  # only with the official ICD-10 title as display
    clinical_status: str = "active"
    verification: str = "provisional"
    onset: date | None = None
    note: str | None = None


class AllergyData(BaseModel):
    text: str
    reaction: str | None = None


class ObservationData(BaseModel):
    """A vital sign / body measurement (key from VITAL_SIGNS) or a free-text observation."""
    name: str
    key: str | None = None
    value: float | None = None
    value_text: str | None = None
    unit: str | None = None  # UCUM code when key is set


class MedicationData(BaseModel):
    name: str
    dosage: str | None = None
    route: str | None = None  # ROUTES key
    frequency: str | None = None  # FREQUENCIES key
    frequency_text: str | None = None  # as written, when it maps to no key
    duration_days: int | None = None
    duration_text: str | None = None
    quantity: int | None = None
    instructions: str | None = None


class OrderData(BaseModel):
    name: str
    status: str = "active"
    priority: str = "routine"
    authored: datetime | None = None
    note: str | None = None
    requester: int | None = None  # Doctor.id when not the author


class ResultData(BaseModel):
    name: str
    # This hospital identifies tests by name only; a coding is used for the simulated external provider's records.
    loinc: Coding | None = None
    value: str
    value_num: float | None = None
    unit: str | None = None
    ref_low: float | None = None
    ref_high: float | None = None
    ref_text: str | None = None
    interpretation: str | None = None  # N, L, H, A


class ReportData(BaseModel):
    name: str
    loinc: Coding | None = None  # as in ResultData
    results: list[ResultData]
    conclusion: str | None = None
    issued: datetime | None = None
    effective: datetime | None = None
    interpreter: int | None = None  # Doctor.id; must be one of the parties passed to build_bundle


class ImmunizationData(BaseModel):
    vaccine: str
    occurrence: str | None = None  # FHIR dateTime, possibly partial: YYYY, YYYY-MM or YYYY-MM-DD
    dose_number: int | None = None
    lot_number: str | None = None


class AttachmentData(BaseModel):
    content_type: str
    data: str  # base64
    title: str


class EncounterData(BaseModel):
    start: datetime
    end: datetime | None = None
    inpatient: bool = False
    status: str = "finished"
    reason: str | None = None


class ClinicalContent(BaseModel):
    record_type: RecordType
    key: str  # stable identity of the source record, e.g. "consultation-5" or "document-3"
    title: str
    date: datetime  # composition date (approval time)
    encounter: EncounterData | None = None
    conditions: list[ConditionData] = []
    allergies: list[AllergyData] = []
    observations: list[ObservationData] = []
    medications: list[MedicationData] = []
    medication_status: str = "active"
    orders: list[OrderData] = []
    reports: list[ReportData] = []
    immunizations: list[ImmunizationData] = []
    chief_complaint: str | None = None
    history: str | None = None
    findings: str | None = None
    plan: str | None = None
    follow_up: str | None = None
    hospital_course: str | None = None
    notes: str | None = None
    attachment: AttachmentData | None = None


# ---------- small helpers ----------

def uid(kind: str, key) -> str:
    """Stable UUID per local record, so regenerating a bundle reuses the same resource ids."""
    return str(uuid5(NAMESPACE_URL, f"abdm-hospital/{kind}/{key}"))


def ref(resource: dict, display: str | None = None, typed: bool = False) -> dict:
    reference = {"reference": f"urn:uuid:{resource['id']}"}
    if typed:
        reference["type"] = resource["resourceType"]
    if display:
        reference["display"] = display
    return reference


def coding(system: str, code: str, display: str) -> dict:
    return {"system": system, "code": code, "display": display}


def concept(text: str, *codings: dict) -> dict:
    return {"coding": list(codings), "text": text} if codings else {"text": text}


def iso(value: datetime | date | None) -> str | None:
    if isinstance(value, datetime):
        return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value).isoformat(timespec="seconds")
    return value.isoformat() if value else None


def narrative(text: str) -> dict:
    lines = "".join(f"<p>{escape(line)}</p>" for line in text.splitlines() if line.strip()) or "<p/>"
    return {"status": "generated", "div": f'<div xmlns="http://www.w3.org/1999/xhtml">{lines}</div>'}


def resource(resource_type: str, rid: str, profile: str | None, summary: str, **fields) -> dict:
    result = {"resourceType": resource_type, "id": rid}
    if profile:
        result["meta"] = {"profile": [NRCES + profile]}
    result["text"] = narrative(summary)
    result.update({k: v for k, v in fields.items() if v not in (None, [], {})})
    return result


def local_system(h: Hospital, what: str) -> str:
    return f"urn:abdm-hospital:{h.code.lower()}:{what}"


def identifier(type_system: str, type_code: str, type_display: str, system: str, value: str) -> dict:
    return {"type": {"coding": [coding(type_system, type_code, type_display)]}, "system": system, "value": value}


# ---------- parties (always from the registry, never from extracted text) ----------

def organization(h: Hospital) -> dict:
    ident = (identifier(V2_ID, "PRN", "Provider number", HFR_SYSTEM, h.hfr_id) if h.hfr_id else
             identifier(V2_ID, "XX", "Organization identifier", local_system(h, "organization"), h.code))
    telecom = [t for t in ({"system": "phone", "value": h.phone, "use": "work"} if h.phone else None,
                           {"system": "email", "value": h.email, "use": "work"} if h.email else None) if t]
    address = [{k: v for k, v in {"text": ", ".join(filter(None, [h.address, h.city, h.state, h.pincode])), "city": h.city,
                                  "state": h.state, "postalCode": h.pincode, "country": "IN"}.items() if v}]         if (h.address or h.city) else None  # FHIR forbids null values
    return resource("Organization", uid("organization", h.id), "Organization", h.name,
                    identifier=[ident], name=h.name, telecom=telecom, address=address)


def patient(p: Patient, h: Hospital) -> dict:
    identifiers = [identifier(V2_ID, "MR", "Medical record number", local_system(h, "patient"), p.patient_code)]
    if p.abha_verified and p.abha_number:  # unverified ABHA numbers are never exported
        abha = f"{p.abha_number[:2]}-{p.abha_number[2:6]}-{p.abha_number[6:10]}-{p.abha_number[10:]}"
        identifiers.append(identifier(NDHM_ID, "ABHA", "Ayushman Bharat Health Account (ABHA) ID", ABHA_SYSTEM, abha))
    return resource("Patient", uid("patient", p.id), "Patient", f"{p.full_name}, {p.patient_code}",
                    identifier=identifiers, name=[{"text": p.full_name}],
                    telecom=[{"system": "phone", "value": f"+91{p.mobile}", "use": "mobile"}],
                    gender={"M": "male", "F": "female", "O": "other", "U": "unknown"}[p.gender],
                    birthDate=iso(p.date_of_birth) or str(p.year_of_birth))


def practitioner(d: Doctor, h: Hospital) -> dict:
    identifiers = [identifier(V2_ID, "MD", "Medical License number", HPR_SYSTEM, d.hpr_id)] if d.hpr_id else []
    identifiers.append(identifier(V2_ID, "MD", "Medical License number", local_system(h, "medical-registration"),
                                  d.registration_number))
    return resource("Practitioner", uid("practitioner", d.id), "Practitioner", d.full_name,
                    identifier=identifiers, name=[{"text": d.full_name}],
                    qualification=[{"code": {"text": d.qualification}}] if d.qualification else None)


def practitioner_role(d: Doctor, h: Hospital, practitioner_res: dict, org: dict) -> dict:
    return resource("PractitionerRole", uid("practitioner-role", d.id), "PractitionerRole",
                    f"{d.full_name} at {h.name}",
                    practitioner=ref(practitioner_res, d.full_name), organization=ref(org, h.name),
                    specialty=[{"text": d.specialization}] if d.specialization else None)


# ---------- clinical resources ----------

class Builder:
    """Collects the resources of one document while sections reference them."""

    def __init__(self, c: ClinicalContent, p: Patient, h: Hospital, author: Doctor, doctors: list[Doctor]):
        self.c, self.h = c, h
        self.org = organization(h)
        self.patient = patient(p, h)
        self.practitioners = {d.id: practitioner(d, h) for d in [author, *doctors]}
        self.author = self.practitioners[author.id]
        self.role = practitioner_role(author, h, self.author, self.org)
        self.resources: list[dict] = []
        self.encounter = self.build_encounter() if c.encounter else None

    def add(self, res: dict) -> dict:
        self.resources.append(res)
        return res

    def subject(self) -> dict:
        return ref(self.patient, self.patient["name"][0]["text"])

    def context(self) -> dict:
        return {"encounter": ref(self.encounter)} if self.encounter else {}

    def rid(self, kind: str, index) -> str:
        return uid(kind, f"{self.c.key}/{index}")

    def build_encounter(self) -> dict:
        e = self.c.encounter
        return self.add(resource(
            "Encounter", self.rid("encounter", 0), "Encounter", f"{'Inpatient' if e.inpatient else 'Outpatient'} visit",
            identifier=[{"system": local_system(self.h, "encounter"), "value": self.c.key}],
            status=e.status,
            **{"class": coding("http://terminology.hl7.org/CodeSystem/v3-ActCode",
                               *(("IMP", "inpatient encounter") if e.inpatient else ("AMB", "ambulatory")))},
            subject=self.subject(),
            participant=[{"individual": ref(self.role, self.author["name"][0]["text"])}],
            period={"start": iso(e.start), "end": iso(e.end)} if e.end else {"start": iso(e.start)},
            reasonCode=[{"text": e.reason}] if e.reason else None,
            serviceProvider=ref(self.org, self.h.name)))

    def conditions(self) -> list[dict]:
        result = []
        for i, cond in enumerate(self.c.conditions):
            code = concept(cond.text, *([cond.icd10.model_dump()] if cond.icd10 else []))
            result.append(self.add(resource(
                "Condition", self.rid("condition", i), "Condition", cond.text,
                clinicalStatus=concept(cond.clinical_status, coding(
                    "http://terminology.hl7.org/CodeSystem/condition-clinical", cond.clinical_status,
                    cond.clinical_status.capitalize())),
                verificationStatus=concept(cond.verification, coding(
                    "http://terminology.hl7.org/CodeSystem/condition-ver-status", cond.verification,
                    cond.verification.capitalize())),
                code=code, subject=self.subject(), **self.context(),
                onsetDateTime=iso(cond.onset), recordedDate=iso(self.c.date),
                note=[{"text": cond.note}] if cond.note else None)))
        if self.encounter and result:
            uses = {"confirmed": ("39154008", "Clinical diagnosis"), "differential": ("47965005", "Differential diagnosis")}
            self.encounter["diagnosis"] = []
            for r, cond in zip(result, self.c.conditions):
                use = uses.get(cond.verification, ("148006", "Preliminary diagnosis"))
                self.encounter["diagnosis"].append({"condition": ref(r), "use": concept(use[1], coding(SNOMED, *use))})
        return result

    def allergies(self) -> list[dict]:
        return [self.add(resource(
            "AllergyIntolerance", self.rid("allergy", i), "AllergyIntolerance", a.text,
            clinicalStatus=concept("Active", coding(
                "http://terminology.hl7.org/CodeSystem/allergyintolerance-clinical", "active", "Active")),
            verificationStatus=concept("Unconfirmed", coding(
                "http://terminology.hl7.org/CodeSystem/allergyintolerance-verification", "unconfirmed", "Unconfirmed")),
            code={"text": a.text}, patient=self.subject(), **self.context(), recordedDate=iso(self.c.date),
            recorder=ref(self.author),
            reaction=[{"manifestation": [{"text": a.reaction}]}] if a.reaction else None))
            for i, a in enumerate(self.c.allergies)]

    def observations(self, wellness: bool = False) -> list[dict]:
        """Vital signs keep LOINC + UCUM coding; the BP pair becomes one panel with two components."""
        result, by_key = [], {o.key: o for o in self.c.observations if o.key and o.value is not None}
        when = iso(self.c.encounter.start if self.c.encounter else self.c.date)

        def vital(key: str, name: str, loinc_code: str, **value) -> dict:
            profile = ("ObservationBodyMeasurement" if key in BODY_MEASUREMENTS else "ObservationVitalSigns") \
                if wellness else "Observation"
            display = LOINC_DISPLAY.get(loinc_code, name)
            return self.add(resource(
                "Observation", self.rid("vital", key), profile, name, status="final",
                category=[concept("Vital Signs", coding(
                    "http://terminology.hl7.org/CodeSystem/observation-category", "vital-signs", "Vital Signs"))],
                code=concept(name, coding(LOINC, loinc_code, display)),
                subject=self.subject(), **self.context(), effectiveDateTime=when,
                performer=[ref(self.author)], **value))

        def quantity(o: ObservationData) -> dict:
            return {"value": o.value, "unit": o.unit, "system": UCUM, "code": o.unit}

        for key, (label, loinc_code, *_rest) in VITAL_SIGNS.items():
            if key in by_key and key not in ("systolic_bp", "diastolic_bp"):
                result.append(vital(key, label, loinc_code, valueQuantity=quantity(by_key[key])))
        bp = [k for k in ("systolic_bp", "diastolic_bp") if k in by_key]
        if bp:
            result.append(vital("bp", "Blood pressure", "85354-9", component=[
                {"code": concept(VITAL_SIGNS[k][0], coding(LOINC, VITAL_SIGNS[k][1], VITAL_SIGNS[k][0])),
                 "valueQuantity": quantity(by_key[k])} for k in bp]))
        for i, o in enumerate(o for o in self.c.observations if not (o.key and o.value is not None)):
            value = ({"valueQuantity": {"value": o.value, **({"unit": o.unit} if o.unit else {})}}
                     if o.value is not None else {"valueString": o.value_text})
            result.append(self.add(resource(
                "Observation", self.rid("observation", i), "Observation", o.name, status="final",
                code={"text": o.name}, subject=self.subject(), **self.context(), effectiveDateTime=when,
                performer=[ref(self.author)], **value)))
        return result

    def medications(self) -> list[dict]:
        result = []
        for i, m in enumerate(self.c.medications):
            parts = [m.dosage, FREQUENCIES[m.frequency][0].lower() if m.frequency else m.frequency_text,
                     f"for {m.duration_days} days" if m.duration_days else m.duration_text]
            dosage = {"text": " ".join(filter(None, parts)) or m.instructions or m.name}
            timing = FREQUENCIES[m.frequency][1] if m.frequency else None
            if m.frequency == "SOS":
                dosage["asNeededBoolean"] = True
            elif timing:
                dosage["timing"] = {"repeat": {**timing, **({"boundsDuration": {
                    "value": m.duration_days, "unit": "days", "system": UCUM, "code": "d"}} if m.duration_days else {})}}
            if m.route:
                label, code, display = ROUTES[m.route]
                dosage["route"] = concept(label, coding(SNOMED, code, display))
            if m.instructions:
                dosage["patientInstruction"] = m.instructions
            result.append(self.add(resource(
                "MedicationRequest", self.rid("medication", i), "MedicationRequest", f"{m.name}: {dosage['text']}",
                status=self.c.medication_status, intent="order", medicationCodeableConcept={"text": m.name},
                subject=self.subject(), **self.context(), authoredOn=iso(self.c.date.date()),
                requester=ref(self.author, self.author["name"][0]["text"]), dosageInstruction=[dosage],
                dispenseRequest={"quantity": {"value": m.quantity}} if m.quantity else None)))
        return result

    def orders(self) -> list[dict]:
        return [self.add(resource(
            "ServiceRequest", self.rid("order", i), "ServiceRequest", o.name, status=o.status, intent="order",
            priority=o.priority, code={"text": o.name}, subject=self.subject(), **self.context(),
            authoredOn=iso(o.authored), requester=self.doctor_ref(o.requester),
            note=[{"text": o.note}] if o.note else None)) for i, o in enumerate(self.c.orders)]

    def doctor_ref(self, doctor_id: int | None) -> dict:
        practitioner_res = self.practitioners.get(doctor_id, self.author)
        return ref(practitioner_res, practitioner_res["name"][0]["text"])

    def reports(self, orders: list[dict]) -> list[dict]:
        result = []
        for i, r in enumerate(self.c.reports):
            observations = []
            for j, res in enumerate(r.results):
                unit = {"unit": res.unit} if res.unit else {}
                ref_range = {k: v for k, v in {
                    "low": {"value": res.ref_low, **unit} if res.ref_low is not None else None,
                    "high": {"value": res.ref_high, **unit} if res.ref_high is not None else None,
                    "text": res.ref_text}.items() if v is not None}
                labels = {"N": "Normal", "L": "Low", "H": "High", "A": "Abnormal"}
                observations.append(self.add(resource(
                    "Observation", self.rid("lab-result", f"{i}/{j}"), "Observation", f"{res.name}: {res.value} {res.unit or ''}",
                    status="final",
                    category=[concept("Laboratory", coding(
                        "http://terminology.hl7.org/CodeSystem/observation-category", "laboratory", "Laboratory"))],
                    code=concept(res.name, *([res.loinc.model_dump()] if res.loinc else [])),
                    subject=self.subject(), **self.context(), effectiveDateTime=iso(r.effective),
                    performer=[ref(self.org, self.h.name)],
                    **({"valueQuantity": {"value": res.value_num, **unit}} if res.value_num is not None
                       else {"valueString": res.value}),
                    interpretation=[concept(labels[res.interpretation], coding(
                        "http://terminology.hl7.org/CodeSystem/v3-ObservationInterpretation", res.interpretation,
                        labels[res.interpretation]))] if res.interpretation else None,
                    referenceRange=[ref_range] if ref_range else None)))
            interpreter = self.practitioners.get(r.interpreter)
            result.append(self.add(resource(
                "DiagnosticReport", self.rid("diagnostic-report", i), "DiagnosticReportLab", r.name, status="final",
                basedOn=[ref(o) for o in orders] or None,
                category=[concept("Laboratory test", coding(SNOMED, "15220000", "Laboratory test"))],
                code=concept(r.name, *([r.loinc.model_dump()] if r.loinc else [])),
                subject=self.subject(), **self.context(), effectiveDateTime=iso(r.effective), issued=iso(r.issued),
                performer=[ref(self.org, self.h.name)],
                resultsInterpreter=[ref(interpreter, interpreter["name"][0]["text"])] if interpreter else None,
                result=[ref(o) for o in observations], conclusion=r.conclusion)))
        return result

    def immunizations(self) -> list[dict]:
        result = []
        for i, im in enumerate(self.c.immunizations):
            result.append(self.add(resource(
                "Immunization", self.rid("immunization", i), "Immunization", im.vaccine, status="completed",
                vaccineCode={"text": im.vaccine}, patient=self.subject(), **self.context(), occurrenceDateTime=im.occurrence,
                primarySource=False, lotNumber=im.lot_number,
                protocolApplied=[{"doseNumberPositiveInt": im.dose_number}] if im.dose_number else None)))
        return result

    def attachment(self, as_binary: bool = False) -> dict | None:
        a = self.c.attachment
        if a is None:
            return None
        if as_binary:  # Binary is not a DomainResource, so it carries no narrative
            return self.add({"resourceType": "Binary", "id": self.rid("binary", 0), "meta": {"profile": [NRCES + "Binary"]},
                             "contentType": a.content_type, "data": a.data})
        return self.add(resource(
            "DocumentReference", self.rid("document-reference", 0), "DocumentReference", a.title,
            status="current", docStatus="final", type={"text": a.title}, subject=self.subject(),
            date=iso(self.c.date), author=[ref(self.author)], custodian=ref(self.org),
            content=[{"attachment": {"contentType": a.content_type, "data": a.data, "title": a.title}}],
            context={"encounter": [ref(self.encounter)]} if self.encounter else None))


def section(title: str, code: tuple[str, str] | None, entries: list[dict] | None = None, text: str | None = None) -> dict | None:
    """A Composition section; dropped when it would have neither entries nor text."""
    if not entries and not text:
        return None
    result = {"title": title}
    if code:
        result["code"] = {"coding": [coding(SNOMED, *code)]}
    if entries:
        result["entry"] = [ref(e, typed=True) for e in entries]
    if text:
        result["text"] = narrative(text)
    return result


def lines(*pairs: tuple[str, str | None]) -> str | None:
    return "\n".join(f"{label}: {value}" for label, value in pairs if value) or None


# Composition type and section layout per record profile.
COMPOSITION_TYPES = {
    "OPConsultRecord": ("371530004", "Clinical consultation report"),
    "PrescriptionRecord": ("440545006", "Prescription record"),
    "DiagnosticReportRecord": ("721981007", "Diagnostic studies report"),
    "DischargeSummaryRecord": ("373942005", "Discharge summary"),
    "ImmunizationRecord": ("41000179103", "Immunization record"),
    "HealthDocumentRecord": ("419891008", "Record artifact"),
}


def build_sections(b: Builder) -> list[dict]:
    c, kind = b.c, b.c.record_type
    if kind == "OPConsultRecord":
        orders = b.orders()
        return [
            section("Chief complaints", ("422843007", "Chief complaint section"), b.conditions(),
                    lines(("Chief complaint", c.chief_complaint), ("History", c.history))),
            section("Allergies", ("722446000", "Allergy record"), b.allergies()),
            section("Physical examination", ("425044008", "Physical exam section"), b.observations(), c.findings),
            section("Investigation advice", ("721963009", "Order document"), orders),
            section("Medications", ("721912009", "Medication summary document"), b.medications()),
            section("Follow up", ("390906007", "Follow-up encounter"), None,
                    lines(("Plan", c.plan), ("Follow-up", c.follow_up), ("Notes", c.notes))),
            section("Document reference", ("371530004", "Clinical consultation report"), [b.attachment()] if c.attachment else None),
        ]
    if kind == "PrescriptionRecord":
        entries = b.medications() + ([b.attachment(as_binary=True)] if c.attachment else [])
        return [section("Prescription record", ("440545006", "Prescription record"), entries, c.notes)]
    if kind == "DiagnosticReportRecord":
        entries = b.reports(b.orders()) + ([b.attachment()] if c.attachment else [])
        return [section("Diagnostic studies report", ("721981007", "Diagnostic studies report"), entries)]
    if kind == "DischargeSummaryRecord":
        return [
            section("Chief complaints", ("422843007", "Chief complaint section"), b.conditions(),
                    lines(("Chief complaint", c.chief_complaint))),
            section("Allergies", ("722446000", "Allergy record"), b.allergies()),
            section("Medical history", ("1003642006", "Past medical history section"), None, c.history),
            section("Physical examination", ("425044008", "Physical exam section"), b.observations(), c.findings),
            section("Investigations", ("721981007", "Diagnostic studies report"), b.reports([])),
            section("Medications", ("1003606003", "Medication history section"), b.medications()),
            section("Care plan", ("734163000", "Care plan"), None, lines(
                ("Hospital course", c.hospital_course), ("Plan", c.plan), ("Follow-up", c.follow_up), ("Notes", c.notes))),
            section("Document reference", ("373942005", "Discharge summary"), [b.attachment()] if c.attachment else None),
        ]
    if kind == "ImmunizationRecord":
        entries = b.immunizations() + ([b.attachment()] if c.attachment else [])
        return [section("Immunization record", ("41000179103", "Immunization record"), entries)]
    if kind == "WellnessRecord":
        observations = b.observations(wellness=True)
        vitals = [o for o in observations if o["meta"]["profile"][0].endswith("VitalSigns")]
        body = [o for o in observations if o["meta"]["profile"][0].endswith("BodyMeasurement")]
        other = [o for o in observations if o["meta"]["profile"][0].endswith("/Observation")]
        return [section("Vital Signs", None, vitals), section("Body Measurement", None, body),
                section("Other Observations", None, other, c.notes),
                section("Document Reference", None, [b.attachment()] if c.attachment else None)]
    return [section("Record artifact", ("419891008", "Record artifact"), [b.attachment()] if c.attachment else None,
                    None if c.attachment else c.notes)]


def build_bundle(c: ClinicalContent, p: Patient, h: Hospital, author: Doctor, doctors: list[Doctor] = (),
                 version: int = 1) -> dict:
    """Assemble the document Bundle: Composition first, then every resource it (transitively) references."""
    b = Builder(c, p, h, author, list(doctors))
    sections = [s for s in build_sections(b) if s]
    ctype = COMPOSITION_TYPES.get(c.record_type)
    composition = resource(
        "Composition", uid("composition", c.key), c.record_type, c.title,
        identifier={"system": local_system(h, "document"), "value": uid("composition", c.key)},
        status="final",
        type=concept(ctype[1], coding(SNOMED, *ctype)) if ctype else {"text": "Wellness Record"},
        subject=b.subject(), encounter=ref(b.encounter) if b.encounter else None, date=iso(c.date),
        author=[ref(b.author, b.author["name"][0]["text"])], title=c.title,
        attester=[{"mode": "legal", "time": iso(c.date), "party": ref(b.role, b.author["name"][0]["text"])}],
        custodian=ref(b.org, h.name), section=sections)
    now = iso(datetime.now(timezone.utc))
    parties = [b.patient, *b.practitioners.values(), b.role, b.org]
    return {
        "resourceType": "Bundle",
        "id": uid("bundle", c.key),
        "meta": {"versionId": str(version), "lastUpdated": now, "profile": [NRCES + "DocumentBundle"]},
        "identifier": {"system": local_system(h, "bundle"), "value": uid("bundle", c.key)},
        "type": "document",
        "timestamp": now,
        "entry": [{"fullUrl": f"urn:uuid:{r['id']}", "resource": r} for r in [composition, *parties, *b.resources]],
    }


# ==============================================================================================================
# Part 2. Sources: approved records -> neutral engine input (ClinicalContent)
# ==============================================================================================================

RECORD_TYPES = {
    "prescription": "PrescriptionRecord", "lab_report": "DiagnosticReportRecord", "opd_consultation": "OPConsultRecord",
    "discharge_summary": "DischargeSummaryRecord", "immunization": "ImmunizationRecord", "wellness": "WellnessRecord",
    "clinical_note": "HealthDocumentRecord", "other": "HealthDocumentRecord",
}


@dataclass
class Source:
    content: ClinicalContent
    patient: Patient
    author: Doctor | None
    doctors: list[Doctor] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@lru_cache(maxsize=2000)
def terminology_display(system: str, code: str) -> str | None:
    """Official display of a code from the terminology server (FHIR $lookup); None if unknown/unreachable."""
    if settings.fhir_tx_server == "n/a":
        return None
    url = f"{settings.fhir_tx_server}/r4/CodeSystem/$lookup?" + urllib.parse.urlencode({"system": system, "code": code})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/fhir+json"}),
                                    timeout=20) as response:
            parameters = json.load(response).get("parameter", [])
    except (OSError, ValueError):
        return None
    return next((p.get("valueString") for p in parameters if p.get("name") == "display"), None)


def icd10_coding(code: str | None, warnings: list[str], what: str) -> Coding | None:
    if not code:
        return None
    display = terminology_display(ICD10, code)
    if display is None:
        warnings.append(f"{what}: ICD-10 code {code} could not be verified on the terminology server, "
                        "so the diagnosis is exported as text only")
        return None
    return Coding(system=ICD10, code=code, display=display)


# ---------- Phase 2 records ----------

def phase2_medication(item: PrescriptionItem) -> MedicationData:
    return MedicationData(name=item.medicine_name, dosage=item.dosage, route=item.route, frequency=item.frequency,
                          duration_days=item.duration_days, quantity=item.quantity, instructions=item.instructions)


def consultation_source(e: Encounter, prescriptions: list[Prescription], orders: list[LabOrder]) -> Source:
    # Only the consulting doctor's prescriptions/orders belong to this note; others export on their own.
    prescriptions = [p for p in prescriptions if p.doctor_id == e.doctor_id]
    orders = [o for o in orders if o.doctor_id == e.doctor_id]
    warnings = []
    follow_up = " ".join(filter(None, [e.follow_up_instructions,
                                       f"Review on {e.follow_up_date.isoformat()}." if e.follow_up_date else None]))
    content = ClinicalContent(
        record_type="OPConsultRecord", key=f"consultation-{e.id}", title="Consultation record", date=e.approved_at,
        encounter=EncounterData(start=e.visit_at, reason=e.chief_complaint),
        conditions=[ConditionData(text=c.display, icd10=icd10_coding(c.code, warnings, c.display),
                                  clinical_status=c.clinical_status,
                                  verification=c.verification_status, onset=c.onset_date, note=c.note)
                    for c in e.conditions],
        observations=[ObservationData(name=VITAL_SIGNS[k][0], key=k, value=v, unit=VITAL_SIGNS[k][2])
                      for k, v in (e.vitals or {}).items() if v is not None and k in VITAL_SIGNS],
        medications=[phase2_medication(i) for p in prescriptions for i in p.items],
        orders=[OrderData(name=o.test.name, status="completed" if o.status == "completed" else "active",
                          priority=o.priority, authored=o.created_at, note=o.clinical_notes) for o in orders],
        chief_complaint=e.chief_complaint, history=e.history_present_illness, findings=e.clinical_findings,
        plan=e.treatment_plan, follow_up=follow_up or None)  # doctor_notes are internal and never exported
    return Source(content, e.patient, e.doctor, warnings=warnings)


def prescription_source(p: Prescription) -> Source:
    content = ClinicalContent(
        record_type="PrescriptionRecord", key=f"prescription-{p.id}", title="Prescription", date=p.approved_at,
        encounter=EncounterData(start=p.encounter.visit_at,
                                status="finished" if p.encounter.status == "approved" else "in-progress"),
        medications=[phase2_medication(i) for i in p.items], notes=p.notes)
    return Source(content, p.patient, p.doctor)


def lab_order_source(o: LabOrder) -> Source:
    r = o.report
    results = [ResultData(name=x.name, value=x.value, value_num=x.value_numeric, unit=x.unit, ref_low=x.ref_low,
                          ref_high=x.ref_high, ref_text=x.ref_text, interpretation=x.interpretation) for x in r.results]
    content = ClinicalContent(
        record_type="DiagnosticReportRecord", key=f"lab-order-{o.id}", title=f"Laboratory report: {o.test.name}",
        date=r.approved_at, encounter=EncounterData(start=o.created_at),
        orders=[OrderData(name=o.test.name, status="completed", priority=o.priority, authored=o.created_at,
                          note=o.clinical_notes, requester=o.doctor_id)],
        reports=[ReportData(name=o.test.name, results=results, conclusion=r.conclusion, issued=r.approved_at,
                            effective=o.sample_collected_at, interpreter=r.approved_by_doctor_id)])
    return Source(content, o.patient, r.approved_by_doctor, [o.doctor])


# ---------- reviewed documents ----------

def parse_iso_date(text: str | None) -> date | None:
    try:
        return date.fromisoformat(text.strip()) if text else None
    except ValueError:
        return None


def parse_number(text: str | None) -> float | None:
    try:
        return float(text.replace(",", "").strip()) if text else None
    except ValueError:
        return None


def parse_range(text: str | None) -> tuple[float | None, float | None, str | None]:
    if not text:
        return None, None, None
    if m := re.fullmatch(r"\s*([\d.]+)\s*(?:-|–|to)\s*([\d.]+)\s*\S*\s*", text):
        return float(m[1]), float(m[2]), None
    if m := re.fullmatch(r"\s*(?:<|<=|≤|up to)\s*([\d.]+)\s*\S*\s*", text, re.I):
        return None, float(m[1]), None
    if m := re.fullmatch(r"\s*(?:>|>=|≥)\s*([\d.]+)\s*\S*\s*", text):
        return float(m[1]), None, None
    return None, None, text


FLAGS = {"H": "H", "HIGH": "H", "↑": "H", "L": "L", "LOW": "L", "↓": "L", "*": "A", "A": "A", "ABNORMAL": "A",
         "N": "N", "NORMAL": "N"}
ROUTE_WORDS = {"oral": "oral", "po": "oral", "by mouth": "oral", "iv": "iv", "intravenous": "iv", "im": "im",
               "intramuscular": "im", "sc": "sc", "s/c": "sc", "subcutaneous": "sc", "topical": "topical",
               "local application": "topical", "sublingual": "sublingual", "sl": "sublingual", "inhalation": "inhalation",
               "inhaled": "inhalation", "nasal": "nasal", "eye": "ophthalmic", "ophthalmic": "ophthalmic",
               "ear": "otic", "otic": "otic", "rectal": "rectal", "pr": "rectal"}
FREQUENCY_WORDS = {"od": "OD", "once daily": "OD", "once a day": "OD", "1-0-0": "OD", "0-0-1": "HS", "hs": "HS",
                   "at bedtime": "HS", "bd": "BD", "bid": "BD", "twice daily": "BD", "twice a day": "BD", "1-0-1": "BD",
                   "tds": "TDS", "tid": "TDS", "thrice daily": "TDS", "three times a day": "TDS", "1-1-1": "TDS",
                   "qid": "QID", "four times a day": "QID", "1-1-1-1": "QID", "q6h": "Q6H", "q8h": "Q8H",
                   "weekly": "WEEKLY", "once a week": "WEEKLY", "sos": "SOS", "prn": "SOS", "as needed": "SOS",
                   "stat": "STAT"}
VITAL_WORDS = {"temperature": "temperature", "temp": "temperature", "pulse": "pulse", "heart rate": "pulse",
               "hr": "pulse", "pr": "pulse", "respiratory rate": "respiratory_rate", "rr": "respiratory_rate",
               "spo2": "spo2", "oxygen saturation": "spo2", "sao2": "spo2", "weight": "weight", "wt": "weight",
               "height": "height", "ht": "height", "bp": "bp", "blood pressure": "bp"}
UNITS = {"°c": "Cel", "c": "Cel", "cel": "Cel", "°f": "[degF]", "f": "[degF]", "bpm": "/min", "/min": "/min",
         "per min": "/min", "beats/min": "/min", "breaths/min": "/min", "%": "%", "kg": "kg", "kgs": "kg",
         "lb": "[lb_av]", "lbs": "[lb_av]", "cm": "cm", "in": "[in_i]", "inch": "[in_i]", "m": "m",
         "mmhg": "mm[Hg]", "mm hg": "mm[Hg]"}
PER_MINUTE = {"pulse", "respiratory_rate"}  # always counted per minute, even when the unit is not written


def word(table: dict, text: str | None) -> str | None:
    return table.get(" ".join(text.lower().split())) if text else None


def document_vitals(record: ReviewedRecord) -> list[ObservationData]:
    result = []
    for v in record.vitals:
        name, raw, unit_text = value(v.name), value(v.value), value(v.unit)
        if not name or not raw:
            continue
        key = word(VITAL_WORDS, name)
        unit = word(UNITS, unit_text) or ("/min" if key in PER_MINUTE else "mm[Hg]" if key == "bp" else None)
        if key == "bp" and (m := re.fullmatch(r"\s*(\d+)\s*/\s*(\d+)\s*", raw)) and unit == "mm[Hg]":
            result += [ObservationData(name="Systolic blood pressure", key="systolic_bp", value=float(m[1]), unit=unit),
                       ObservationData(name="Diastolic blood pressure", key="diastolic_bp", value=float(m[2]), unit=unit)]
        elif key and key != "bp" and (number := parse_number(raw)) is not None and unit:
            result.append(ObservationData(name=VITAL_SIGNS[key][0], key=key, value=number, unit=unit))
        else:  # kept as written when it cannot be coded safely
            result.append(ObservationData(name=name, value=parse_number(raw), value_text=raw, unit=unit_text))
    return result


def document_medication(m) -> MedicationData | None:
    name = value(m.name)
    if not name:
        return None
    duration = value(m.duration)
    days = None
    if duration and (d := re.fullmatch(r"\s*(?:x\s*)?(\d+)\s*(d|days?|w|wks?|weeks?)\s*", duration, re.I)):
        days = int(d[1]) * (7 if d[2].lower().startswith("w") else 1)
    frequency = value(m.frequency)
    quantity = parse_number(value(m.quantity))
    return MedicationData(name=name, dosage=value(m.dosage), route=word(ROUTE_WORDS, value(m.route)),
                          frequency=word(FREQUENCY_WORDS, frequency), frequency_text=frequency,
                          duration_days=days, duration_text=None if days else duration,
                          quantity=int(quantity) if quantity and quantity.is_integer() else None,
                          instructions=value(m.instructions))


def document_condition(d, warnings: list[str]) -> ConditionData:
    code = (value(d.icd10_code) or "").strip().upper() or None
    return ConditionData(text=value(d.text), icd10=icd10_coding(code, warnings, value(d.text)))


def document_source(doc: ClinicalDocument) -> Source:
    record, warnings = ReviewedRecord.model_validate(doc.data), []
    kind = RECORD_TYPES[doc.document_type]
    enc = record.encounter
    visit = parse_iso_date(value(enc.visit_date)) or parse_iso_date(value(record.document_date))
    admitted, discharged = parse_iso_date(value(enc.admission_date)), parse_iso_date(value(enc.discharge_date))
    for label, raw, parsed in (("Visit/document date", value(enc.visit_date) or value(record.document_date), visit),
                               ("Admission date", value(enc.admission_date), admitted),
                               ("Discharge date", value(enc.discharge_date), discharged)):
        if raw and parsed is None:
            warnings.append(f"{label} '{raw}' is not in YYYY-MM-DD format, so it was not used")

    encounter = None
    if kind == "DischargeSummaryRecord" and admitted:
        encounter = EncounterData(start=datetime.combine(admitted, datetime.min.time()), inpatient=True,
                                  end=datetime.combine(discharged, datetime.min.time()) if discharged else None)
    elif kind == "OPConsultRecord" and visit:
        encounter = EncounterData(start=datetime.combine(visit, datetime.min.time()), reason=value(enc.chief_complaint))

    results = []
    for r in record.lab_results:
        name, raw = value(r.test_name), value(r.value)
        if not name or raw is None:
            continue
        low, high, ref_text = parse_range(value(r.reference_range))
        results.append(ResultData(name=name, value=raw, value_num=parse_number(raw), unit=value(r.unit), ref_low=low,
                                  ref_high=high, ref_text=ref_text,
                                  interpretation=FLAGS.get((value(r.flag) or "").strip().upper())))
    panels = {value(r.panel_name) for r in record.lab_results if value(r.panel_name)}
    reports = [ReportData(name=panels.pop() if len(panels) == 1 else "Laboratory report", results=results,
                          conclusion=value(record.report_conclusion), issued=doc.approved_at,
                          effective=datetime.combine(visit, datetime.min.time()) if visit else None,
                          interpreter=doc.approved_by_doctor_id)] if results else []

    immunizations = []
    for im in record.immunizations:
        if vaccine := value(im.vaccine):
            when, dose = value(im.date), parse_number(value(im.dose_number))
            partial = when if when and re.fullmatch(r"\d{4}(-\d{2}(-\d{2})?)?", when.strip()) else None
            if when and not partial:
                warnings.append(f"{vaccine}: date '{when}' must be YYYY, YYYY-MM or YYYY-MM-DD; correct it in review")
            immunizations.append(ImmunizationData(vaccine=vaccine, occurrence=partial and partial.strip(),
                                                  dose_number=int(dose) if dose and dose.is_integer() else None,
                                                  lot_number=value(im.lot_number)))

    data = (settings.upload_dir / doc.storage_name).read_bytes()
    content = ClinicalContent(
        record_type=kind, key=f"document-{doc.id}", title=doc.file_name, date=doc.approved_at, encounter=encounter,
        conditions=[document_condition(d, warnings) for d in record.diagnoses if value(d.text)],
        allergies=[AllergyData(text=s, reaction=value(a.reaction)) for a in record.allergies if (s := value(a.substance))],
        observations=document_vitals(record),
        medications=[m for m in map(document_medication, record.medications) if m],
        reports=reports, immunizations=immunizations,
        chief_complaint=value(enc.chief_complaint), history=value(enc.history_of_present_illness),
        findings=value(enc.examination_findings), plan=value(enc.treatment_plan), follow_up=value(enc.follow_up),
        hospital_course=value(enc.hospital_course),
        notes="\n".join(filter(None, [value(enc.instructions), value(record.notes)])) or None,
        attachment=AttachmentData(content_type=doc.content_type, data=base64.b64encode(data).decode(), title=doc.file_name))
    return Source(content, doc.patient, doc.author_doctor,
                  [doc.approved_by_doctor] if doc.approved_by_doctor else [], warnings)


# ==============================================================================================================
# Part 3. Validation: local pre-checks and the official HL7 FHIR validator
# ==============================================================================================================

def issue(severity: str, category: str, message: str, location: str | None = None) -> dict:
    return {"severity": severity, "category": category, "message": message, "location": location}


def describe(entry: dict) -> str:
    """Readable name of a bundle entry, e.g. 'Observation (Haemoglobin)'."""
    r = entry.get("resource", {})
    concept = r.get("code") or r.get("medicationCodeableConcept") or r.get("vaccineCode") or {}
    label = concept.get("text") or r.get("title") or r.get("name")
    if isinstance(label, list):
        label = label[0].get("text") if label else None
    return f"{r.get('resourceType', '?')} ({label})" if isinstance(label, str) else r.get("resourceType", "?")


def find_references(node, path: str = ""):
    if isinstance(node, dict):
        for key, child in node.items():
            if key == "reference" and isinstance(child, str):
                yield path, child
            else:
                yield from find_references(child, f"{path}.{key}" if path else key)
    elif isinstance(node, list):
        for i, child in enumerate(node):
            yield from find_references(child, f"{path}[{i}]")


# Elements the ABDM profiles require (min=1) that depend on source data rather than on the engine.
REQUIRED = {
    "DiagnosticReport": [("result", "at least one result"), ("conclusion", "a conclusion"),
                         ("resultsInterpreter", "an approving doctor (results interpreter)")],
    "MedicationRequest": [("dosageInstruction", "dosage instructions"), ("requester", "a prescriber")],
    "Immunization": [("occurrenceDateTime", "a vaccination date as YYYY, YYYY-MM or YYYY-MM-DD")],
    "Composition": [("section", "at least one section with content"), ("author", "an author")],
}


def prechecks(bundle: dict, warnings: list[str] = ()) -> list[dict]:
    issues = [issue("warning", "data", w) for w in warnings]
    entries = bundle.get("entry", [])
    if bundle.get("type") != "document":
        issues.append(issue("error", "structure", "Bundle type must be 'document'"))
    if not entries or entries[0]["resource"].get("resourceType") != "Composition":
        issues.append(issue("error", "structure", "The first entry of a document Bundle must be the Composition"))
        return issues
    urls = [e.get("fullUrl") for e in entries]
    if len(urls) != len(set(urls)):
        issues.append(issue("error", "structure", "Two entries share the same fullUrl"))
    known = set(urls)
    for i, entry in enumerate(entries):
        r = entry["resource"]
        for path, target in find_references(r):
            if target.startswith("urn:uuid:") and target not in known:
                issues.append(issue("error", "reference", f"{describe(entry)} refers to {target}, which is not in the bundle",
                                    f"entry[{i}].{path}"))
        for fields, what in REQUIRED.get(r["resourceType"], []):
            if not any(r.get(f) for f in fields.split("|")):
                issues.append(issue("error", "required", f"{describe(entry)} needs {what}", f"entry[{i}]"))
    composition = entries[0]["resource"]
    record_type = composition["meta"]["profile"][0].removeprefix(NRCES)
    if record_type in ("OPConsultRecord", "DischargeSummaryRecord") and not composition.get("encounter"):
        what = "an admission date" if record_type == "DischargeSummaryRecord" else "a visit date"
        issues.append(issue("error", "required", f"{record_type} needs an encounter, which needs {what} (YYYY-MM-DD)"))
    return issues


# ---------- official HL7 validator ----------

def java_executable() -> str:
    if settings.java_path:
        return settings.java_path
    tools = settings.fhir_validator_jar.parent
    bundled = sorted(tools.glob("jdk-*/bin/java.exe")) + sorted(tools.glob("jdk-*/bin/java"))
    return str(bundled[0]) if bundled else "java"


def validator_available() -> bool:
    return settings.fhir_validator_jar.exists()


def categorise(text: str) -> str:
    lowered = text.lower()
    if any(k in lowered for k in ("minimum required", "is required", "cardinality")):
        return "required"
    if any(k in lowered for k in ("code", "valueset", "value set", "display", "codesystem", "terminology")):
        return "terminology"
    if any(k in lowered for k in ("reference", "resolve", "not found in the bundle", "reachable")):
        return "reference"
    if any(k in lowered for k in ("slice", "profile", "fixed value", "pattern")):
        return "profile"
    return "other"


def plain_location(expression: str | None, entries: list[dict]) -> str | None:
    """'Bundle.entry[3].resource.code' -> 'Observation (Haemoglobin) › code'."""
    if not expression:
        return None
    m = re.match(r"Bundle\.entry\[(\d+)\]\.resource(?:/\*[^*]*\*/)?\.?(.*)", expression)
    if not m or int(m[1]) >= len(entries):
        return expression
    element = m[2].replace(".", " › ")
    return f"{describe(entries[int(m[1])])}{' › ' + element if element else ''}"


def validate(bundle: dict) -> tuple[str, list[dict], str]:
    """Run the HL7 validator. Returns (status, issues, validator description)."""
    if not validator_available():
        return "error", [issue("error", "validator",
                               "HL7 FHIR validator is not installed. Run scripts\\setup_validator.ps1 in the backend folder.")], ""
    with tempfile.TemporaryDirectory() as tmp:
        source, output = Path(tmp) / "bundle.json", Path(tmp) / "outcome.json"
        source.write_text(json.dumps(bundle), encoding="utf-8")
        command = [java_executable(), "-jar", str(settings.fhir_validator_jar), str(source), "-version", FHIR_VERSION,
                   "-ig", IG_PACKAGE, "-tx", settings.fhir_tx_server, "-output", str(output)]
        try:
            run = subprocess.run(command, capture_output=True, text=True, timeout=900)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return "error", [issue("error", "validator", f"The validator could not run: {exc}")], ""
        version = next((line.strip() for line in run.stdout.splitlines() if "FHIR Validation tool" in line), "HL7 FHIR Validator")
        if not output.exists():
            return "error", [issue("error", "validator", "The validator produced no result: " + run.stdout[-500:])], version
        outcome = json.loads(output.read_text(encoding="utf-8"))
    entries = bundle.get("entry", [])
    issues = []
    for i in outcome.get("issue", []):
        text = (i.get("details") or {}).get("text") or i.get("diagnostics") or ""
        expression = (i.get("expression") or i.get("location") or [None])[0]
        severity = "error" if i["severity"] in ("error", "fatal") else i["severity"]
        issues.append({**issue(severity, categorise(text), text, plain_location(expression, entries)),
                       "expression": expression})
    status = "invalid" if any(x["severity"] == "error" for x in issues) else "valid"
    description = f"{version} · FHIR {FHIR_VERSION} · {IG_PACKAGE} · terminology: {settings.fhir_tx_server}"
    return status, issues, description
