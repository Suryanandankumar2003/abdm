"""ABDM Health Information Provider (HIP): sharing this hospital's records through ABDM.

Sections, in order:
- Encryption: ECDH on Curve25519 + HKDF-SHA256 + AES-256-GCM, compatible with NHA's wrapper and Fidelius.
- ABDM gateway client: session token, request headers, outbound calls and callback authentication.
- HIP workflows: identity linking, care contexts, discovery, user-initiated linking, consent and data transfer.
- Simulator: in-process stand-in for the ABDM gateway, consent manager, ABHA app and an HIU (simulation mode only).
- API routes: HIP staff API (/api/hip/...) and ABDM callback endpoints (bridge paths /api/v3/...).
"""

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid
from datetime import date, datetime, timedelta, timezone

import httpx
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import demo
from app.config import settings
from app.database import SessionLocal, get_db
from app.fhir import validator_available
from app.models import (CareContext, FhirRecord, HipConsent, HipLinkRequest, HipPatientLink, HipTransaction, Hospital,
                        Patient, User, utcnow)
from app.schemas import ORMModel, Page, PatientSummary, UTCDateTime
from app.security import require
from app.services import audit, get_or_404, name_similarity, paginate


# ====================================================================================================================
# Encryption (formerly app/hip/crypto.py)
# ====================================================================================================================
# ABDM health-information encryption (ECDH on Curve25519 + HKDF-SHA256 + AES-256-GCM).
#
# Matches the scheme used by NHA's ABDM wrapper and Fidelius CLI (both BouncyCastle):
# - keys live on BouncyCastle's "curve25519" in short-Weierstrass form; public keys are uncompressed points
#   (0x04 || X || Y), private keys are big-endian integers (Java BigInteger.toByteArray());
# - shared secret = 32-byte big-endian X coordinate of d·Q;
# - xor = senderNonce XOR receiverNonce; HKDF salt = xor[:20]; AES-GCM IV = xor[-12:]; 128-bit tag appended.
# The HIP shares its public key X.509-encoded (explicit parameters), as the NHA wrapper does; both raw points and
# X.509 keys are accepted from the HIU. Verified against Fidelius CLI's published test vectors (tests/test_hip.py).

P = 2**255 - 19
MONT_A = 486662
SHIFT = MONT_A * pow(3, -1, P) % P  # Weierstrass x = Montgomery u + A/3
WEI_A = (3 - MONT_A * MONT_A) * pow(3, -1, P) % P
WEI_B = (2 * MONT_A**3 - 9 * MONT_A) * pow(27, -1, P) % P
N = 2**252 + 27742317777372353535851937790883648493
BASE_U = 9

# DER SubjectPublicKeyInfo header with explicit curve25519 (Weierstrass) domain parameters, as produced by
# BouncyCastle's ECPublicKey.getEncoded() for these keys; the 65-byte uncompressed point follows it.
X509_PREFIX = bytes.fromhex(
    "308201313081ea06072a8648ce3d02013081de020101302b06072a8648ce3d01010220"
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed3044"
    "04202aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144"
    "04207b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864"
    "0441042aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a"
    "20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9"
    "02201000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed020108034200")

CRYPTO_ALG, CURVE, PARAMETERS = "ECDH", "Curve25519", "Curve25519/32byte random key"


class CryptoError(ValueError):
    pass


def ladder(scalar: int, u: int) -> int:
    """Montgomery ladder (RFC 7748 arithmetic, without clamping, like BouncyCastle's plain d·Q)."""
    x2, z2, x3, z3, swap = 1, 0, u, 1, 0
    for t in reversed(range(255)):
        bit = (scalar >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3, z3 = (da + cb) ** 2 % P, u * (da - cb) ** 2 % P
        x2, z2 = aa * bb % P, e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return x2 * pow(z2, P - 2, P) % P


def sqrt_mod(value: int) -> int:
    """Square root modulo P (P = 5 mod 8)."""
    root = pow(value, (P + 3) // 8, P)
    if root * root % P != value % P:
        root = root * pow(2, (P - 1) // 4, P) % P
    if root * root % P != value % P:
        raise CryptoError("Not a point on the curve")
    return root


def point_from_u(u: int) -> bytes:
    x = (u + SHIFT) % P
    y = sqrt_mod((x**3 + WEI_A * x + WEI_B) % P)
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def u_from_public_key(key: bytes) -> int:
    """Accept a raw uncompressed point or an X.509 SubjectPublicKeyInfo for this curve."""
    if key.startswith(X509_PREFIX):
        key = key[len(X509_PREFIX):]
    if len(key) != 65 or key[0] != 4:
        raise CryptoError("Public key must be an uncompressed Curve25519 point or its X.509 encoding")
    x, y = int.from_bytes(key[1:33], "big"), int.from_bytes(key[33:], "big")
    if (y * y - (x**3 + WEI_A * x + WEI_B)) % P:
        raise CryptoError("Public key is not on Curve25519")
    return (x - SHIFT) % P


def generate_key_material() -> dict:
    """Ephemeral HIP key pair and nonce for one data transfer (never stored or logged)."""
    private = secrets.randbelow(N - 1) + 1
    public = point_from_u(ladder(private, BASE_U))
    return {"private": private, "public": public, "x509": X509_PREFIX + public, "nonce": secrets.token_bytes(32)}


def session_key(private: int, peer_public: bytes, own_nonce: bytes, peer_nonce: bytes, sender_first: bool):
    shared_u = ladder(private, u_from_public_key(peer_public))
    shared = ((shared_u + SHIFT) % P).to_bytes(32, "big")
    first, second = (own_nonce, peer_nonce) if sender_first else (peer_nonce, own_nonce)
    xor = bytes(b ^ second[i % len(second)] for i, b in enumerate(first))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=xor[:20], info=None).derive(shared)
    return AESGCM(key), xor[-12:]


def encrypt(plaintext: str, sender_private: int, sender_nonce: bytes, receiver_public: bytes, receiver_nonce: bytes) -> str:
    cipher, iv = session_key(sender_private, receiver_public, sender_nonce, receiver_nonce, sender_first=True)
    return base64.b64encode(cipher.encrypt(iv, plaintext.encode(), None)).decode()


def decrypt(ciphertext: str, receiver_private: int, receiver_nonce: bytes, sender_public: bytes, sender_nonce: bytes) -> str:
    cipher, iv = session_key(receiver_private, sender_public, receiver_nonce, sender_nonce, sender_first=False)
    return cipher.decrypt(iv, base64.b64decode(ciphertext), None).decode()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise CryptoError("Invalid base64 value in key material") from exc


# ====================================================================================================================
# ABDM gateway client (formerly app/hip/gateway.py)
# ====================================================================================================================
# ABDM gateway client: session token, request headers, outbound calls and callback authentication.
#
# Paths, headers and bodies follow NHA's ABDM sandbox documentation (Milestone 3 v2.5) and NHA's ABDM
# wrapper (application-v3.properties). In simulation mode the identical calls go to the simulator section below.

SESSIONS_PATH = "/gateway/v3/sessions"
CERTS_PATH = "/gateway/v3/certs"
BRIDGE_URL_PATH = "/gateway/v3/bridge/url"
GENERATE_LINK_TOKEN_PATH = "/v3/token/generate-token"
ADD_CARE_CONTEXTS_PATH = "/hip/v3/link/carecontext"
ON_DISCOVER_PATH = "/user-initiated-linking/v3/patient/care-context/on-discover"
ON_INIT_LINK_PATH = "/user-initiated-linking/v3/link/care-context/on-init"
ON_CONFIRM_LINK_PATH = "/user-initiated-linking/v3/link/care-context/on-confirm"
CONSENT_ON_NOTIFY_PATH = "/consent/v3/request/hip/on-notify"
HI_ON_REQUEST_PATH = "/data-flow/v3/health-information/hip/on-request"
HI_NOTIFY_PATH = "/data-flow/v3/health-information/notify"
# HIU (NHA sandbox documentation, Milestone 3 v2.5)
CONSENT_INIT_PATH = "/consent/v3/request/init"
CONSENT_STATUS_PATH = "/consent/v3/request/status"
CONSENT_HIU_ON_NOTIFY_PATH = "/consent/v3/request/hiu/on-notify"
CONSENT_FETCH_PATH = "/consent/v3/fetch"
HI_REQUEST_PATH = "/data-flow/v3/health-information/request"

_lock = threading.Lock()
_session = {"token": None, "expires": 0.0}
_jwks = {"keys": None, "fetched": 0.0}


class GatewayError(Exception):
    """An ABDM call failed; `message` is safe to show to staff."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.message, self.status = message, status


class CallbackAuthError(Exception):
    pass


def simulation() -> bool:
    return settings.abdm_mode == "simulation"


def hospital_hip_id(hospital=None) -> str | None:
    """The HIP service ID of a hospital: its own (Hospital.abdm_hip_id), else the bridge-wide default."""
    if hospital is not None and hospital.abdm_hip_id:
        return hospital.abdm_hip_id
    return settings.abdm_hip_id or ("SIM_HIP_001" if simulation() else None)


def hospital_hiu_id(hospital=None) -> str | None:
    if hospital is not None and hospital.abdm_hiu_id:
        return hospital.abdm_hiu_id
    return settings.abdm_hiu_id or ("SIM_HIU_LOCAL" if simulation() else None)


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def http_client() -> httpx.Client:
    """Separate so tests can substitute a mock transport."""
    return httpx.Client(timeout=settings.abdm_timeout_seconds)


def base_headers(request_id: str | None = None) -> dict:
    return {"REQUEST-ID": request_id or str(uuid.uuid4()), "TIMESTAMP": timestamp(), "X-CM-ID": settings.abdm_cm_id,
            "Content-Type": "application/json"}


def reset_gateway() -> None:
    _session.update(token=None, expires=0.0)
    _jwks.update(keys=None, fetched=0.0)


def session_token() -> str:
    if simulation():
        return issue_token()
    with _lock:
        if _session["token"] and _session["expires"] > time.time():
            return _session["token"]
        if not (settings.abdm_client_id and settings.abdm_client_secret):
            raise GatewayError("ABDM_CLIENT_ID and ABDM_CLIENT_SECRET are not configured")
        body = {"clientId": settings.abdm_client_id, "clientSecret": settings.abdm_client_secret,
                "grantType": "client_credentials"}
        try:
            with http_client() as client:
                r = client.post(settings.abdm_gateway_url + SESSIONS_PATH, json=body, headers=base_headers())
        except httpx.HTTPError as exc:
            raise GatewayError(f"ABDM gateway is unreachable ({type(exc).__name__})") from None
        if r.status_code not in (200, 202) or "accessToken" not in (data := r.json() or {}):
            raise GatewayError(f"ABDM rejected the client credentials (HTTP {r.status_code})", r.status_code)
        _session.update(token=data["accessToken"], expires=time.time() + max(int(data.get("expiresIn", 1200)) - 60, 30))
        return _session["token"]


def call(path: str, body: dict | None, headers: dict | None = None, method: str = "POST") -> tuple[int, dict | None, str]:
    """Call a gateway API. Returns (HTTP status, JSON body or None, REQUEST-ID used)."""
    request_headers = {**base_headers(), **(headers or {})}
    for attempt in (1, 2):
        request_headers["Authorization"] = f"Bearer {session_token()}"
        if simulation():
            status, data = receive(method, path, body, request_headers)
            return status, data, request_headers["REQUEST-ID"]
        try:
            with http_client() as client:
                r = client.request(method, settings.abdm_gateway_url + path, json=body, headers=request_headers)
        except httpx.HTTPError as exc:
            raise GatewayError(f"ABDM gateway is unreachable ({type(exc).__name__})") from None
        if r.status_code == 401 and attempt == 1:
            _session.update(token=None)  # token expired early: renew once
            continue
        try:
            data = r.json() if r.content else None
        except ValueError:
            data = None
        return r.status_code, data, request_headers["REQUEST-ID"]
    return r.status_code, None, request_headers["REQUEST-ID"]


def push(url: str, body: dict) -> int:
    """Data push to the HIU's dataPushUrl (sent directly to the HIU, as in NHA's wrapper)."""
    if simulation():
        return receive_push(url, body)
    try:
        with http_client() as client:
            return client.post(url, json=body, headers={"Content-Type": "application/json"}).status_code
    except httpx.HTTPError:
        return 0


def jwks(refresh: bool = False) -> dict:
    if simulation():
        return sim_jwks()
    with _lock:
        if _jwks["keys"] and not refresh and time.time() - _jwks["fetched"] < 3600:
            return _jwks["keys"]
        try:
            with http_client() as client:
                r = client.get(settings.abdm_gateway_url + CERTS_PATH, headers=base_headers())
        except httpx.HTTPError as exc:
            raise CallbackAuthError(f"Cannot fetch ABDM signing keys ({type(exc).__name__})") from None
        if r.status_code not in (200, 202):
            raise CallbackAuthError(f"Cannot fetch ABDM signing keys (HTTP {r.status_code})")
        _jwks.update(keys=r.json(), fetched=time.time())
        return _jwks["keys"]


def verify_callback(authorization: str | None) -> dict:
    """Check the gateway JWT on a callback against ABDM's published keys (/gateway/v3/certs)."""
    if not settings.abdm_verify_callbacks:
        return {}
    if not authorization or not authorization.lower().startswith("bearer "):
        raise CallbackAuthError("Missing gateway token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        kid = jwt.get_unverified_header(token).get("kid")
        keys = jwks()
        match = next((k for k in keys.get("keys", []) if k.get("kid") == kid), None)
        if match is None:  # keys may have rotated
            match = next((k for k in jwks(refresh=True).get("keys", []) if k.get("kid") == kid), None)
        if match is None:
            raise CallbackAuthError("Gateway token signed with an unknown key")
        return jwt.decode(token, jwt.PyJWK(match).key, algorithms=["RS256", "RS512"], options={"verify_aud": False})
    except jwt.PyJWTError as exc:
        raise CallbackAuthError(f"Invalid gateway token: {exc}") from None


# ====================================================================================================================
# HIP workflows (formerly app/hip/service.py)
# ====================================================================================================================
# HIP workflows: identity linking, care contexts, discovery, user-initiated linking, consent and data transfer.
#
# Message shapes follow NHA's ABDM V3 contracts (sandbox documentation + NHA ABDM wrapper). Inbound callbacks
# are processed by handle_inbound(); every exchange is recorded as a HipTransaction with redacted details.
# Health records are never decrypted, logged or returned here: only consented, HIP-eligible FHIR records are
# encrypted and pushed to the HIU.

HI_TYPES = {"OPConsultRecord": "OPConsultation", "PrescriptionRecord": "Prescription",
            "DiagnosticReportRecord": "DiagnosticReport", "DischargeSummaryRecord": "DischargeSummary",
            "ImmunizationRecord": "ImmunizationRecord", "WellnessRecord": "WellnessRecord",
            "HealthDocumentRecord": "HealthDocumentRecord"}
HI_LABELS = {"OPConsultation": "OP consultation", "Prescription": "Prescription", "DiagnosticReport": "Lab report",
             "DischargeSummary": "Discharge summary", "ImmunizationRecord": "Immunization",
             "WellnessRecord": "Wellness record", "HealthDocumentRecord": "Health document"}
SECRET_KEYS = {"linktoken", "token", "keyvalue", "content", "nonce", "otp", "accesstoken", "signature", "x-link-token",
               "authorization", "clientsecret"}
PATIENT_NOT_FOUND = ("ABDM-1010", "Patient not found")  # codes as used by NHA's ABDM wrapper
INCORRECT_OTP = ("ABDM-1035", "Incorrect OTP")
GENERIC_ERROR = "1000"
PUSH_PAGE_SIZE = 7  # entries per data-push page, as in NHA's wrapper


class HipError(Exception):
    """A request the HIP refuses; message is shown to staff."""


# ---------- helpers ----------

def redact(node):
    if isinstance(node, dict):
        return {k: "***" if k.lower() in SECRET_KEYS else redact(v) for k, v in node.items()}
    if isinstance(node, list):
        return [redact(v) for v in node]
    return node


def record(db: Session, hospital_id: int, kind: str, direction: str, status: str, message: str, **fields) -> HipTransaction:
    tx = HipTransaction(hospital_id=hospital_id, mode=settings.abdm_mode, kind=kind, direction=direction,
                        status=status, message=message[:500], **{k: v for k, v in fields.items() if k != "details"},
                        details=redact(fields.get("details")))
    db.add(tx)
    return tx


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed


def hospital_for(db: Session, facility_id: str | None, role: str = "hip") -> Hospital | None:
    """The hospital an ABDM message is addressed to (X-HIP-ID or X-HIU-ID), or None when no hospital uses the ID.

    A hospital with its own ID (Hospital.abdm_hip_id / abdm_hiu_id) answers only to that ID. The bridge-wide
    default (ABDM_HIP_ID / ABDM_HIU_ID, or the simulation default) belongs to the hospital without its own ID
    whose HFR ID equals it, else to the only hospital without its own ID."""
    column = Hospital.abdm_hip_id if role == "hip" else Hospital.abdm_hiu_id
    if facility_id:
        hospital = db.scalar(select(Hospital).where(column == facility_id))
        if hospital is not None:
            return hospital if hospital.is_active else None  # a deactivated hospital takes no ABDM traffic
    default = hospital_hip_id() if role == "hip" else hospital_hiu_id()
    if facility_id and facility_id != default:
        return None
    unassigned = db.scalars(select(Hospital).where(column.is_(None), Hospital.is_active.is_(True))
                            .order_by(Hospital.id)).all()
    by_hfr = [h for h in unassigned if default and h.hfr_id == default]
    if len(by_hfr) == 1:
        return by_hfr[0]
    return unassigned[0] if len(unassigned) == 1 else None


def hip_hospital(db: Session, facility_id: str | None = None) -> Hospital:
    """The hospital addressed by an X-HIP-ID (default: the bridge-wide HIP ID)."""
    hospital = hospital_for(db, facility_id, "hip")
    if hospital is None:
        raise HipError(f"No hospital uses HIP ID {facility_id or hospital_hip_id()}: set each hospital's ABDM HIP ID "
                       "(Hospital profile) so callbacks can be routed")
    return hospital


def otp_hash(otp: str, link_reference: str) -> str:
    return hmac.new(settings.jwt_secret.encode(), f"{link_reference}:{otp}".encode(), hashlib.sha256).hexdigest()


def masked(mobile: str) -> str:
    return "X" * (len(mobile) - 4) + mobile[-4:]


def check_accepted(db: Session, tx: HipTransaction, status: int, data: dict | None, success: str) -> bool:
    tx.http_status = status
    if 200 <= status < 300:
        tx.message = success
        return True
    error = (data or {}).get("error") or {}
    tx.status, tx.message = "failed", f"ABDM refused the request (HTTP {status}): {error.get('message', 'no details')}"
    return False


# ---------- care contexts ----------

def record_date(record: FhirRecord) -> datetime:
    composition = record.bundle["entry"][0]["resource"]
    return parse_time(composition.get("date")) or record.generated_at


def sync_care_contexts(db: Session, patient: Patient) -> list[CareContext]:
    """One care context per HIP-eligible (validated) FHIR record of the patient."""
    existing = {c.fhir_record_id for c in db.scalars(select(CareContext).where(CareContext.patient_id == patient.id))}
    hospital = db.get(Hospital, patient.hospital_id)
    for rec in db.scalars(select(FhirRecord).where(FhirRecord.patient_id == patient.id)):
        if rec.id in existing or not rec.hip_eligible:
            continue
        hi_type, when = HI_TYPES[rec.record_type], record_date(rec)
        db.add(CareContext(hospital_id=patient.hospital_id, patient_id=patient.id, fhir_record_id=rec.id,
                           reference=f"{hospital.code}-{rec.source_type.upper().replace('_', '-')}-{rec.source_id}",
                           display=f"{HI_LABELS[hi_type]} · {when:%d %b %Y}", hi_type=hi_type, record_date=when))
    db.flush()
    return db.scalars(select(CareContext).where(CareContext.patient_id == patient.id).order_by(CareContext.id)).all()


def grouped(patient: Patient, contexts: list[CareContext]) -> list[dict]:
    """Care contexts grouped by HI type, the shape used by on-discover, on-confirm and add care contexts."""
    groups: dict[str, list[CareContext]] = {}
    for c in contexts:
        groups.setdefault(c.hi_type, []).append(c)
    return [{"referenceNumber": patient.patient_code, "display": patient.full_name, "hiType": hi_type,
             "count": len(items), "careContexts": [{"referenceNumber": c.reference, "display": c.display} for c in items]}
            for hi_type, items in groups.items()]


# ---------- HIP-initiated linking (staff) ----------

def generate_link_token(db: Session, user: User, patient: Patient) -> HipTransaction:
    """Ask ABDM to confirm the patient's ABHA address against their demographics and issue a link token."""
    if not patient.abha_address:
        raise HipError("Enter the patient's ABHA address first")
    if patient.gender not in ("M", "F", "O"):
        raise HipError("ABDM linking needs gender M, F or O")
    hospital = db.get(Hospital, patient.hospital_id)
    body = {"abhaAddress": patient.abha_address, "name": patient.full_name, "gender": patient.gender,
            "yearOfBirth": patient.year_of_birth}
    request_id = str(uuid.uuid4())
    link = db.scalar(select(HipPatientLink).where(HipPatientLink.patient_id == patient.id)) or \
        HipPatientLink(hospital_id=patient.hospital_id, patient_id=patient.id)
    link.abha_address, link.status, link.request_id, link.link_token = patient.abha_address, "pending", request_id, None
    link.message, link.mode = "Waiting for ABDM to verify the ABHA address", settings.abdm_mode
    db.add(link)
    tx = record(db, patient.hospital_id, "generate_link_token", "outbound", "pending", "Sending to ABDM",
                request_id=request_id, patient_id=patient.id, details=body)
    audit(db, user, "hip.link_token_request", "patient", patient.id)
    db.commit()
    status, data, _ = call(GENERATE_LINK_TOKEN_PATH, body,
                           {"REQUEST-ID": request_id, "X-HIP-ID": hospital_hip_id(hospital)})
    if not check_accepted(db, tx, status, data, "Accepted by ABDM; waiting for the link token callback"):
        link.status, link.message = "failed", tx.message
    db.commit()
    return tx


def on_generate_token(db: Session, body: dict) -> str:
    request_id = (body.get("response") or {}).get("requestId")
    link = db.scalar(select(HipPatientLink).where(HipPatientLink.request_id == request_id))
    if link is None:
        return "Unknown link token response"
    patient, error = link.patient, body.get("error")
    if error or not body.get("linkToken"):
        link.status = "failed"
        link.message = f"ABDM could not verify {link.abha_address}: {(error or {}).get('message', 'no link token')}"
        return link.message
    if (body.get("abhaAddress") or "").lower() != link.abha_address.lower():
        link.status, link.message = "failed", "ABDM answered for a different ABHA address; nothing was linked"
        return link.message
    link.status, link.link_token = "verified", body["linkToken"]
    link.message = "ABHA address verified by ABDM (demographic match); link token received"
    claims = jwt.decode(body["linkToken"], options={"verify_signature": False})  # token itself is opaque to the HIP
    abha_number = re.sub(r"\D", "", claims.get("abhaNumber") or "")
    if patient.abha_number and abha_number and patient.abha_number != abha_number:
        link.message += "; the ABHA number on file differs from ABDM's and was not marked verified"
    else:
        patient.abha_number = patient.abha_number or abha_number or None
        patient.abha_verified, patient.abha_verified_at = True, utcnow()
        patient.abha_verification_method = "abdm_link_token"
    return link.message


def add_care_contexts(db: Session, user: User, patient: Patient, contexts: list[CareContext]) -> HipTransaction:
    """Add care contexts to the patient's ABHA address with the link token (HIP-initiated linking)."""
    link = db.scalar(select(HipPatientLink).where(HipPatientLink.patient_id == patient.id))
    if link is None or link.status != "verified" or not link.link_token:
        raise HipError("Verify the patient's ABHA address with ABDM (link token) first")
    if not contexts:
        raise HipError("No care contexts to link")
    hospital = db.get(Hospital, patient.hospital_id)
    claims = jwt.decode(link.link_token, options={"verify_signature": False})
    body = {"abhaNumber": claims.get("abhaNumber"), "abhaAddress": link.abha_address, "patient": grouped(patient, contexts)}
    request_id = str(uuid.uuid4())
    for c in contexts:
        c.link_status, c.request_id, c.message = "linking", request_id, "Waiting for ABDM"
    tx = record(db, patient.hospital_id, "add_care_contexts", "outbound", "pending", "Sending to ABDM",
                request_id=request_id, patient_id=patient.id, details={"careContexts": [c.reference for c in contexts]})
    audit(db, user, "hip.care_context_link", "patient", patient.id, {"care_contexts": [c.reference for c in contexts]})
    db.commit()
    status, data, _ = call(ADD_CARE_CONTEXTS_PATH, body,
                           {"REQUEST-ID": request_id, "X-HIP-ID": hospital_hip_id(hospital), "X-LINK-TOKEN": link.link_token})
    if not check_accepted(db, tx, status, data, "Accepted by ABDM; waiting for confirmation"):
        for c in contexts:
            c.link_status, c.message = "failed", tx.message
    db.commit()
    return tx


def on_add_care_contexts(db: Session, body: dict) -> str:
    request_id = (body.get("response") or {}).get("requestId")
    contexts = db.scalars(select(CareContext).where(CareContext.request_id == request_id)).all()
    if not contexts:
        return "Unknown add-care-context response"
    error = body.get("error")
    for c in contexts:
        if error:
            c.link_status, c.message = "failed", f"ABDM did not link: {error.get('message', 'unknown error')}"
        else:
            c.link_status, c.linked_abha_address, c.linked_at = "linked", body.get("abhaAddress"), utcnow()
            c.link_method, c.message = "hip_initiated", body.get("status") or "Linked"
    return contexts[0].message


# ---------- discovery and user-initiated linking (inbound) ----------

def match_patient(db: Session, hospital_id: int, p: dict) -> tuple[Patient | None, str | None]:
    """Find exactly one patient: by ABHA address, else by verified mobile or MR number, always with demographics."""
    gender, name, yob = (p.get("gender") or "").upper()[:1], p.get("name") or "", int(p.get("yearOfBirth") or 0)

    def demographics_match(candidate: Patient) -> bool:
        return (candidate.gender == gender and abs(candidate.year_of_birth - yob) <= 1
                and name_similarity(candidate.full_name, name) >= 0.85)

    patients = select(Patient).where(Patient.hospital_id == hospital_id)
    address = (p.get("id") or "").lower()
    by_abha = [c for c in db.scalars(patients.where(Patient.abha_address == address)) if demographics_match(c)]
    if len(by_abha) == 1:
        return by_abha[0], "ABHA_ADDRESS"
    for kind in ("MOBILE", "MR"):
        values = {i.get("value") for i in (p.get("verifiedIdentifiers") or []) + (p.get("unverifiedIdentifiers") or [])
                  if i.get("type") == kind and i.get("value")}
        for value in values:
            column = Patient.mobile if kind == "MOBILE" else Patient.patient_code
            key = re.sub(r"\D", "", value)[-10:] if kind == "MOBILE" else value
            found = [c for c in db.scalars(patients.where(column == key)) if demographics_match(c)]
            if kind == "MOBILE" and not any(i.get("type") == "MOBILE" for i in p.get("verifiedIdentifiers") or []):
                found = []  # an unverified mobile is never enough
            if len(found) == 1:  # ambiguous matches are never returned
                return found[0], kind
    return None, None


def discover(db: Session, hospital: Hospital, headers: dict, body: dict) -> HipTransaction:
    patient_info, transaction_id = body.get("patient") or {}, body.get("transactionId")
    patient, matched_by = match_patient(db, hospital.id, patient_info)
    response = {"transactionId": transaction_id, "response": {"requestId": headers.get("request-id")}}
    contexts = [c for c in sync_care_contexts(db, patient) if c.link_status != "linked"] if patient else []
    if patient is None:
        response["error"] = dict(zip(("code", "message"), PATIENT_NOT_FOUND))
        message = "No single matching patient (nothing revealed)"
    elif not contexts:
        response["error"] = {"code": GENERIC_ERROR, "message": "Care Contexts not found for patient"}
        message = "Patient matched but has no unlinked shareable records"
    else:
        response.update(patient=grouped(patient, contexts), matchedBy=[matched_by])
        message = f"Patient matched by {matched_by}; {len(contexts)} care context(s) offered"
    tx = record(db, hospital.id, "discover", "inbound", "pending", message, transaction_id=transaction_id,
                request_id=headers.get("request-id"), patient_id=patient.id if patient else None,
                details={"matchedBy": matched_by, "careContexts": [c.reference for c in contexts]})
    db.commit()
    status, data, _ = call(ON_DISCOVER_PATH, response, {"X-HIP-ID": hospital_hip_id(hospital)})
    if check_accepted(db, tx, status, data, message):
        tx.status = "success"  # a "no match" answer is still a completed discovery
    return tx


def link_init(db: Session, hospital: Hospital, headers: dict, body: dict) -> HipTransaction:
    transaction_id, address = body.get("transactionId"), (body.get("abhaAddress") or "").lower()
    groups = body.get("patient") or []
    patient_code = groups[0].get("referenceNumber") if groups else None
    refs = [c.get("referenceNumber") for g in groups for c in g.get("careContexts") or []]
    patient = db.scalar(select(Patient).where(Patient.hospital_id == hospital.id, Patient.patient_code == patient_code))
    contexts = db.scalars(select(CareContext).where(CareContext.hospital_id == hospital.id,
                                                    CareContext.reference.in_(refs))).all() if patient else []
    response = {"transactionId": transaction_id, "response": {"requestId": headers.get("request-id")}}
    problem = None
    if patient is None:
        problem = PATIENT_NOT_FOUND
    elif not refs or len(contexts) != len(set(refs)) or any(c.patient_id != patient.id or c.link_status == "linked"
                                                             for c in contexts):
        problem = (GENERIC_ERROR, "Care contexts do not belong to this patient or are already linked")
    elif patient.abha_verified and patient.abha_address and patient.abha_address != address:
        problem = (GENERIC_ERROR, "This patient is already linked to a different ABHA address")
    elif not (simulation() or settings.abdm_otp_test_display):
        problem = (GENERIC_ERROR, "The HIP cannot deliver the OTP: no SMS gateway is configured")
    if problem:
        response["error"] = dict(zip(("code", "message"), problem))
        tx = record(db, hospital.id, "link_init", "inbound", "failed", f"Link request refused: {problem[1]}",
                    transaction_id=transaction_id, patient_id=patient.id if patient else None)
    else:
        otp, reference = f"{secrets.randbelow(10**6):06d}", str(uuid.uuid4())
        expires = utcnow() + timedelta(minutes=10)
        db.add(HipLinkRequest(hospital_id=hospital.id, patient_id=patient.id, transaction_id=transaction_id,
                              link_reference=reference, abha_address=address, care_context_refs=refs,
                              otp_hash=otp_hash(otp, reference), otp_expires_at=expires, mode=settings.abdm_mode,
                              test_otp=otp))  # delivered to the patient below; cleared once used
        if simulation():
            deliver_sms(patient.mobile, otp)
        response["link"] = {"referenceNumber": reference, "authenticationType": "MEDIATE",
                            "meta": {"communicationMedium": "MOBILE", "communicationHint": masked(patient.mobile),
                                     "communicationExpiry": expires.isoformat(timespec="milliseconds") + "Z"}}
        tx = record(db, hospital.id, "link_init", "inbound", "pending",
                    f"OTP sent to the patient's registered mobile {masked(patient.mobile)}",
                    transaction_id=transaction_id, patient_id=patient.id, details={"careContexts": refs})
    db.commit()
    status, data, _ = call(ON_INIT_LINK_PATH, response, {"X-HIP-ID": hospital_hip_id(hospital)})
    if check_accepted(db, tx, status, data, tx.message) and not problem:
        tx.status = "success"
    return tx


def link_confirm(db: Session, hospital: Hospital, headers: dict, body: dict) -> HipTransaction:
    confirmation = body.get("confirmation") or {}
    request = db.scalar(select(HipLinkRequest).where(HipLinkRequest.hospital_id == hospital.id,
                                                     HipLinkRequest.link_reference == confirmation.get("linkRefNumber")))
    response = {"response": {"requestId": headers.get("request-id")}}
    problem = None
    if request is None or request.status != "otp_sent":
        problem = (GENERIC_ERROR, "Unknown or completed link request")
    elif request.otp_expires_at < utcnow() or request.attempts >= 3:
        request.status, problem = "failed", (GENERIC_ERROR, "OTP expired or too many attempts")
    elif not hmac.compare_digest(request.otp_hash, otp_hash(str(confirmation.get("token") or ""), request.link_reference)):
        request.attempts += 1
        problem = INCORRECT_OTP
    if problem:
        response["error"] = dict(zip(("code", "message"), problem))
        tx = record(db, hospital.id, "link_confirm", "inbound", "failed", f"Link not confirmed: {problem[1]}",
                    patient_id=request.patient_id if request else None)
    else:
        patient = db.get(Patient, request.patient_id)
        contexts = db.scalars(select(CareContext).where(CareContext.hospital_id == hospital.id,
                                                        CareContext.reference.in_(request.care_context_refs))).all()
        for c in contexts:
            c.link_status, c.linked_abha_address, c.linked_at = "linked", request.abha_address, utcnow()
            c.link_method, c.message = "patient_initiated", "Linked by the patient from their ABHA app"
        request.status, request.test_otp = "linked", None
        if not patient.abha_address:
            patient.abha_address = request.abha_address
        if patient.abha_address == request.abha_address:  # the patient authenticated with ABDM and proved the mobile
            patient.abha_verified, patient.abha_verified_at = True, utcnow()
            patient.abha_verification_method = "abdm_patient_linking"
        response["patient"] = grouped(patient, contexts)
        tx = record(db, hospital.id, "link_confirm", "inbound", "pending",
                    f"{len(contexts)} care context(s) linked to {request.abha_address}", patient_id=patient.id,
                    details={"careContexts": request.care_context_refs})
    db.commit()
    status, data, _ = call(ON_CONFIRM_LINK_PATH, response, {"X-HIP-ID": hospital_hip_id(hospital)})
    if check_accepted(db, tx, status, data, tx.message) and not problem:
        tx.status = "success"
    return tx


# ---------- consent ----------

def consent_problem(db: Session, hospital: Hospital, detail: dict) -> tuple[str | None, Patient | None]:
    """Checks a GRANTED consent artefact against this HIP's records. Returns (problem, patient)."""
    if (detail.get("hip") or {}).get("id") != hospital_hip_id(hospital):
        return "Consent is for a different HIP", None
    address = ((detail.get("patient") or {}).get("id") or "").lower()
    refs = detail.get("careContexts") or []
    contexts = db.scalars(select(CareContext).where(
        CareContext.hospital_id == hospital.id,
        CareContext.reference.in_([r.get("careContextReference") for r in refs]))).all()
    if not refs or len(contexts) != len(refs):
        return "Consent lists care contexts this HIP does not hold", None
    if any(c.link_status != "linked" or (c.linked_abha_address or "").lower() != address for c in contexts):
        return "Consent lists care contexts not linked to this ABHA address", None
    patient = db.get(Patient, contexts[0].patient_id)
    if any(c.patient_id != patient.id for c in contexts) or any(r.get("patientReference") != patient.patient_code for r in refs):
        return "Consent mixes records of different patients", None
    permission = detail.get("permission") or {}
    try:
        erase_at = parse_time(permission.get("dataEraseAt"))
        start, end = (parse_time((permission.get("dateRange") or {}).get(k)) for k in ("from", "to"))
    except ValueError:
        return "Consent permission dates are invalid", patient
    if not (erase_at and start and end) or start > end:
        return "Consent permission is missing its date range or erase date", patient
    if erase_at < utcnow():
        return "Consent has already expired (dataEraseAt passed)", patient
    if not set(detail.get("hiTypes") or []) <= set(HI_TYPES.values()) or not detail.get("hiTypes"):
        return "Consent contains unsupported health information types", patient
    return None, patient


def consent_notify(db: Session, hospital: Hospital, headers: dict, body: dict) -> HipTransaction:
    notification = body.get("notification") or {}
    status, consent_id = (notification.get("status") or "").upper(), notification.get("consentId")
    detail = notification.get("consentDetail") or {}
    consent = db.scalar(select(HipConsent).where(HipConsent.hospital_id == hospital.id, HipConsent.consent_id == consent_id))
    response = {"response": {"requestId": headers.get("request-id")}}
    if status == "GRANTED":
        problem, patient = consent_problem(db, hospital, detail)
        permission = detail.get("permission") or {}
        consent = consent or HipConsent(hospital_id=hospital.id, consent_id=consent_id, mode=settings.abdm_mode)
        consent.patient_id, consent.abha_address = patient.id if patient else None, (detail.get("patient") or {}).get("id")
        consent.hiu_id, consent.purpose = (detail.get("hiu") or {}).get("id"), (detail.get("purpose") or {}).get("code")
        consent.hi_types, consent.care_contexts = detail.get("hiTypes") or [], detail.get("careContexts") or []
        if not problem:
            consent.date_from = parse_time(permission["dateRange"]["from"])
            consent.date_to = parse_time(permission["dateRange"]["to"])
            consent.data_erase_at = parse_time(permission["dataEraseAt"])
        consent.status, consent.status_reason = ("REJECTED", problem) if problem else ("GRANTED", None)
        consent.artefact = detail
        db.add(consent)
        if problem:
            response.update(error={"code": GENERIC_ERROR, "message": problem},
                            acknowledgement={"status": "FAILURE", "consentId": consent_id})
        else:
            response["acknowledgement"] = {"status": "OK", "consentId": consent_id}
        message = f"Consent refused: {problem}" if problem else f"Consent granted to {consent.hiu_id} for {', '.join(consent.hi_types)}"
    else:  # REVOKED, EXPIRED, DENIED: stop sharing immediately
        if consent:
            consent.status, consent.status_reason = status or "REVOKED", "Notified by the consent manager"
        response["acknowledgement"] = {"status": "OK", "consentId": consent_id}
        problem, message = None, f"Consent {consent_id} is now {status or 'REVOKED'}"
    tx = record(db, hospital.id, "consent_notify", "inbound", "failed" if problem else "pending", message,
                consent_id=consent_id, patient_id=consent.patient_id if consent else None,
                details={"status": status, "hiTypes": detail.get("hiTypes"), "hiu": (detail.get("hiu") or {}).get("id")})
    db.commit()
    http_status, data, _ = call(CONSENT_ON_NOTIFY_PATH, response, {"X-HIP-ID": hospital_hip_id(hospital)})
    if check_accepted(db, tx, http_status, data, message) and not problem:
        tx.status = "success"
    return tx


# ---------- health information request and transfer ----------

def health_information(db: Session, hospital: Hospital, headers: dict, body: dict) -> HipTransaction:
    transaction_id, hi_request = body.get("transactionId"), body.get("hiRequest") or {}
    consent_id = (hi_request.get("consent") or {}).get("id")
    consent = db.scalar(select(HipConsent).where(HipConsent.hospital_id == hospital.id, HipConsent.consent_id == consent_id))
    key_material = hi_request.get("keyMaterial") or {}
    problem = None
    try:
        start, end = (parse_time((hi_request.get("dateRange") or {}).get(k)) for k in ("from", "to"))
    except ValueError:
        start = end = None
    if consent is None or consent.status != "GRANTED":
        problem = "Consent not found or not active (granted)"
    elif consent.data_erase_at and consent.data_erase_at < utcnow():
        problem = "Consent EXPIRED: exceeded dataEraseAt"
    elif not (start and end) or start < consent.date_from or end > consent.date_to or start > end:
        problem = "Requested date range is outside the consented range"
    elif key_material.get("cryptoAlg") != CRYPTO_ALG or (key_material.get("curve") or "").lower() != CURVE.lower():
        problem = "Unsupported key material (expected ECDH on Curve25519)"
    elif not re.match(r"^https://" if not simulation() else r"^(https|sim)://", hi_request.get("dataPushUrl") or ""):
        problem = "dataPushUrl must be an https URL"
    else:
        try:
            receiver_key = unb64(key_material["dhPublicKey"]["keyValue"])
            receiver_nonce = unb64(key_material["nonce"])
            u_from_public_key(receiver_key)
            if len(receiver_nonce) != 32:
                raise CryptoError("nonce must be 32 bytes")
        except (KeyError, TypeError, CryptoError) as exc:
            problem = f"Invalid key material: {exc}"
    on_request = {"response": {"requestId": headers.get("request-id")}}
    if problem:
        on_request["error"] = {"code": GENERIC_ERROR, "message": problem}
    else:
        on_request["hiRequest"] = {"transactionId": transaction_id, "sessionStatus": "ACKNOWLEDGED"}
    tx = record(db, hospital.id, "health_information", "inbound", "failed" if problem else "pending",
                f"Request refused: {problem}" if problem else "Request acknowledged; preparing records",
                transaction_id=transaction_id, consent_id=consent_id, patient_id=consent.patient_id if consent else None,
                details={"dateRange": hi_request.get("dateRange"), "hiu": consent.hiu_id if consent else None})
    db.commit()
    status, data, _ = call(HI_ON_REQUEST_PATH, on_request, {"X-HIP-ID": hospital_hip_id(hospital)})
    check_accepted(db, tx, status, data, tx.message)
    db.commit()  # release SQLite's write lock: the receiving HIU may be another hospital in this database
    if problem or tx.status == "failed":
        return tx

    # Only care contexts in the consent, of consented HI types, validated (HIP-eligible) and dated inside both ranges.
    refs = [r["careContextReference"] for r in consent.care_contexts]
    contexts = db.scalars(select(CareContext).where(CareContext.hospital_id == hospital.id,
                                                    CareContext.reference.in_(refs))).all()
    own = generate_key_material()
    entries, statuses = [], []
    for c in contexts:
        reason = None
        if c.hi_type not in consent.hi_types:
            reason = "HI type not covered by the consent"
        elif not (start <= c.record_date <= end):
            reason = "Record date is outside the requested date range"
        elif not c.fhir_record.hip_eligible:
            reason = "Record is no longer validated for sharing"
        if reason:
            statuses.append({"careContextReference": c.reference, "hiStatus": "ERRORED", "description": reason})
            continue
        content = json.dumps(c.fhir_record.bundle, separators=(",", ":"))
        entries.append({"content": encrypt(content, own["private"], own["nonce"], receiver_key, receiver_nonce),
                        "media": "application/fhir+json",
                        "checksum": hashlib.md5(content.encode()).hexdigest(),  # MD5 of the FHIR content
                        "careContextReference": c.reference})
        statuses.append({"careContextReference": c.reference, "hiStatus": "DELIVERED", "description": "Done"})
    key_out = {"cryptoAlg": CRYPTO_ALG, "curve": CURVE,
               "dhPublicKey": {"expiry": key_material["dhPublicKey"].get("expiry"),
                               "parameters": key_material["dhPublicKey"].get("parameters") or PARAMETERS,
                               "keyValue": b64(own["x509"])},
               "nonce": b64(own["nonce"])}
    pages = [entries[i:i + PUSH_PAGE_SIZE] for i in range(0, len(entries), PUSH_PAGE_SIZE)] or [[]]
    pushed_ok = True
    for number, page in enumerate(pages):
        if not entries:
            break
        push_status = push(hi_request["dataPushUrl"], {"pageNumber": number, "pageCount": len(pages),
                                                       "transactionId": transaction_id, "entries": page,
                                                       "keyMaterial": key_out})
        pushed_ok = pushed_ok and 200 <= push_status < 300
    if not pushed_ok:
        statuses = [{**s, "hiStatus": "ERRORED", "description": "Data push to the HIU failed"}
                    if s["hiStatus"] == "DELIVERED" else s for s in statuses]
    delivered = sum(s["hiStatus"] == "DELIVERED" for s in statuses)
    session_status = "TRANSFERRED" if delivered and pushed_ok else "FAILED"
    notify = {"notification": {
        "consentId": consent_id, "transactionId": transaction_id, "doneAt": timestamp(),
        "notifier": {"type": "HIP", "id": hospital_hip_id(hospital)},
        "statusNotification": {"sessionStatus": session_status, "hipId": hospital_hip_id(hospital), "statusResponses": statuses}}}
    status, data, _ = call(HI_NOTIFY_PATH, notify, {"X-HIP-ID": hospital_hip_id(hospital)})
    tx.details = {**(tx.details or {}), "statusResponses": statuses, "pages": len(pages) if entries else 0}
    tx.status = "success" if session_status == "TRANSFERRED" else "failed"
    tx.message = (f"{delivered} of {len(statuses)} record(s) encrypted and sent to {consent.hiu_id}"
                  if delivered else "No records could be shared for this request")
    if not 200 <= status < 300:
        tx.message += f"; status notification refused by ABDM (HTTP {status})"
    audit(db, None, "hip.data_transfer", "consent", consent_id,
          {"transaction_id": transaction_id, "delivered": delivered, "hiu": consent.hiu_id}, hospital_id=hospital.id)
    db.commit()
    return tx


# ---------- inbound dispatch ----------

INBOUND = {"discover": discover, "link_init": link_init, "link_confirm": link_confirm,
           "consent_notify": consent_notify, "health_information": health_information}
CALLBACKS = {"on_generate_token": on_generate_token, "on_add_care_contexts": on_add_care_contexts}


def handle_inbound(kind: str, headers: dict, body: dict) -> HipTransaction | None:
    """Process one authenticated ABDM callback (run after the 202 acknowledgement)."""
    headers = {k.lower(): v for k, v in headers.items()}
    with SessionLocal() as db:
        try:
            hospital = hip_hospital(db, headers.get("x-hip-id"))
            if kind in CALLBACKS:
                message = CALLBACKS[kind](db, body)
                tx = record(db, hospital.id, kind, "inbound", "failed" if body.get("error") else "success", message,
                            request_id=(body.get("response") or {}).get("requestId"), details={"error": body.get("error")})
                db.commit()
                return tx
            tx = INBOUND[kind](db, hospital, headers, body)
            db.commit()
            return tx
        except (GatewayError, HipError) as exc:
            db.rollback()
            hospital = hospital_for(db, headers.get("x-hip-id")) or db.scalar(select(Hospital).order_by(Hospital.id))
            tx = record(db, hospital.id, kind, "inbound", "failed", f"Could not complete: {exc}")
            db.commit()
            return tx


# ====================================================================================================================
# Simulator (ABDM_MODE=simulation) (formerly app/hip/simulator.py)
# ====================================================================================================================
# In-process stand-in for the ABDM gateway, consent manager, the patient's ABHA app and an HIU.
#
# Used only when ABDM_MODE=simulation. Several hospitals can share this bridge: every message carries the
# addressed hospital's X-HIP-ID, and a data push to a push URL of this bridge (/api/hiu/data-push/...) is
# delivered to that hospital's HIU, so hospitals in this database exchange records with each other. It receives the HIP's outbound calls exactly as the real gateway would
# (same paths, headers and bodies), signs its callbacks with its own RSA key (verified by the same code path as
# real gateway tokens) and decrypts data pushes with its own HIU keys. Its state is in memory and every
# transaction it causes is labelled "simulation". It is not a model of ABDM's internal rules.

KID = "simulated-abdm-gateway"
_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
registry: dict[str, dict] = demo.abha_accounts()  # simulated ABHA accounts: address -> {name, gender, yearOfBirth, abhaNumber}
outbox: list[dict] = []  # calls received from the HIP (newest last)
phone: dict[str, str] = {}  # last OTP "delivered" by SMS per mobile number
sim_hiu: dict[str, dict] = {}  # transaction id -> {key material, decrypted summary}
_callbacks: list[tuple[str, dict, dict]] = []


def sim_reset() -> None:
    from app import hiu
    registry.clear(), outbox.clear(), phone.clear(), sim_hiu.clear(), _callbacks.clear()
    registry.update(demo.abha_accounts())  # the demo people always have ABHA accounts
    hiu.reset()


def issue_token(**claims) -> str:
    now = int(time.time())
    payload = {"iss": "simulated-abdm-gateway", "iat": now, "exp": now + 1200, **claims}
    return jwt.encode(payload, _key, algorithm="RS256", headers={"kid": KID})


def sim_jwks() -> dict:
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(_key.public_key(), as_dict=True)
    return {"keys": [{**jwk, "kid": KID, "alg": "RS256", "use": "sig"}]}


def callback_headers(hip_id: str | None = None) -> dict:
    return {"Authorization": f"Bearer {issue_token()}", "REQUEST-ID": str(uuid.uuid4()), "TIMESTAMP": timestamp(),
            "X-HIP-ID": hip_id or hospital_hip_id(), "X-CM-ID": "sbx"}


def deliver_sms(mobile: str, otp: str) -> None:
    phone[mobile] = otp


def last_call(path: str) -> dict | None:
    return next((c for c in reversed(outbox) if c["path"] == path), None)


def receive(method: str, path: str, body: dict | None, headers: dict) -> tuple[int, dict | None]:
    """The gateway side of an outbound HIP call."""
    outbox.append({"path": path, "method": method, "body": body, "request_id": headers.get("REQUEST-ID")})
    del outbox[:-200]
    if path in (CONSENT_INIT_PATH, CONSENT_STATUS_PATH, CONSENT_FETCH_PATH, HI_REQUEST_PATH):
        from app import hiu  # the HIU side: consent manager + an external HIP
        return hiu.receive(path, body, headers)
    if path == GENERATE_LINK_TOKEN_PATH:
        account = registry.get((body.get("abhaAddress") or "").lower())
        reply = {"abhaAddress": body.get("abhaAddress"), "response": {"requestId": headers["REQUEST-ID"]}}
        if account is None:
            reply["error"] = {"code": "SIM-404", "message": "ABHA address not found (simulated ABHA registry)"}
        elif (account["gender"], account["yearOfBirth"]) != (body.get("gender"), body.get("yearOfBirth")) \
                or account["name"].lower() != (body.get("name") or "").lower():
            reply["error"] = {"code": "SIM-422", "message": "Demographic details do not match the ABHA account (simulated)"}
        else:
            reply["linkToken"] = issue_token(abhaAddress=body["abhaAddress"], abhaNumber=account.get("abhaNumber"))
        _callbacks.append(("on_generate_token", callback_headers(headers.get("X-HIP-ID")), reply))
    elif path == ADD_CARE_CONTEXTS_PATH:
        reply = {"abhaAddress": body.get("abhaAddress"), "response": {"requestId": headers["REQUEST-ID"]}}
        try:
            jwt.decode(headers.get("X-LINK-TOKEN", ""), _key.public_key(), algorithms=["RS256"])
            reply["status"] = "Successfully Linked care context (simulated)"
        except jwt.PyJWTError:
            reply["error"] = {"code": "SIM-401", "message": "Invalid or expired link token (simulated)"}
        _callbacks.append(("on_add_care_contexts", callback_headers(headers.get("X-HIP-ID")), reply))
    return 202, None


LOCAL_PUSH_PATH = "/api/hiu/data-push/"


def receive_push(url: str, body: dict) -> int:
    """A data push from a HIP. To a push URL of this bridge it is delivered, after the HIP's own work is done, to
    the HIU of the hospital that opened it; otherwise the simulated HIU decrypts it with its own key material."""
    if LOCAL_PUSH_PATH in url:
        _callbacks.append(("local_push", {}, {"token": url.rsplit("/", 1)[-1], "body": body}))
        return 202
    session = sim_hiu.get(body.get("transactionId"))
    if session is None:
        return 404
    material = body["keyMaterial"]
    for entry in body.get("entries", []):
        content = decrypt(entry["content"], session["private"], session["nonce"],
                          unb64(material["dhPublicKey"]["keyValue"]), unb64(material["nonce"]))
        bundle = json.loads(content)
        session["received"].append({"careContextReference": entry["careContextReference"],
                                    "checksum_ok": hashlib.md5(content.encode()).hexdigest() == entry["checksum"],
                                    "resourceType": bundle["resourceType"],
                                    "profile": bundle["entry"][0]["resource"]["meta"]["profile"][0].rsplit("/", 1)[-1],
                                    "entries": len(bundle["entry"])})
    return 202


def flush() -> None:
    """Deliver queued gateway callbacks (after the HIP's own request has committed)."""
    from app.database import SessionLocal
    from app import hiu
    while _callbacks:
        kind, headers, body = _callbacks.pop(0)
        if kind == "local_push":  # a hospital's HIP pushing to another hospital's HIU (no gateway token involved)
            with SessionLocal() as db:
                hiu.receive_push(db, body["token"], body["body"])
            continue
        verify_callback(headers["Authorization"])
        if kind == "hiu_push":  # the simulated external HIP pushes data to the HIU's push URL
            with SessionLocal() as db:
                hiu.sim_push(db, body["transactionId"], body["hiRequest"])
        elif kind.startswith("hiu_"):
            hiu.handle_inbound(kind, headers, body)
        else:
            handle_inbound(kind, headers, body)


def send(kind: str, body: dict, hip_id: str | None = None):
    """A signed ABDM callback into the HIP, through the same verification as real callbacks."""
    headers = callback_headers(hip_id)
    verify_callback(headers["Authorization"])
    tx = handle_inbound(kind, headers, body)
    flush()
    return tx, headers["REQUEST-ID"]


def reply_to(path: str, request_id: str) -> dict | None:
    """The HIP's answer (on-discover, on-init, ...) to a simulated request."""
    call = next((c for c in reversed(outbox) if c["path"] == path
                 and (c["body"] or {}).get("response", {}).get("requestId") == request_id), None)
    return call["body"] if call else None


# ---------- simulated patient / consent manager / HIU actions ----------

def sim_discover(abha_address: str, name: str, gender: str, year_of_birth: int, mobile: str | None,
                 hip_id: str | None = None) -> dict:
    body = {"transactionId": str(uuid.uuid4()),
            "patient": {"id": abha_address, "name": name, "gender": gender, "yearOfBirth": year_of_birth,
                        "verifiedIdentifiers": [{"type": "MOBILE", "value": mobile}] if mobile else [],
                        "unverifiedIdentifiers": []}}
    _, request_id = send("discover", body, hip_id)
    return {"request": body, "response": reply_to(ON_DISCOVER_PATH, request_id)}


def sim_link_init(transaction_id: str, abha_address: str, discovered: list[dict], hip_id: str | None = None) -> dict:
    body = {"transactionId": transaction_id, "abhaAddress": abha_address, "patient": discovered}
    _, request_id = send("link_init", body, hip_id)
    return reply_to(ON_INIT_LINK_PATH, request_id)


def sim_link_confirm(link_reference: str, otp: str, hip_id: str | None = None) -> dict:
    _, request_id = send("link_confirm", {"confirmation": {"linkRefNumber": link_reference, "token": otp}}, hip_id)
    return reply_to(ON_CONFIRM_LINK_PATH, request_id)


def grant_consent(abha_address: str, patient_reference: str, care_contexts: list[str], hi_types: list[str],
                  date_from: str, date_to: str, erase_at: str, status: str = "GRANTED", consent_id: str | None = None,
                  hip_id: str | None = None, to_hip: str | None = None) -> dict:
    """The patient grants a simulated HIU access. to_hip: the HIP the notification is sent to; hip_id: the HIP
    named in the artefact (normally the same; different to test that a HIP refuses another HIP's consent)."""
    consent_id = consent_id or str(uuid.uuid4())
    to_hip = to_hip or hospital_hip_id()
    detail = {"schemaVersion": "v3", "consentId": consent_id, "createdAt": timestamp(),
              "patient": {"id": abha_address}, "hip": {"id": hip_id or to_hip}, "hiu": {"id": "SIM_HIU_001"},
              "careContexts": [{"patientReference": patient_reference, "careContextReference": r} for r in care_contexts],
              "purpose": {"text": "Care Management", "code": "CAREMGT"}, "hiTypes": hi_types,
              "consentManager": {"id": "sbx"},
              "permission": {"accessMode": "VIEW", "dateRange": {"from": date_from, "to": date_to},
                             "dataEraseAt": erase_at, "frequency": {"unit": "HOUR", "value": 1, "repeats": 0}}}
    _, request_id = send("consent_notify", {"notification": {"status": status, "consentId": consent_id,
                                                             "consentDetail": detail, "signature": "simulated"}},
                         to_hip)
    return {"consent_id": consent_id, "response": reply_to(CONSENT_ON_NOTIFY_PATH, request_id)}


def request_health_information(consent_id: str, date_from: str, date_to: str, hip_id: str | None = None) -> dict:
    """The HIU asks for data: fresh key material, then the HIP pushes encrypted records to the HIU."""
    own = generate_key_material()
    transaction_id = str(uuid.uuid4())
    sim_hiu[transaction_id] = {"private": own["private"], "nonce": own["nonce"], "received": []}
    body = {"transactionId": transaction_id, "hiRequest": {
        "consent": {"id": consent_id}, "dateRange": {"from": date_from, "to": date_to},
        "dataPushUrl": "sim://hiu/data-push",
        "keyMaterial": {"cryptoAlg": "ECDH", "curve": "Curve25519",
                        "dhPublicKey": {"expiry": "2099-01-01T00:00:00.000Z", "parameters": PARAMETERS,
                                        "keyValue": b64(own["public"])},
                        "nonce": b64(own["nonce"])}}}
    tx, request_id = send("health_information", body, hip_id)
    notify = last_call(HI_NOTIFY_PATH)
    return {"transaction_id": transaction_id, "on_request": reply_to(HI_ON_REQUEST_PATH, request_id),
            "received_by_hiu": sim_hiu[transaction_id]["received"],
            "notification": notify["body"] if notify and notify["body"]["notification"]["transactionId"] == transaction_id else None}


# ====================================================================================================================
# API routes (formerly app/hip/routes.py)
# ====================================================================================================================
# HIP staff API (/api/hip/...) and ABDM callback endpoints (bridge paths /api/v3/...).

staff = APIRouter(prefix="/hip", tags=["hip"])
callbacks = APIRouter(tags=["abdm-callbacks"])


class CareContextOut(ORMModel):
    id: int
    patient_id: int
    reference: str
    display: str
    hi_type: str
    record_date: UTCDateTime
    link_status: str
    linked_abha_address: str | None
    link_method: str | None
    linked_at: UTCDateTime | None
    message: str | None
    fhir_record_id: int


class TransactionOut(ORMModel):
    id: int
    mode: str
    kind: str
    direction: str
    status: str
    message: str
    request_id: str | None
    transaction_id: str | None
    consent_id: str | None
    patient: PatientSummary | None
    http_status: int | None
    details: dict | None
    created_at: UTCDateTime


class ConsentOut(ORMModel):
    consent_id: str
    mode: str
    status: str
    status_reason: str | None
    patient: PatientSummary | None
    abha_address: str | None
    hiu_id: str | None
    hiu_name: str | None = None  # the requesting hospital, when it is served by this bridge
    purpose: str | None
    hi_types: list
    care_contexts: list
    date_from: UTCDateTime | None
    date_to: UTCDateTime | None
    data_erase_at: UTCDateTime | None
    created_at: UTCDateTime


def facility_names(db: Session, role: str = "hiu") -> dict[str, str]:
    """ABDM service ID -> hospital name, for the hospitals served by this bridge."""
    names = {}
    for hospital in db.scalars(select(Hospital)):
        facility = hospital_hip_id(hospital) if role == "hip" else hospital_hiu_id(hospital)
        found = hospital_for(db, facility, role) if facility else None
        if found is not None and found.id == hospital.id:
            names[facility] = hospital.name
    return names


def consents_out(db: Session, rows) -> list[dict]:
    names = facility_names(db, "hiu")
    return [{**ConsentOut.model_validate(c).model_dump(), "hiu_name": names.get(c.hiu_id)} for c in rows]


def utc(value: datetime | None) -> str | None:
    return value.isoformat(timespec="seconds") + "Z" if value else None


def after_change() -> None:
    """In simulation, deliver the gateway's callbacks once the HIP's own transaction is committed."""
    if simulation():
        flush()


def run(action):
    try:
        result = action()
    except HipError as exc:
        raise HTTPException(422, str(exc))
    except GatewayError as exc:
        raise HTTPException(502, exc.message)
    after_change()
    return result


# ---------- status ----------

@staff.get("/status")
def hip_status(user: User = Depends(require("hip:read")), db: Session = Depends(get_db)):
    sandbox = not simulation()
    hip_id = hospital_hip_id(user.hospital)
    owner = hospital_for(db, hip_id, "hip") if hip_id else None
    routable = owner is not None and owner.id == user.hospital_id
    checks = [
        {"label": "Mode", "ok": True, "detail": "Simulation: an in-process stand-in for ABDM (no real data leaves)"
         if not sandbox else f"ABDM sandbox at {settings.abdm_gateway_url} (X-CM-ID {settings.abdm_cm_id})"},
        {"label": "HIP ID", "ok": routable,
         "detail": (f"{hip_id} ({user.hospital.name})" if routable else
                    f"{hip_id} is shared with another hospital: set this hospital's ABDM HIP ID on the Hospital profile")
         if hip_id else "Set ABDM_HIP_ID or the hospital's ABDM HIP ID (facility ID registered as HIP)"},
        {"label": "Client credentials", "ok": not sandbox or bool(settings.abdm_client_id and settings.abdm_client_secret),
         "detail": "Not needed in simulation" if not sandbox else
         ("Configured" if settings.abdm_client_id and settings.abdm_client_secret else "Set ABDM_CLIENT_ID and ABDM_CLIENT_SECRET")},
        {"label": "Bridge URL", "ok": not sandbox or (settings.abdm_bridge_url or "").startswith("https://"),
         "detail": settings.abdm_bridge_url or ("Not needed in simulation" if not sandbox else "Set ABDM_BRIDGE_URL to a public https URL")},
        {"label": "Callback verification", "ok": settings.abdm_verify_callbacks,
         "detail": "Gateway JWTs are verified against ABDM's published keys" if settings.abdm_verify_callbacks
         else "DISABLED: callbacks are not authenticated"},
        {"label": "Patient OTP delivery", "ok": not sandbox or settings.abdm_otp_test_display,
         "detail": "Simulated SMS" if not sandbox else ("Test display only (no SMS gateway)" if settings.abdm_otp_test_display
                                                         else "No SMS gateway: patient-initiated linking will be refused")},
        {"label": "FHIR validator", "ok": validator_available(), "detail": "Only validated FHIR records become care contexts"},
    ]
    hid = user.hospital_id

    def count(model, *where):
        return db.scalar(select(func.count()).select_from(model).where(model.hospital_id == hid, *where))

    counts = {
        "verified_links": count(HipPatientLink, HipPatientLink.status == "verified"),
        "care_contexts": count(CareContext), "linked_care_contexts": count(CareContext, CareContext.link_status == "linked"),
        "discovery_requests": count(HipTransaction, HipTransaction.kind == "discover"),
        "active_consents": count(HipConsent, HipConsent.status == "GRANTED"),
        "completed_transfers": count(HipTransaction, HipTransaction.kind == "health_information", HipTransaction.status == "success"),
        "pending_transfers": count(HipTransaction, HipTransaction.kind == "health_information", HipTransaction.status == "pending"),
        "failed": count(HipTransaction, HipTransaction.status == "failed"),
    }
    return {"mode": settings.abdm_mode, "hip_id": hip_id, "hiu_id": hospital_hiu_id(user.hospital), "checks": checks,
            "counts": counts, "ready": all(c["ok"] for c in checks if c["label"] != "FHIR validator")}


@staff.get("/network")
def network(user: User = Depends(require("hip:read")), db: Session = Depends(get_db)):
    """The hospitals this bridge serves and their ABDM IDs (a directory: names and IDs only, no patient data)."""
    hips, hius = facility_names(db, "hip"), facility_names(db, "hiu")
    rows = []
    for h in db.scalars(select(Hospital).where(Hospital.is_active.is_(True)).order_by(Hospital.id)):
        hip_id, hiu_id = hospital_hip_id(h), hospital_hiu_id(h)
        rows.append({"id": h.id, "name": h.name, "code": h.code, "city": h.city, "state": h.state,
                     "hip_id": hip_id if hips.get(hip_id) == h.name else None,
                     "hiu_id": hiu_id if hius.get(hiu_id) == h.name else None,
                     "this_hospital": h.id == user.hospital_id})
    return {"mode": settings.abdm_mode, "hospitals": rows}


@staff.post("/session-check")
def session_check(user: User = Depends(require("hip:configure")), db: Session = Depends(get_db)):
    """Obtain a gateway session token (proves the client credentials work); the token is not returned."""
    try:
        reset_gateway()
        session_token()
        status, message = "success", "Gateway session created with the configured credentials"
    except GatewayError as exc:
        status, message = "failed", exc.message
    tx = record(db, user.hospital_id, "session", "outbound", status, message)
    db.commit()
    return {"status": status, "message": message, "transaction_id": tx.id}


@staff.post("/bridge-url")
def update_bridge_url(user: User = Depends(require("hip:configure")), db: Session = Depends(get_db)):
    if not (settings.abdm_bridge_url or "").startswith("https://") and not simulation():
        raise HTTPException(422, "Set ABDM_BRIDGE_URL to the public https URL of this server first")
    url = settings.abdm_bridge_url or "https://hip.simulated.local"
    status, data, request_id = call(BRIDGE_URL_PATH, {"url": url}, method="PATCH")
    ok = 200 <= status < 300
    tx = record(db, user.hospital_id, "bridge_url", "outbound", "success" if ok else "failed",
                f"Bridge URL set to {url}" if ok else f"ABDM refused the bridge URL (HTTP {status})",
                request_id=request_id, http_status=status)
    db.commit()
    return {"status": tx.status, "message": tx.message}


# ---------- patients and care contexts ----------

@staff.get("/patients/{patient_id}")
def patient_overview(patient_id: int, user: User = Depends(require("hip:read")), db: Session = Depends(get_db)):
    patient = get_or_404(db, Patient, patient_id, user.hospital_id)
    contexts = sync_care_contexts(db, patient)
    db.commit()
    link = db.scalar(select(HipPatientLink).where(HipPatientLink.patient_id == patient.id))
    show_otp = simulation() or settings.abdm_otp_test_display
    requests = db.scalars(select(HipLinkRequest).where(HipLinkRequest.patient_id == patient.id)
                          .order_by(HipLinkRequest.id.desc()).limit(5)).all()
    return {
        "patient": PatientSummary.model_validate(patient).model_dump(),
        "abha_verification_method": patient.abha_verification_method,
        "link": link and {"abha_address": link.abha_address, "status": link.status, "message": link.message,
                          "mode": link.mode, "updated_at": utc(link.updated_at)},
        "care_contexts": [CareContextOut.model_validate(c).model_dump() for c in contexts],
        "link_requests": [{"link_reference": r.link_reference, "status": r.status, "abha_address": r.abha_address,
                           "care_contexts": r.care_context_refs, "mode": r.mode, "expires_at": utc(r.otp_expires_at),
                           "test_otp": r.test_otp if show_otp and r.status == "otp_sent" else None} for r in requests],
        "consents": consents_out(db, db.scalars(
            select(HipConsent).where(HipConsent.patient_id == patient.id).order_by(HipConsent.id.desc()))),
    }


@staff.post("/patients/{patient_id}/link-token")
def request_link_token(patient_id: int, user: User = Depends(require("hip:manage")), db: Session = Depends(get_db)):
    patient = get_or_404(db, Patient, patient_id, user.hospital_id)
    tx = run(lambda: generate_link_token(db, user, patient))
    return {"status": tx.status, "message": tx.message}


class LinkSelection(BaseModel):
    care_context_ids: list[int]


@staff.post("/patients/{patient_id}/care-contexts/link")
def link_care_contexts(patient_id: int, body: LinkSelection, user: User = Depends(require("hip:manage")),
                       db: Session = Depends(get_db)):
    patient = get_or_404(db, Patient, patient_id, user.hospital_id)
    contexts = db.scalars(select(CareContext).where(CareContext.id.in_(body.care_context_ids),
                                                    CareContext.patient_id == patient.id)).all()
    if len(contexts) != len(set(body.care_context_ids)) or any(c.link_status == "linked" for c in contexts):
        raise HTTPException(422, "Select unlinked care contexts of this patient")
    tx = run(lambda: add_care_contexts(db, user, patient, contexts))
    return {"status": tx.status, "message": tx.message}


@staff.get("/care-contexts", response_model=Page[CareContextOut])
def list_care_contexts(link_status: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                       user: User = Depends(require("hip:read")), db: Session = Depends(get_db)):
    query = select(CareContext).where(CareContext.hospital_id == user.hospital_id).order_by(CareContext.id.desc())
    if link_status:
        query = query.where(CareContext.link_status == link_status)
    return paginate(db, query, page, page_size)


@staff.get("/consents", response_model=Page[ConsentOut])
def list_consents(status: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                  user: User = Depends(require("hip:read")), db: Session = Depends(get_db)):
    query = select(HipConsent).where(HipConsent.hospital_id == user.hospital_id).order_by(HipConsent.id.desc())
    if status:
        query = query.where(HipConsent.status == status)
    result = paginate(db, query, page, page_size)
    return {**result, "items": consents_out(db, result["items"])}


@staff.get("/transactions", response_model=Page[TransactionOut])
def list_transactions(kind: str | None = None, status: str | None = None, page: int = Query(1, ge=1),
                      page_size: int = Query(25, ge=1, le=100), user: User = Depends(require("hip:read")),
                      db: Session = Depends(get_db)):
    query = select(HipTransaction).where(HipTransaction.hospital_id == user.hospital_id).order_by(HipTransaction.id.desc())
    if kind:
        query = query.where(HipTransaction.kind.in_(kind.split(",")))
    if status:
        query = query.where(HipTransaction.status == status)
    return paginate(db, query, page, page_size)


# ---------- simulation (ABDM_MODE=simulation only) ----------

def simulation_only(user: User = Depends(require("hip:manage"))) -> User:
    if not simulation():
        raise HTTPException(409, "Simulation actions are disabled in sandbox mode")
    return user


class SimAbha(BaseModel):
    abha_address: str
    name: str
    gender: str
    year_of_birth: int
    abha_number: str | None = None


@staff.post("/simulate/abha")
def simulate_abha(body: SimAbha, _: User = Depends(simulation_only)):
    registry[body.abha_address.lower()] = {"name": body.name, "gender": body.gender,
                                           "yearOfBirth": body.year_of_birth, "abhaNumber": body.abha_number}
    return {"message": f"Simulated ABHA account {body.abha_address} created"}


@staff.post("/simulate/discover/{patient_id}")
def simulate_discover(patient_id: int, abha_address: str = Body(embed=True), user: User = Depends(simulation_only),
                      db: Session = Depends(get_db)):
    p = get_or_404(db, Patient, patient_id, user.hospital_id)
    return sim_discover(abha_address.lower(), p.full_name, p.gender, p.year_of_birth, p.mobile,
                        hip_id=hospital_hip_id(user.hospital))


class SimLink(BaseModel):
    transaction_id: str
    abha_address: str
    patient: list[dict]


@staff.post("/simulate/link-init")
def simulate_link_init(body: SimLink, user: User = Depends(simulation_only), db: Session = Depends(get_db)):
    reply = sim_link_init(body.transaction_id, body.abha_address.lower(), body.patient,
                          hip_id=hospital_hip_id(user.hospital))
    request = db.scalar(select(HipLinkRequest).where(HipLinkRequest.link_reference == ((reply or {}).get("link") or {}).get("referenceNumber")))
    return {"response": reply, "sms_to_patient": phone.get(db.get(Patient, request.patient_id).mobile) if request else None}


class SimConfirm(BaseModel):
    link_reference: str
    otp: str


@staff.post("/simulate/link-confirm")
def simulate_link_confirm(body: SimConfirm, user: User = Depends(simulation_only)):
    return sim_link_confirm(body.link_reference, body.otp, hip_id=hospital_hip_id(user.hospital))


class SimConsent(BaseModel):
    patient_id: int
    care_context_ids: list[int] | None = None  # default: all linked care contexts
    hi_types: list[str] | None = None
    date_from: date
    date_to: date
    erase_at: datetime
    status: str = "GRANTED"
    consent_id: str | None = None


@staff.post("/simulate/consent")
def simulate_consent(body: SimConsent, user: User = Depends(simulation_only), db: Session = Depends(get_db)):
    patient = get_or_404(db, Patient, body.patient_id, user.hospital_id)
    contexts = [c for c in db.scalars(select(CareContext).where(CareContext.patient_id == patient.id))
                if c.link_status == "linked" and (body.care_context_ids is None or c.id in body.care_context_ids)]
    if not contexts and body.status == "GRANTED":
        raise HTTPException(422, "The patient has no linked care contexts to consent to")
    return grant_consent(contexts[0].linked_abha_address if contexts else patient.abha_address or "",
                         patient.patient_code, [c.reference for c in contexts],
                         body.hi_types or sorted({c.hi_type for c in contexts}),
                         f"{body.date_from}T00:00:00.000Z", f"{body.date_to}T23:59:59.000Z",
                         body.erase_at.isoformat() + ("Z" if body.erase_at.tzinfo is None else ""),
                         body.status, body.consent_id, to_hip=hospital_hip_id(user.hospital))


class SimRequest(BaseModel):
    consent_id: str
    date_from: date
    date_to: date


@staff.post("/simulate/health-information")
def simulate_health_information(body: SimRequest, user: User = Depends(simulation_only)):
    return request_health_information(body.consent_id, f"{body.date_from}T00:00:00.000Z",
                                      f"{body.date_to}T23:59:59.000Z", hip_id=hospital_hip_id(user.hospital))


# ---------- ABDM callbacks (bridge URL + these paths) ----------

REQUIRED = {
    "discover": ["transactionId", "patient"],
    "link_init": ["transactionId", "abhaAddress", "patient"],
    "link_confirm": ["confirmation.linkRefNumber", "confirmation.token"],
    "consent_notify": ["notification.consentId", "notification.status"],
    "health_information": ["transactionId", "hiRequest.consent.id", "hiRequest.dataPushUrl", "hiRequest.keyMaterial"],
    "on_generate_token": ["response.requestId"],
    "on_add_care_contexts": ["response.requestId"],
}
HIP_ADDRESSED = {"discover", "link_init", "link_confirm", "consent_notify", "health_information"}


def accept(kind: str, required: list[str] | None = None, handler=None, role: str | None = None):
    """A callback endpoint: verify the gateway JWT and that the addressed HIP/HIU id belongs to one of this bridge's
    hospitals, check required fields, answer 202 and process afterwards. Shared by the HIP and HIU callbacks."""
    required = REQUIRED[kind] if required is None else required
    handler = handler or handle_inbound
    if role is None and kind in HIP_ADDRESSED:
        role = "hip"
    id_header = {"hip": "x-hip-id", "hiu": "x-hiu-id"}.get(role)

    async def endpoint(request: Request, background: BackgroundTasks, db: Session = Depends(get_db)):
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(400, "Body must be JSON")
        try:
            verify_callback(request.headers.get("authorization"))
            if id_header and not (request.headers.get(id_header)
                                  and hospital_for(db, request.headers.get(id_header), role)):
                raise CallbackAuthError(f"{id_header.upper()} does not match any facility of this bridge")
        except CallbackAuthError as exc:
            hospital = hospital_for(db, None, role or "hip")
            if hospital is not None:  # with several hospitals and no match, there is no one to log it for
                record(db, hospital.id, "callback_rejected", "inbound", "failed", f"{kind}: {exc}",
                       request_id=request.headers.get("request-id"))
                db.commit()
            raise HTTPException(401, "Callback authentication failed")
        for path in required:
            node = body
            for part in path.split("."):
                node = node.get(part) if isinstance(node, dict) else None
            if node in (None, "", []):
                raise HTTPException(400, f"Missing {path}")
        background.add_task(handler, kind, dict(request.headers), body)
        return None
    return endpoint


for kind, path in {
    "discover": "/v3/hip/patient/care-context/discover",
    "link_init": "/v3/hip/link/care-context/init",
    "link_confirm": "/v3/hip/link/care-context/confirm",
    "consent_notify": "/v3/consent/request/hip/notify",
    "health_information": "/v3/hip/health-information/request",
    "on_generate_token": "/v3/hip/token/on-generate-token",
    "on_add_care_contexts": "/v3/link/on_carecontext",
}.items():
    callbacks.add_api_route(path, accept(kind), methods=["POST"], status_code=202, name=f"abdm_{kind}")
