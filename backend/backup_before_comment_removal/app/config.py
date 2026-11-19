from pathlib import Path
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
BACKEND_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BACKEND_DIR.parent / "database"  # project-level folder, next to backend/ and frontend/


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BACKEND_DIR / ".env", extra="ignore")

    # SQLite file in the project's database/ folder, wherever the backend is started from; set DATABASE_URL in .env
    # for another file or PostgreSQL.
    database_url: str = f"sqlite:///{(DATABASE_DIR / 'hospital.db').as_posix()}"
    jwt_secret: str
    jwt_expire_minutes: int = 480  # longest a sign-in lasts (one shift), however active it is
    session_idle_minutes: int = 30  # a session unused this long ends; the browser also signs out after this
    # The browser keeps its session in an HttpOnly cookie (scripts cannot read it). Secure = https only; browsers
    # also accept Secure cookies on http://localhost, so keep it on unless testing from another machine over http.
    cookie_secure: bool = True
    password_scrypt_n: int = 2**15  # scrypt cost for new password hashes; older, cheaper hashes upgrade at sign-in
    # Roles that must use two-step sign-in (TOTP authenticator app), e.g. "hospital_admin,doctor"; anyone can opt in.
    mfa_required_roles: str = ""
    mfa_issuer: str = "ABDM Hospital"  # name shown in the authenticator app
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Only used by init_db.py when seeding the first hospital.
    hospital_name: str = "City General Hospital"
    hospital_code: str = "CGH"
    admin_username: str = "admin"
    admin_password: str | None = None

    # Phase 3: AI (Mistral AI) for document extraction and the clinical assistant; OCR model reads PDFs and images.
    mistral_api_key: str | None = None
    ai_model: str = "mistral-large-latest"
    ai_ocr_model: str = "mistral-ocr-latest"
    upload_dir: Path = BACKEND_DIR / "uploads"
    max_upload_mb: int = 20
    # Official HL7 FHIR validator; scripts/setup_validator.ps1 downloads both into backend/tools.
    fhir_validator_jar: Path = BACKEND_DIR / "tools" / "validator_cli.jar"
    java_path: str | None = None  # default: tools/jdk-*/bin/java.exe, else `java` on PATH
    fhir_tx_server: str = "https://tx.fhir.org"  # terminology server; "n/a" validates offline (no code checks)

    # ABDM (HIP and HIU) runs as an in-process simulation. Default service IDs for hospitals without their own.
    abdm_hip_id: str | None = None
    abdm_hiu_id: str | None = None

    # Encryption at rest for records received from other providers (and HIU key material). Kept apart from
    # JWT_SECRET so either can be rotated on its own. Without it, the legacy key derived from JWT_SECRET is used.
    record_sealing_key: str | None = None  # active key: >= 32 random characters
    record_sealing_old_keys: str = ""  # comma-separated earlier keys, still accepted for reading after a rotation

    @field_validator("jwt_secret")
    @classmethod
    def strong_secret(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters")
        if value.startswith("change-me"):
            raise ValueError("JWT_SECRET still has the example value from .env.example; generate a new one")
        return value

    @field_validator("record_sealing_key")
    @classmethod
    def strong_sealing_key(cls, value: str | None) -> str | None:
        if value is not None and value.strip() == "":
            return None
        if value is not None and len(value) < 32:
            raise ValueError("RECORD_SEALING_KEY must be at least 32 characters")
        return value

    @field_validator("password_scrypt_n")
    @classmethod
    def scrypt_cost(cls, value: int) -> int:
        if value < 2**14 or value & (value - 1):
            raise ValueError("PASSWORD_SCRYPT_N must be a power of two, at least 16384")
        return value

    @property
    def mfa_required_role_list(self) -> set[str]:
        return {r.strip() for r in self.mfa_required_roles.split(",") if r.strip()}

    @property
    def record_sealing_old_key_list(self) -> list[str]:
        return [k.strip() for k in self.record_sealing_old_keys.split(",") if k.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
