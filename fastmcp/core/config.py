from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic_settings import BaseSettings, SettingsConfigDict


def _b64url_int(data: int) -> str:
    """Return base64url encoding without padding for RSA component integers."""
    length = (data.bit_length() + 7) // 8
    return _b64url_bytes(data.to_bytes(length, "big"))


def _b64url_bytes(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class Settings(BaseSettings):
    APP_NAME: str = "fastmcp"
    JWT_ISSUER: str = "https://idp.local"
    JWT_AUDIENCE: str = "fastmcp"
    JWT_ALG: str = "RS256"
    JWT_TTL_MIN: int = 10
    JWKS_PATH: str = ".runtime/dev-jwks.json"
    REQUIRE_MTLS: bool = False
    CONFIRM_TTL_SEC: int = 300
    ACTION_TOKEN_BYTES: int = 24
    IDEMPOTENCY_TTL_SEC: int = 600
    RATE_LIMIT_DEFAULT_RPS: int = 5
    RATE_BUCKET_BURST: int = 10
    SQLITE_URL: str = "sqlite:///./fastmcp.db"
    REDIS_URL: str = ""
    CATALOG_TENANT_DEFAULT: str = "public"
    AUDIT_WORM_DIR: str = ".audit"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    @property
    def jwks_path(self) -> Path:
        return Path(self.JWKS_PATH)

    @property
    def private_key_path(self) -> Path:
        return self.jwks_path.with_suffix(".pem")


def _generate_dev_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _ensure_dev_jwks(settings: Settings) -> Tuple[Dict[str, Any], bytes]:
    """Ensure JWKS and PEM exist; returns jwks dict and private key bytes."""
    jwks_path = settings.jwks_path
    pem_path = settings.private_key_path

    jwks: Dict[str, Any] | None = None
    pem_bytes: bytes | None = None

    if jwks_path.exists() and pem_path.exists():
        jwks = json.loads(jwks_path.read_text("utf-8"))
        pem_bytes = pem_path.read_bytes()
        return jwks, pem_bytes

    jwks_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = _generate_dev_rsa_key()

    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_path.write_bytes(pem_bytes)

    numbers = private_key.private_numbers()
    public_numbers = numbers.public_numbers

    jwk = {
        "kty": "RSA",
        "alg": settings.JWT_ALG,
        "use": "sig",
        "kid": "dev-key",
        "n": _b64url_int(public_numbers.n),
        "e": _b64url_int(public_numbers.e),
        "d": _b64url_int(numbers.d),
        "p": _b64url_int(numbers.p),
        "q": _b64url_int(numbers.q),
        "dp": _b64url_int(numbers.dmp1),
        "dq": _b64url_int(numbers.dmq1),
        "qi": _b64url_int(numbers.iqmp),
    }

    jwks = {"keys": [jwk]}
    jwks_path.write_text(json.dumps(jwks, indent=2), encoding="utf-8")

    return jwks, pem_bytes


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    _ensure_dev_jwks(settings)
    return settings


@lru_cache
def get_dev_crypto_material() -> Tuple[Dict[str, Any], bytes]:
    """Return JWKS dictionary and PEM-encoded private key for dev usage."""
    settings = get_settings()
    return _ensure_dev_jwks(settings)
