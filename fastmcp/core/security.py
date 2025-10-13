from __future__ import annotations

import hashlib
import json
import time
import uuid
from contextvars import ContextVar
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request, status
from jose import JWTError, jwt

from .config import get_dev_crypto_material, get_settings


_correlation_id_ctx: ContextVar[str] = ContextVar("correlation_id", default="")


def correlation_id(force_new: bool = False, value: str | None = None) -> str:
    """Return correlation id for current context, creating one if missing."""
    if value:
        _correlation_id_ctx.set(value)
        return value
    current = "" if force_new else _correlation_id_ctx.get()
    if current:
        return current
    new_id = uuid.uuid4().hex
    _correlation_id_ctx.set(new_id)
    return new_id


def _load_keys() -> dict[str, Any]:
    jwks, _ = get_dev_crypto_material()
    keys: dict[str, Any] = {}
    for key in jwks.get("keys", []):
        kid = key.get("kid")
        if not kid:
            continue
        keys[kid] = key
    return keys


def _get_private_key() -> bytes:
    _, pem = get_dev_crypto_material()
    return pem


_public_keys = _load_keys()


def decode_agent_jwt(bearer: Optional[str]) -> Dict[str, Any]:
    """Validate incoming Bearer token and return claims."""
    if not bearer or not bearer.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": "Missing bearer token", "corr_id": correlation_id()},
        )

    token = bearer.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": "Invalid bearer token", "corr_id": correlation_id()},
        )

    settings = get_settings()

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        key = _public_keys.get(kid)
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "UNAUTHORIZED", "message": "Unknown token key id", "corr_id": correlation_id()},
            )

        claims = jwt.decode(token, key, algorithms=[settings.JWT_ALG], audience=settings.JWT_AUDIENCE, issuer=settings.JWT_ISSUER)
    except JWTError as exc:  # pragma: no cover - rewrapped as HTTP error
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": f"JWT validation failed: {exc}", "corr_id": correlation_id()},
        ) from exc

    exp = claims.get("exp")
    if exp and int(exp) < int(time.time()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": "Token expired", "corr_id": correlation_id()},
        )

    claims.setdefault("roles", [])
    claims.setdefault("scopes", [])
    claims.setdefault("tenant", get_settings().CATALOG_TENANT_DEFAULT)
    return claims


def issue_internal_jwt(subject: str, scopes: list[str], ttl: int) -> str:
    """Issue a short-lived internal JWT (dev only)."""
    settings = get_settings()
    now = int(time.time())
    payload = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "sub": subject,
        "iat": now,
        "exp": now + ttl,
        "scopes": scopes,
    }
    private_key = _get_private_key()
    return jwt.encode(payload, private_key, algorithm=settings.JWT_ALG, headers={"kid": "dev-key"})


async def idempotency_key(request: Request, claims: Dict[str, Any]) -> str:
    """Return an idempotency key deriving from header or request hash."""
    header_key = request.headers.get("Idempotency-Key")
    if header_key:
        return header_key

    body = await request.body()
    payload = "|".join(
        [
            request.url.path,
            body.decode("utf-8", errors="ignore"),
            claims.get("sub", ""),
            claims.get("tenant", ""),
        ]
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return digest
