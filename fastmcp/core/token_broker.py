from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Dict, Tuple

from structlog import get_logger

from fastmcp.providers.base import get_adapter


logger = get_logger(__name__)

_cache: Dict[str, Tuple[dict, float]] = {}
_cache_lock = asyncio.Lock()


def _cache_key(provider_id: str, tenant: str, scopes: list[str]) -> str:
    normalized = sorted(scopes)
    hash_input = "|".join([provider_id, tenant, ",".join(normalized)])
    digest = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()
    return f"{provider_id}:{tenant}:{digest}"


async def exchange(provider_id: str, scopes: list[str], subject: str, tenant: str, purpose: str) -> dict:
    """Return provider access tokens without logging sensitive values."""
    key = _cache_key(provider_id, tenant, scopes)
    now = time.monotonic()

    async with _cache_lock:
        cached = _cache.get(key)
        if cached and cached[1] > now:
            logger.info(
                "token_broker.cache_hit",
                provider=provider_id,
                tenant=tenant,
                scopes_count=len(scopes),
            )
            return cached[0]

    adapter = get_adapter(provider_id)
    token_meta = await adapter.exchange(scopes, subject, tenant, purpose)
    ttl = max(1, int(token_meta.get("expires_in", 60)))
    expire_at = now + ttl - 1

    async with _cache_lock:
        _cache[key] = (token_meta, expire_at)

    logger.info(
        "token_broker.exchange",
        provider=provider_id,
        tenant=tenant,
        scopes_count=len(scopes),
        purpose=purpose,
    )
    return token_meta

