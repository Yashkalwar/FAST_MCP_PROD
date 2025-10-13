from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .config import get_settings

try:
    import redis.asyncio as aioredis  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    aioredis = None


@dataclass
class RateDecision:
    allowed: bool
    retry_after: float = 0.0


class RateLimiter:
    def __init__(self) -> None:
        settings = get_settings()
        self.rate = float(settings.RATE_LIMIT_DEFAULT_RPS)
        self.burst = float(settings.RATE_BUCKET_BURST)
        self._lock = asyncio.Lock()
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._redis = None
        if settings.REDIS_URL:
            if aioredis:
                self._redis = aioredis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
            else:
                # Fallback silently to in-memory if redis client not available.
                self._redis = None

    async def check(self, tenant: str, subject: str, tool_id: str) -> RateDecision:
        key = f"rl:{tenant}:{subject}:{tool_id}"
        if self._redis:
            return await self._check_redis(key)
        return await self._check_memory(key)

    async def _check_memory(self, key: str) -> RateDecision:
        async with self._lock:
            now = time.monotonic()
            tokens, timestamp = self._buckets.get(key, (self.burst, now))
            # Refill tokens
            tokens = min(self.burst, tokens + (now - timestamp) * self.rate)
            if tokens >= 1.0:
                tokens -= 1.0
                self._buckets[key] = (tokens, now)
                return RateDecision(True, 0.0)
            retry = (1.0 - tokens) / self.rate if self.rate > 0 else 1.0
            self._buckets[key] = (tokens, now)
            return RateDecision(False, max(retry, 0.0))

    async def _check_redis(self, key: str) -> RateDecision:
        assert self._redis is not None  # For type checkers
        now = time.monotonic()
        data = await self._redis.hgetall(key)
        tokens = float(data.get("tokens", self.burst))
        timestamp = float(data.get("ts", now))
        tokens = min(self.burst, tokens + (now - timestamp) * self.rate)
        if tokens >= 1.0:
            tokens -= 1.0
            mapping = {"tokens": tokens, "ts": now}
            await self._redis.hset(key, mapping=mapping)
            ttl = int(self.burst / self.rate) + 1 if self.rate > 0 else int(self.burst) + 1
            await self._redis.expire(key, ttl)
            return RateDecision(True, 0.0)
        retry = (1.0 - tokens) / self.rate if self.rate > 0 else 1.0
        mapping = {"tokens": tokens, "ts": now}
        await self._redis.hset(key, mapping=mapping)
        ttl = int(self.burst / self.rate) + 1 if self.rate > 0 else int(self.burst) + 1
        await self._redis.expire(key, ttl)
        return RateDecision(False, max(retry, 0.0))


_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter
