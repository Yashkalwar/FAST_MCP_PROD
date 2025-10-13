from __future__ import annotations

import asyncio
import os
import secrets
from typing import Any, Dict

from structlog import get_logger

from .base import ProviderAdapter, register_adapter


logger = get_logger(__name__)


class AdsProviderAdapter(ProviderAdapter):
    def __init__(self) -> None:
        super().__init__("ads")
        self.mode = os.getenv("ADS_PROVIDER_MODE", "mock")
        self.audience = os.getenv("ADS_PROVIDER_AUDIENCE", "ads")

    async def exchange(self, scopes: list[str], subject: str, tenant: str, purpose: str) -> dict:
        # Mocked client credentials exchange.
        expires_in = 120
        token_meta = {
            "access_token": secrets.token_urlsafe(32),
            "token_type": "Bearer",
            "expires_in": expires_in,
            "audience": self.audience,
        }
        logger.info(
            "ads_provider.exchange",
            tenant=tenant,
            subject=subject,
            scopes_count=len(scopes),
            purpose=purpose,
        )
        return token_meta

    async def call(self, endpoint: str, payload: dict) -> dict:
        if endpoint == "createCampaign":
            return await self.create_campaign(payload)
        raise ValueError(f"unsupported endpoint: {endpoint}")

    async def create_campaign(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        await asyncio.sleep(0.1)
        campaign_id = secrets.token_hex(8)
        logger.info("ads_provider.create_campaign", payload_keys=list(payload.keys()))
        return {"campaignId": campaign_id, "status": "CREATED"}


register_adapter(AdsProviderAdapter())

