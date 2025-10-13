# Pipedrive CRM Provider - Integrates with Pipedrive API for deal and contact management
# Main functions: exchange() for auth tokens, call() for API operations
# Supports: createDeal, getDeal, updateDeal, createContact operations

from __future__ import annotations

import os
import secrets
from typing import Any, Dict

import httpx
from structlog import get_logger

from .base import ProviderAdapter, register_adapter

logger = get_logger(__name__)


class PipedriveProviderAdapter(ProviderAdapter):
    def __init__(self) -> None:
        super().__init__("pipedrive")
        self.api_token = os.getenv("PIPEDRIVE_API_TOKEN", "")
        self.company_domain = os.getenv("PIPEDRIVE_COMPANY_DOMAIN", "api")
        self.base_url = f"https://{self.company_domain}.pipedrive.com/v1"

    async def exchange(self, scopes: list[str], subject: str, tenant: str, purpose: str) -> dict:
        # Return mock token metadata - Pipedrive uses API tokens directly
        expires_in = 3600
        token_meta = {
            "access_token": self.api_token,
            "token_type": "Bearer", 
            "expires_in": expires_in,
            "audience": "pipedrive",
        }
        logger.info(
            "pipedrive_provider.exchange",
            tenant=tenant,
            subject=subject,
            scopes_count=len(scopes),
            purpose=purpose,
        )
        return token_meta

    async def call(self, endpoint: str, payload: dict) -> dict:
        if endpoint == "createDeal":
            return await self.create_deal(payload)
        elif endpoint == "getDeal":
            return await self.get_deal(payload)
        elif endpoint == "updateDeal":
            return await self.update_deal(payload)
        elif endpoint == "createContact":
            return await self.create_contact(payload)
        raise ValueError(f"unsupported endpoint: {endpoint}")

    async def create_deal(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/deals",
                params={"api_token": self.api_token},
                json=payload
            )
            response.raise_for_status()
            data = response.json()
            logger.info("pipedrive_provider.create_deal", deal_id=data.get("data", {}).get("id"))
            return {"dealId": data["data"]["id"], "status": "CREATED", "title": data["data"]["title"]}

    async def get_deal(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        deal_id = payload.get("deal_id")
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/deals/{deal_id}",
                params={"api_token": self.api_token}
            )
            response.raise_for_status()
            data = response.json()
            return {"dealId": data["data"]["id"], "title": data["data"]["title"], "value": data["data"]["value"]}

    async def update_deal(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        deal_id = payload.pop("deal_id")
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{self.base_url}/deals/{deal_id}",
                params={"api_token": self.api_token},
                json=payload
            )
            response.raise_for_status()
            data = response.json()
            return {"dealId": data["data"]["id"], "status": "UPDATED", "title": data["data"]["title"]}

    async def create_contact(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/persons",
                params={"api_token": self.api_token},
                json=payload
            )
            response.raise_for_status()
            data = response.json()
            return {"contactId": data["data"]["id"], "status": "CREATED", "name": data["data"]["name"]}


register_adapter(PipedriveProviderAdapter())
