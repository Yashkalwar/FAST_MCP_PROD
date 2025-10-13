# Internal Service API - Health checks, metrics, and token broker for internal services
# Main functions: health() status, metrics() for monitoring, broker_exchange_internal() for tokens
# Flow: internal call validation -> token exchange -> return metadata

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

from fastmcp.api.utils import error_response
from fastmcp.core.config import get_settings
from fastmcp.core.security import correlation_id
from fastmcp.core.token_broker import exchange as broker_exchange


router = APIRouter(tags=["internal"])


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.get("/metrics")
async def metrics() -> PlainTextResponse:
    return PlainTextResponse("fastmcp_ready 1\n")


class BrokerRequest(BaseModel):
    provider_id: str
    scopes: List[str] = []
    purpose: str


@router.post("/auth/token-broker/exchange")
async def broker_exchange_internal(request: Request, payload: BrokerRequest):
    corr_id = correlation_id()
    if request.headers.get("X-Internal-Call", "").lower() != "true":
        return error_response("FORBIDDEN", "Internal access required", 403, corr_id)

    subject = request.headers.get("X-Subject", "internal")
    tenant = request.headers.get("X-Tenant", get_settings().CATALOG_TENANT_DEFAULT)

    token_meta = await broker_exchange(
        payload.provider_id,
        payload.scopes,
        subject=subject,
        tenant=tenant,
        purpose=payload.purpose,
    )
    return JSONResponse(token_meta)

