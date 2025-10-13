# Tool Execution API - Core endpoints for invoking tools with confirmation flow
# Main functions: invoke_tool() for execution, confirm_tool() for destructive operations
# Flow: validate -> RBAC -> rate limit -> idempotency -> [confirmation OR direct execution] -> audit

from __future__ import annotations

import datetime as dt
import json
import secrets
from typing import Any, Dict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlmodel import Session, select

from fastmcp.api.deps import get_claims
from fastmcp.api.utils import error_response, hash_payload
from fastmcp.core.rate_limit import RateDecision, get_rate_limiter
from fastmcp.core.rbac import allowed
from fastmcp.core.security import correlation_id, idempotency_key
from fastmcp.core.token_broker import exchange as broker_exchange
from fastmcp.db.schemas_sqlmodel import ConfirmationRequest, IdempotencyRecord, Manifest
from fastmcp.db.session import get_session
from fastmcp.models.tool_manifest import ToolManifest
from fastmcp.providers.base import get_adapter
from fastmcp.utils.audit_logger import log_audit_event


router = APIRouter(prefix="/tools", tags=["tools"])


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


async def _get_manifest(session: Session, tool_id: str) -> ToolManifest | None:
    manifest_row = session.exec(select(Manifest).where(Manifest.toolId == tool_id)).first()
    if not manifest_row:
        return None
    return ToolManifest(**manifest_row.manifest)


async def _write_idempotency_record(
    session: Session,
    key: str,
    request_hash: str,
    tenant: str,
    sub: str,
    tool_id: str,
    status: str,
    response_body: Dict[str, Any] | None,
    response_hash: str | None,
    ttl_seconds: int,
    ) -> None:
    expires_at = _utcnow() + dt.timedelta(seconds=ttl_seconds)
    record = session.get(IdempotencyRecord, key)
    if record:
        record.request_hash = request_hash
        record.status = status
        record.response_body = json.dumps(response_body) if response_body else None
        record.response_hash = response_hash
        record.expires_at = expires_at
        record.tool_id = tool_id
        record.tenant = tenant
        record.sub = sub
        session.add(record)
    else:
        session.add(
            IdempotencyRecord(
                key=key,
                request_hash=request_hash,
                status=status,
                response_body=json.dumps(response_body) if response_body else None,
                response_hash=response_hash,
                expires_at=expires_at,
                tool_id=tool_id,
                tenant=tenant,
                sub=sub,
            )
        )
    session.commit()


def _load_cached_response(record: IdempotencyRecord) -> Dict[str, Any]:
    if not record.response_body:
        return {}
    import json

    return json.loads(record.response_body)


def _rate_limit_error(rate_decision: RateDecision, corr_id: str) -> JSONResponse:
    response = error_response(
        code="RATE_LIMITED",
        message="Rate limit exceeded",
        status_code=429,
        corr_id=corr_id,
        details={"retry_after": rate_decision.retry_after},
    )
    if rate_decision.retry_after:
        response.headers["Retry-After"] = f"{int(rate_decision.retry_after)}"
    return response


async def _create_confirmation(
    session: Session,
    settings,
    tool_id: str,
    payload_hash: str,
    request_hash: str,
    tenant: str,
    sub: str,
    ) -> Dict[str, Any]:
    expires_at = _utcnow() + dt.timedelta(seconds=settings.CONFIRM_TTL_SEC)
    action_token = secrets.token_urlsafe(settings.ACTION_TOKEN_BYTES)
    confirmation = ConfirmationRequest(
        action_token=action_token,
        request_hash=request_hash,
        tool_id=tool_id,
        sub=sub,
        tenant=tenant,
        payload_hash=payload_hash,
        expires_at=expires_at,
    )
    session.add(confirmation)
    session.commit()
    return {"requires_confirmation": True, "action_token": action_token, "expires_at": expires_at.isoformat() + "Z"}


@router.post("/{tool_id}/invoke")
async def invoke_tool(
    tool_id: str,
    request: Request,
    session: Session = Depends(get_session),
    claims: Dict[str, Any] = Depends(get_claims),
    ):
    from fastmcp.core.config import get_settings

    settings = get_settings()
    corr_id = correlation_id()
    sub = claims.get("sub")
    if not sub:
        return error_response("UNAUTHORIZED", "Missing subject in token", 401, corr_id)

    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise ValueError("Payload must be JSON object")
    except ValueError as exc:
        return error_response("VALIDATION_ERROR", f"Invalid JSON payload: {exc}", 422, corr_id)

    manifest = await _get_manifest(session, tool_id)
    if not manifest:
        return error_response("FAILED_DEPENDENCY", "Tool manifest not found", 404, corr_id)

    tenant = claims.get("tenant", manifest.tenant)
    rate_decision = await get_rate_limiter().check(tenant, claims.get("sub", ""), tool_id)
    if not rate_decision.allowed:
        return _rate_limit_error(rate_decision, corr_id)

    decision = allowed(
        claims,
        "tools.invoke",
        resource={"toolId": manifest.toolId, "safety_tags": manifest.safety_tags, "tenant": manifest.tenant},
    )
    if not decision.allowed:
        return error_response("FORBIDDEN", f"Access denied: {decision.reason}", 403, corr_id)

    try:
        manifest.validate_input(payload)
    except Exception as exc:  # jsonschema ValidationError
        return error_response("VALIDATION_ERROR", f"Input validation failed: {exc}", 422, corr_id)

    payload_hash = hash_payload(payload)
    request_hash = hash_payload({"tool": tool_id, "payload": payload})
    key = await idempotency_key(request, claims)

    record = session.get(IdempotencyRecord, key)
    now = _utcnow()
    if record and record.expires_at > now and record.request_hash == request_hash:
        cached = _load_cached_response(record)
        response = JSONResponse(status_code=200 if record.status == "completed" else 202, content=cached)
        response.headers["X-Idempotent-Replay"] = "true"
        return response

    if decision.require_confirmation:
        confirmation_body = await _create_confirmation(session, settings, tool_id, payload_hash, request_hash, tenant, sub)
        await _write_idempotency_record(
            session,
            key,
            request_hash,
            tenant,
            sub,
            tool_id,
            status="pending_confirmation",
            response_body=confirmation_body,
            response_hash=None,
            ttl_seconds=settings.IDEMPOTENCY_TTL_SEC,
        )
        await log_audit_event(
            {
                "tenant": tenant,
                "sub": claims.get("sub", ""),
                "action": "tools.invoke",
                "toolId": tool_id,
                "request_hash": payload_hash,
                "result_hash": None,
                "policy_decision": decision.reason,
                "rate_limit": {"allowed": True},
                "provider_call_meta": {"provider": manifest.provider_id, "deferred": True},
            }
        )
        return JSONResponse(status_code=202, content=confirmation_body)

    await _write_idempotency_record(
        session,
        key,
        request_hash,
        tenant,
        sub,
        tool_id,
        status="in_progress",
        response_body=None,
        response_hash=None,
        ttl_seconds=settings.IDEMPOTENCY_TTL_SEC,
    )

    token_meta = await broker_exchange(
        manifest.provider_id,
        manifest.required_scopes,
        subject=claims.get("sub", ""),
        tenant=tenant,
        purpose=f"tool:{tool_id}",
    )

    adapter = get_adapter(manifest.provider_id)
    endpoint = tool_id.split(":", 1)[1] if ":" in tool_id else tool_id
    try:
        provider_result = await adapter.call(endpoint, payload)
    except Exception as exc:
        await _write_idempotency_record(
            session,
            key,
            request_hash,
            tenant,
            claims["sub"],
            tool_id,
            status="failed",
            response_body={"error": "provider_failure"},
            response_hash=None,
            ttl_seconds=settings.IDEMPOTENCY_TTL_SEC,
        )
        return error_response("FAILED_DEPENDENCY", f"Provider invocation failed: {exc}", 502, corr_id)

    try:
        manifest.validate_output(provider_result)
    except Exception as exc:
        await _write_idempotency_record(
            session,
            key,
            request_hash,
            tenant,
            claims["sub"],
            tool_id,
            status="failed",
            response_body=None,
            response_hash=None,
            ttl_seconds=settings.IDEMPOTENCY_TTL_SEC,
        )
        return error_response("FAILED_DEPENDENCY", f"Provider output invalid: {exc}", 502, corr_id)

    response_body = {
        "toolId": tool_id,
        "result": provider_result,
        "token_meta": {k: token_meta.get(k) for k in ("token_type", "expires_in", "audience")},
    }
    result_hash = hash_payload(provider_result)

    await _write_idempotency_record(
        session,
        key,
        request_hash,
        tenant,
        claims["sub"],
        tool_id,
        status="completed",
        response_body=response_body,
        response_hash=result_hash,
        ttl_seconds=settings.IDEMPOTENCY_TTL_SEC,
    )

    await log_audit_event(
        {
            "tenant": tenant,
            "sub": claims.get("sub", ""),
            "action": "tools.invoke",
            "toolId": tool_id,
            "request_hash": payload_hash,
            "result_hash": result_hash,
            "policy_decision": decision.reason,
            "rate_limit": {"allowed": True},
            "provider_call_meta": {"provider": manifest.provider_id},
        }
    )

    return JSONResponse(status_code=200, content=response_body)


@router.post("/{tool_id}/confirm")
async def confirm_tool(
    tool_id: str,
    request: Request,
    session: Session = Depends(get_session),
    claims: Dict[str, Any] = Depends(get_claims),
    ):
    from fastmcp.core.config import get_settings

    settings = get_settings()
    corr_id = correlation_id()

    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise ValueError("Payload must be JSON object")
    except ValueError as exc:
        return error_response("VALIDATION_ERROR", f"Invalid JSON payload: {exc}", 422, corr_id)

    action_token = payload.get("action_token") or request.headers.get("X-Action-Token")
    if not action_token:
        return error_response("UNAUTHORIZED", "Missing action token", 401, corr_id)

    confirmation = session.exec(
        select(ConfirmationRequest).where(ConfirmationRequest.action_token == action_token)
    ).first()
    if not confirmation:
        return error_response("UNAUTHORIZED", "Invalid action token", 401, corr_id)

    if confirmation.tool_id != tool_id or confirmation.sub != claims.get("sub") or confirmation.tenant != claims.get("tenant"):
        return error_response("FORBIDDEN", "Token context mismatch", 403, corr_id)

    if confirmation.expires_at < _utcnow():
        return error_response("CONFLICT", "Confirmation token expired", 409, corr_id)

    if confirmation.confirmed_at:
        return error_response("CONFLICT", "Action already confirmed", 409, corr_id)

    manifest = await _get_manifest(session, tool_id)
    if not manifest:
        return error_response("FAILED_DEPENDENCY", "Tool manifest not found", 404, corr_id)

    actual_payload = (
        payload.get("input")
        or payload.get("payload")
        or {k: v for k, v in payload.items() if k != "action_token"}
    )
    if not isinstance(actual_payload, dict):
        return error_response("VALIDATION_ERROR", "Confirmation payload must be object", 422, corr_id)

    if hash_payload(actual_payload) != confirmation.payload_hash:
        return error_response("UNAUTHORIZED", "Payload mismatch", 401, corr_id)

    try:
        manifest.validate_input(actual_payload)
    except Exception as exc:
        return error_response("VALIDATION_ERROR", f"Input validation failed: {exc}", 422, corr_id)

    tenant = claims.get("tenant", manifest.tenant)
    request_hash = hash_payload({"tool": tool_id, "payload": actual_payload})
    if request_hash != confirmation.request_hash:
        return error_response("UNAUTHORIZED", "Request hash mismatch", 401, corr_id)
    record = session.exec(select(IdempotencyRecord).where(IdempotencyRecord.request_hash == confirmation.request_hash)).first()
    if record:
        key = record.key
    else:
        key = await idempotency_key(request, claims)

    # reuse invoke execution path
    token_meta = await broker_exchange(
        manifest.provider_id,
        manifest.required_scopes,
        subject=claims.get("sub", ""),
        tenant=tenant,
        purpose=f"tool:{tool_id}",
    )

    adapter = get_adapter(manifest.provider_id)
    endpoint = tool_id.split(":", 1)[1] if ":" in tool_id else tool_id
    try:
        provider_result = await adapter.call(endpoint, actual_payload)
    except Exception as exc:
        return error_response("FAILED_DEPENDENCY", f"Provider invocation failed: {exc}", 502, corr_id)
    manifest.validate_output(provider_result)

    result_hash = hash_payload(provider_result)
    response_body = {
        "toolId": tool_id,
        "result": provider_result,
        "token_meta": {k: token_meta.get(k) for k in ("token_type", "expires_in", "audience")},
    }

    confirmation.confirmed_at = _utcnow()
    session.add(confirmation)

    await _write_idempotency_record(
        session,
        key,
        request_hash,
        tenant,
        claims["sub"],
        tool_id,
        status="completed",
        response_body=response_body,
        response_hash=result_hash,
        ttl_seconds=settings.IDEMPOTENCY_TTL_SEC,
    )

    await log_audit_event(
        {
            "tenant": tenant,
            "sub": claims.get("sub", ""),
            "action": "tools.confirm",
            "toolId": tool_id,
            "request_hash": confirmation.request_hash,
            "result_hash": result_hash,
            "policy_decision": "confirmation",
            "rate_limit": {"allowed": True},
            "provider_call_meta": {"provider": manifest.provider_id},
        }
    )

    session.commit()

    return JSONResponse(status_code=200, content=response_body)
