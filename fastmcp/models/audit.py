from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    ts: str
    corr_id: str
    tenant: str
    sub: str
    action: str
    toolId: Optional[str] = None
    request_hash: Optional[str] = None
    result_hash: Optional[str] = None
    policy_decision: Optional[str] = None
    rate_limit: Optional[Dict[str, Any]] = None
    provider_call_meta: Optional[Dict[str, Any]] = None
    prev_hash: Optional[str] = None
    event_hash: Optional[str] = None

