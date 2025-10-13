from __future__ import annotations

from typing import Any, Dict

from fastapi import Depends, Request

from fastmcp.core.security import correlation_id, decode_agent_jwt


async def get_claims(request: Request) -> Dict[str, Any]:
    bearer = request.headers.get("Authorization")
    claims = decode_agent_jwt(bearer)
    request.state.claims = claims
    request.state.correlation_id = correlation_id()
    return claims

