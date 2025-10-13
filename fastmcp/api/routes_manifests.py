# Tool Manifest Management API - Allows admins to register new tool definitions
# Main function: register_manifest() creates/updates tool manifests in database
# Flow: admin role check -> validate manifest -> upsert to database -> return status

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlmodel import Session

from fastmcp.api.deps import get_claims
from fastmcp.api.utils import error_response
from fastmcp.core.security import correlation_id
from fastmcp.db.schemas_sqlmodel import Manifest
from fastmcp.db.session import get_session
from fastmcp.models.tool_manifest import ToolManifest


router = APIRouter(prefix="/manifests", tags=["manifests"])


@router.post("/register")
async def register_manifest(
    manifest: ToolManifest,
    session: Session = Depends(get_session),
    claims=Depends(get_claims),
    ):
    corr_id = correlation_id()
    allowed_admin_roles = {"admin", "data-admin", "mcp-admin"}
    roles = set(claims.get("roles") or [])
    if not roles.intersection(allowed_admin_roles):
        return error_response("FORBIDDEN", "Admin role required", 403, corr_id)

    existing = session.get(Manifest, manifest.toolId)
    if existing:
        existing.manifest = manifest.model_dump()
        existing.tenant = manifest.tenant
        existing.provider_id = manifest.provider_id
        session.add(existing)
    else:
        session.add(
            Manifest(
                toolId=manifest.toolId,
                manifest=manifest.model_dump(),
                tenant=manifest.tenant,
                provider_id=manifest.provider_id,
            )
        )
    session.commit()
    return JSONResponse(status_code=201, content={"status": "registered", "toolId": manifest.toolId})
