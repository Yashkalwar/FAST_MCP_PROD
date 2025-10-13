# Tool Catalog API - Lists available tools filtered by user permissions
# Main function: list_tool_catalog() returns tools user can access based on RBAC and scopes
# Flow: RBAC check -> get user tenant -> query manifests -> filter by scopes -> return catalog

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlmodel import Session, select

from fastmcp.api.deps import get_claims
from fastmcp.api.utils import error_response
from fastmcp.core.config import get_settings
from fastmcp.core.rbac import allowed, subject_scopes
from fastmcp.core.security import correlation_id
from fastmcp.db.schemas_sqlmodel import Manifest
from fastmcp.db.session import get_session
from fastmcp.models.tool_manifest import ToolManifest


router = APIRouter(tags=["catalog"])


@router.get("/tool-catalog")
async def list_tool_catalog(
    session: Session = Depends(get_session),
    claims: Dict[str, Any] = Depends(get_claims),
):
    corr_id = correlation_id()
    decision = allowed(claims, "catalog:list")
    if not decision.allowed:
        return error_response("FORBIDDEN", "Catalog access denied", 403, corr_id)

    settings = get_settings()
    tenant = claims.get("tenant", settings.CATALOG_TENANT_DEFAULT)
    rows = session.exec(
        select(Manifest).where(Manifest.tenant.in_({tenant, settings.CATALOG_TENANT_DEFAULT}))
    ).all()
    scopes = subject_scopes(claims)

    manifests: List[Dict[str, Any]] = []
    for row in rows:
        manifest = ToolManifest(**row.manifest)
        if manifest.required_scopes and not set(manifest.required_scopes).issubset(scopes):
            continue
        manifests.append(manifest.model_dump())

    return JSONResponse({"tenant": tenant, "tools": manifests})
