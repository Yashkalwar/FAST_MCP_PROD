# FastMCP Main Application - Enterprise orchestration platform for agent tooling
# Core functions: FastAPI app setup, middleware for correlation IDs, database seeding
# Flow: startup -> load config -> seed DB -> register routes -> handle requests with RBAC/audit

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
from typing import Any, Dict

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlmodel import SQLModel, Session, select

from fastmcp.api.routes_catalog import router as catalog_router
from fastmcp.api.routes_internal import router as internal_router
from fastmcp.api.routes_manifests import router as manifests_router
from fastmcp.api.routes_tools import router as tools_router
from fastmcp.core.config import get_settings
from fastmcp.core.security import correlation_id
from fastmcp.db.schemas_sqlmodel import Manifest
from fastmcp.db.session import engine
from fastmcp.models.tool_manifest import ToolManifest
from fastmcp.providers import ads_provider  # noqa: F401 - ensure registration
from fastmcp.providers import database_provider  # noqa: F401 - ensure registration
from fastmcp.providers import mcp_provider  # noqa: F401 - ensure registration
from fastmcp.providers import pipedrive_provider  # noqa: F401 - ensure registration


def configure_logging() -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(),
    )


settings = get_settings()
configure_logging()

app = FastAPI(title=settings.APP_NAME, version="0.1.0")

app.include_router(internal_router)
app.include_router(catalog_router)
app.include_router(manifests_router)
app.include_router(tools_router)


SAMPLE_MANIFEST = {
    "toolId": "ads:createCampaign",
    "name": "Create Ad Campaign",
    "description": "Creates a new ad campaign on the Ads provider.",
    "inputs": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["name", "budget", "startDate"],
        "properties": {
            "name": {"type": "string", "minLength": 3, "maxLength": 64},
            "budget": {"type": "number", "minimum": 1},
            "startDate": {"type": "string", "format": "date"},
            "endDate": {"type": "string", "format": "date"},
        },
    },
    "outputs": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["campaignId", "status"],
        "properties": {
            "campaignId": {"type": "string"},
            "status": {"type": "string", "enum": ["CREATED", "CONFIRMED"]},
        },
    },
    "required_scopes": ["ads.write"],
    "safety_tags": ["financial", "destructive"],
    "provider_id": "ads",
    "cost_estimate": {"currency": "USD", "estimate": 0.02},
    "latency_estimate_ms": 400,
    "tenant": "public",
    "examples": [{"input": {"name": "LaunchX", "budget": 1000, "startDate": "2025-10-10"}}],
}

PIPEDRIVE_MANIFEST = {
    "toolId": "pipedrive:createDeal",
    "name": "Create Pipedrive Deal",
    "description": "Creates a new deal in Pipedrive CRM.",
    "inputs": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["title", "value"],
        "properties": {
            "title": {"type": "string", "minLength": 1, "maxLength": 255},
            "value": {"type": "number", "minimum": 0},
            "currency": {"type": "string", "default": "USD"},
            "person_id": {"type": "integer"},
            "org_id": {"type": "integer"},
        },
    },
    "outputs": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["dealId", "status", "title"],
        "properties": {
            "dealId": {"type": "integer"},
            "status": {"type": "string"},
            "title": {"type": "string"},
        },
    },
    "required_scopes": ["pipedrive.write"],
    "safety_tags": ["business"],
    "provider_id": "pipedrive",
    "cost_estimate": {"currency": "USD", "estimate": 0.01},
    "latency_estimate_ms": 500,
    "tenant": "public",
    "examples": [{"input": {"title": "New Sales Opportunity", "value": 5000, "currency": "USD"}}],
}

DATABASE_EXECUTE_MANIFEST = {
    "toolId": "database:executeQuery",
    "name": "Execute Database Query",
    "description": "Execute SQL query on SQLite database with security validation.",
    "inputs": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": 5000},
            "params": {"type": "array", "items": {"type": ["string", "number", "null"]}, "maxItems": 50}
        }
    },
    "outputs": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "rows": {"type": "array"},
            "columns": {"type": "array", "items": {"type": "string"}},
            "count": {"type": "integer"},
            "affected_rows": {"type": "integer"},
            "query": {"type": "string"},
            "type": {"type": "string", "enum": ["SELECT", "MODIFY"]},
            "last_row_id": {"type": ["integer", "null"]}
        }
    },
    "required_scopes": ["database.execute"],
    "safety_tags": ["data_access"],
    "provider_id": "database",
    "cost_estimate": {"currency": "USD", "estimate": 0.001},
    "latency_estimate_ms": 50,
    "tenant": "public",
    "examples": [
        {"input": {"query": "SELECT * FROM users LIMIT 10"}},
        {"input": {"query": "INSERT INTO users (name, email) VALUES (?, ?)", "params": ["Alice", "alice@example.com"]}}
    ]
}

DATABASE_TABLES_MANIFEST = {
    "toolId": "database:listTables",
    "name": "List Database Tables",
    "description": "List all tables in the SQLite database with row counts.",
    "inputs": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {},
        "additionalProperties": False
    },
    "outputs": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["tables", "count"],
        "properties": {
            "tables": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "type": {"type": "string"},
                        "row_count": {"type": "integer"}
                    }
                }
            },
            "count": {"type": "integer"}
        }
    },
    "required_scopes": ["database.read"],
    "safety_tags": ["data_access"],
    "provider_id": "database",
    "cost_estimate": {"currency": "USD", "estimate": 0.001},
    "latency_estimate_ms": 20,
    "tenant": "public",
    "examples": [{"input": {}}]
}

DATABASE_SCHEMA_MANIFEST = {
    "toolId": "database:getSchema",
    "name": "Get Table Schema",
    "description": "Get detailed schema information for a specific database table.",
    "inputs": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["table_name"],
        "properties": {
            "table_name": {"type": "string", "pattern": "^[a-zA-Z_][a-zA-Z0-9_]*$", "maxLength": 64}
        }
    },
    "outputs": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["table_name", "columns", "column_count"],
        "properties": {
            "table_name": {"type": "string"},
            "columns": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "type": {"type": "string"},
                        "not_null": {"type": "boolean"},
                        "default_value": {"type": ["string", "null"]},
                        "primary_key": {"type": "boolean"}
                    }
                }
            },
            "foreign_keys": {"type": "array"},
            "column_count": {"type": "integer"}
        }
    },
    "required_scopes": ["database.read"],
    "safety_tags": ["data_access"],
    "provider_id": "database",
    "cost_estimate": {"currency": "USD", "estimate": 0.001},
    "latency_estimate_ms": 10,
    "tenant": "public",
    "examples": [{"input": {"table_name": "users"}}]
}


async def discover_and_seed_mcp_tools() -> None:
    """Auto-discover MCP tools and register them"""
    try:
        from fastmcp.providers.base import get_adapter
        mcp_adapter = get_adapter("mcp")
        
        # Discover tools from all MCP servers
        discovered_tools = await mcp_adapter.discover_tools()
        
        # Register discovered tools
        with Session(engine) as session:
            for tool_manifest_dict in discovered_tools:
                tool_manifest = ToolManifest(**tool_manifest_dict)
                existing = session.get(Manifest, tool_manifest.toolId)
                if not existing:
                    session.add(
                        Manifest(
                            toolId=tool_manifest.toolId,
                            manifest=tool_manifest.model_dump(),
                            tenant=tool_manifest.tenant,
                            provider_id=tool_manifest.provider_id,
                        )
                    )
            session.commit()
            
        logger.info("mcp_discovery.complete", tools_discovered=len(discovered_tools))
        
    except Exception as e:
        logger.warning("mcp_discovery.failed", error=str(e))


def seed_database() -> None:
    SQLModel.metadata.create_all(engine)
    
    # Seed ads manifest
    manifest = ToolManifest(**SAMPLE_MANIFEST)
    with Session(engine) as session:
        existing = session.get(Manifest, manifest.toolId)
        if not existing:
            session.add(
                Manifest(
                    toolId=manifest.toolId,
                    manifest=manifest.model_dump(),
                    tenant=manifest.tenant,
                    provider_id=manifest.provider_id,
                )
            )
        
        # Seed pipedrive manifest
        pipedrive_manifest = ToolManifest(**PIPEDRIVE_MANIFEST)
        existing_pipedrive = session.get(Manifest, pipedrive_manifest.toolId)
        if not existing_pipedrive:
            session.add(
                Manifest(
                    toolId=pipedrive_manifest.toolId,
                    manifest=pipedrive_manifest.model_dump(),
                    tenant=pipedrive_manifest.tenant,
                    provider_id=pipedrive_manifest.provider_id,
                )
            )
        
        # Seed database manifests
        database_execute_manifest = ToolManifest(**DATABASE_EXECUTE_MANIFEST)
        existing_database_execute = session.get(Manifest, database_execute_manifest.toolId)
        if not existing_database_execute:
            session.add(
                Manifest(
                    toolId=database_execute_manifest.toolId,
                    manifest=database_execute_manifest.model_dump(),
                    tenant=database_execute_manifest.tenant,
                    provider_id=database_execute_manifest.provider_id,
                )
            )
        
        database_tables_manifest = ToolManifest(**DATABASE_TABLES_MANIFEST)
        existing_database_tables = session.get(Manifest, database_tables_manifest.toolId)
        if not existing_database_tables:
            session.add(
                Manifest(
                    toolId=database_tables_manifest.toolId,
                    manifest=database_tables_manifest.model_dump(),
                    tenant=database_tables_manifest.tenant,
                    provider_id=database_tables_manifest.provider_id,
                )
            )
        
        database_schema_manifest = ToolManifest(**DATABASE_SCHEMA_MANIFEST)
        existing_database_schema = session.get(Manifest, database_schema_manifest.toolId)
        if not existing_database_schema:
            session.add(
                Manifest(
                    toolId=database_schema_manifest.toolId,
                    manifest=database_schema_manifest.model_dump(),
                    tenant=database_schema_manifest.tenant,
                    provider_id=database_schema_manifest.provider_id,
                )
            )
        session.commit()


@app.on_event("startup")
async def on_startup() -> None:
    seed_database()
    # Auto-discover MCP tools after seeding static tools
    await discover_and_seed_mcp_tools()


@app.middleware("http")
async def correlation_middleware(request: Request, call_next):
    inbound = request.headers.get("X-Correlation-ID")
    if inbound:
        corr = correlation_id(value=inbound)
    else:
        corr = correlation_id(force_new=True)
    request.state.correlation_id = corr
    structlog.contextvars.bind_contextvars(corr_id=corr)
    try:
        response = await call_next(request)
    except Exception as exc:  # pragma: no cover - safety net
        logging.exception("Request failed", exc_info=exc)
        body = {"error": {"code": "INTERNAL", "message": "Internal server error", "corr_id": corr}}
        response = JSONResponse(status_code=500, content=body)
    finally:
        structlog.contextvars.clear_contextvars()
    response.headers["X-Correlation-ID"] = corr
    return response


@app.middleware("http")
async def otel_stub(request: Request, call_next):
    # Minimal OpenTelemetry hook placeholder.
    request.state.otel_span = f"span-{correlation_id()}"
    response = await call_next(request)
    return response
