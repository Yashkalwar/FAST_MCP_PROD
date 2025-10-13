from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

import yaml

from fastmcp.models.tool_manifest import ToolManifest


DEFAULT_DENY_PATTERNS = [r"admin", r"internal"]


def _load_spec(path: Path) -> Dict[str, Any]:
    content = path.read_text("utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(content)
    return json.loads(content)


def ingest_openapi(
    path: Path,
    provider_id: str,
    tenant: str,
    deny_patterns: List[str] | None = None,
) -> List[ToolManifest]:
    patterns = [re.compile(pat) for pat in (deny_patterns or DEFAULT_DENY_PATTERNS)]
    spec = _load_spec(path)
    manifests: List[ToolManifest] = []

    for route, methods in (spec.get("paths") or {}).items():
        for http_method, operation in (methods or {}).items():
            if not isinstance(operation, dict):
                continue
            operation_id = operation.get("operationId")
            if not operation_id:
                continue
            if any(pattern.search(operation_id) for pattern in patterns):
                continue

            name = operation.get("summary") or operation_id
            description = operation.get("description") or f"Auto generated tool for {operation_id}"
            input_schema = operation.get("requestBody", {}).get("content", {}).get("application/json", {}).get(
                "schema", {"type": "object"}
            )
            output_schema = operation.get("responses", {}).get("200", {}).get("content", {}).get(
                "application/json", {}
            ).get("schema", {"type": "object"})

            manifest = ToolManifest(
                toolId=f"{provider_id}:{operation_id}",
                name=name,
                description=description,
                inputs=input_schema,
                outputs=output_schema,
                required_scopes=operation.get("x-required-scopes", []),
                safety_tags=["unknown"],
                provider_id=provider_id,
                cost_estimate={"currency": "USD", "estimate": 0.0},
                latency_estimate_ms=1000,
                tenant=tenant,
                examples=[],
                manual_review_required=True,
                http_method=http_method.upper(),
                route=route,
            )
            manifests.append(manifest)
    return manifests

