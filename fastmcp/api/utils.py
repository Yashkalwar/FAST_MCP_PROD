from __future__ import annotations

import hashlib
import json
from typing import Any, Dict


def hash_payload(data: Dict[str, Any]) -> str:
    normalized = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def error_response(code: str, message: str, status_code: int, corr_id: str, details: dict | None = None):
    from fastapi.responses import JSONResponse

    body = {"error": {"code": code, "message": message, "corr_id": corr_id}}
    if details:
        body["error"]["details"] = details
    return JSONResponse(status_code=status_code, content=body)

