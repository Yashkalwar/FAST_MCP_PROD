from __future__ import annotations

from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType


def _load_module() -> ModuleType:
    source_path = Path(__file__).with_name("schemas.sqlmodel")
    loader = SourceFileLoader("fastmcp.db.schemas_data", str(source_path))
    module = loader.load_module()  # type: ignore[attr-defined]
    return module


_schemas = _load_module()

Manifest = getattr(_schemas, "Manifest")
IdempotencyRecord = getattr(_schemas, "IdempotencyRecord")
ConfirmationRequest = getattr(_schemas, "ConfirmationRequest")
AuditEventRow = getattr(_schemas, "AuditEventRow")

__all__ = [
    "Manifest",
    "IdempotencyRecord",
    "ConfirmationRequest",
    "AuditEventRow",
]
