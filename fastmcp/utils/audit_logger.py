from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from structlog import get_logger

from fastmcp.core.config import get_settings
from fastmcp.core.security import correlation_id


logger = get_logger(__name__)


class AuditLogger:
    def __init__(self) -> None:
        settings = get_settings()
        self.base_path = Path(settings.AUDIT_WORM_DIR)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        self._prev_hash: Dict[Path, str] = {}

    async def emit(self, event: Dict[str, Any]) -> str:
        record = dict(event)
        record.setdefault("ts", dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"))
        record.setdefault("corr_id", correlation_id())

        log_path = self._log_path_for_ts(record["ts"])

        async with self._lock:
            prev_hash = await self._previous_hash(log_path)
            record["prev_hash"] = prev_hash
            payload = json.dumps(record, sort_keys=True)
            event_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            record["event_hash"] = event_hash
            await self._append_line(log_path, json.dumps(record, sort_keys=True))
            self._prev_hash[log_path] = event_hash
            logger.info(
                "audit.event",
                action=record.get("action"),
                toolId=record.get("toolId"),
                corr_id=record.get("corr_id"),
            )
            return event_hash

    def _log_path_for_ts(self, iso_ts: str) -> Path:
        day = iso_ts.split("T", 1)[0].replace("-", "")
        return self.base_path / f"audit-{day}.jsonl"

    async def _append_line(self, path: Path, line: str) -> None:
        await asyncio.to_thread(self._write_line, path, line)

    def _write_line(self, path: Path, line: str) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    async def _previous_hash(self, path: Path) -> str:
        cached = self._prev_hash.get(path)
        if cached:
            return cached
        if not path.exists():
            self._prev_hash[path] = ""
            return ""
        last_line = await asyncio.to_thread(self._read_last_line, path)
        if not last_line:
            self._prev_hash[path] = ""
            return ""
        try:
            data = json.loads(last_line)
            event_hash = data.get("event_hash", "")
            self._prev_hash[path] = event_hash
            return event_hash
        except json.JSONDecodeError:
            return ""

    def _read_last_line(self, path: Path) -> str:
        last = ""
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if line:
                    last = line
        return last


audit_logger = AuditLogger()


async def log_audit_event(event: Dict[str, Any]) -> str:
    return await audit_logger.emit(event)
