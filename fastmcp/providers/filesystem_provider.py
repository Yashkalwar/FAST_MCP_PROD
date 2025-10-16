# Filesystem Provider - Safe, sandboxed file operations
from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any, Dict, List

import asyncio
from structlog import get_logger

from .base import ProviderAdapter, register_adapter

logger = get_logger(__name__)


class FilesystemProviderAdapter(ProviderAdapter):
    def __init__(self) -> None:
        super().__init__("filesystem")
        root_env = os.getenv("FILESYSTEM_ROOT", "./data/files/")
        self.root = Path(root_env).expanduser().resolve()
        self.max_file_mb = int(os.getenv("FILESYSTEM_MAX_FILE_MB", "10"))
        self.max_depth = int(os.getenv("FILESYSTEM_MAX_DEPTH", "8"))
        self.root.mkdir(parents=True, exist_ok=True)
        logger.info("filesystem_provider.init", root=str(self.root))

    # Tool router
    async def call(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if endpoint == "listDirectory":
            return await self.list_directory(payload)
        if endpoint == "readFile":
            return await self.read_file(payload)
        if endpoint == "writeFile":
            return await self.write_file(payload)
        raise ValueError(f"unsupported endpoint: {endpoint}")

    # Helpers
    def _resolve(self, rel_path: str) -> Path:
        # Normalize absolute-style '/' to relative
        rel = rel_path.lstrip("/\\")
        target = (self.root / rel).resolve()
        if not str(target).startswith(str(self.root)):
            raise ValueError("Path escapes sandbox root")
        return target

    def _enforce_depth(self, path: Path) -> None:
        try:
            rel = path.relative_to(self.root)
        except Exception:
            raise ValueError("Invalid path")
        depth = len(rel.parts)
        if depth > self.max_depth:
            raise ValueError("Path exceeds maximum depth")

    # Tools
    async def list_directory(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        path = payload.get("path", "/")
        recursive = bool(payload.get("recursive", False))
        p = self._resolve(path)
        self._enforce_depth(p)

        def _list() -> Dict[str, Any]:
            if not p.exists():
                raise ValueError("Path not found")
            if not p.is_dir():
                raise ValueError("Path is not a directory")
            entries: List[Dict[str, Any]] = []
            if recursive:
                for root, dirs, files in os.walk(p):
                    for name in dirs + files:
                        fp = Path(root) / name
                        rel = fp.relative_to(self.root).as_posix()
                        info = {
                            "path": "/" + rel,
                            "type": "directory" if fp.is_dir() else "file",
                            "size": fp.stat().st_size if fp.is_file() else None,
                            "modified": int(fp.stat().st_mtime),
                        }
                        entries.append(info)
            else:
                for fp in p.iterdir():
                    rel = fp.relative_to(self.root).as_posix()
                    info = {
                        "path": "/" + rel,
                        "type": "directory" if fp.is_dir() else "file",
                        "size": fp.stat().st_size if fp.is_file() else None,
                        "modified": int(fp.stat().st_mtime),
                    }
                    entries.append(info)
            logger.info("filesystem_provider.list_directory", count=len(entries))
            return {"entries": entries, "count": len(entries)}

        return await asyncio.to_thread(_list)

    async def read_file(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        path = payload["path"]
        as_base64 = bool(payload.get("as_base64", False))
        p = self._resolve(path)
        self._enforce_depth(p)

        def _read() -> Dict[str, Any]:
            if not p.exists() or not p.is_file():
                raise ValueError("File not found")
            data = p.read_bytes()
            if as_base64:
                b64 = base64.b64encode(data).decode("ascii")
                return {"content_base64": b64, "size": len(data)}
            # try utf-8, fallback to base64
            try:
                text = data.decode("utf-8")
                return {"content": text, "encoding": "utf-8", "size": len(data)}
            except UnicodeDecodeError:
                b64 = base64.b64encode(data).decode("ascii")
                return {"content_base64": b64, "size": len(data)}

        return await asyncio.to_thread(_read)

    async def write_file(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        path = payload["path"]
        overwrite = bool(payload.get("overwrite", False))
        content = payload.get("content")
        content_b64 = payload.get("content_base64")
        encoding = payload.get("encoding", "utf-8")
        p = self._resolve(path)
        self._enforce_depth(p)
        p.parent.mkdir(parents=True, exist_ok=True)

        def _write() -> Dict[str, Any]:
            if p.exists() and not overwrite:
                raise ValueError("File exists; set overwrite=true to replace")
            if content_b64 is not None:
                data = base64.b64decode(content_b64)
            elif content is not None:
                data = content.encode(encoding)
            else:
                raise ValueError("Provide content or content_base64")
            max_bytes = self.max_file_mb * 1024 * 1024
            if len(data) > max_bytes:
                raise ValueError("File exceeds max size limit")
            p.write_bytes(data)
            logger.info("filesystem_provider.write_file", path=str(p), size=len(data))
            rel = p.relative_to(self.root).as_posix()
            return {"written": True, "size": len(data), "path": "/" + rel}

        return await asyncio.to_thread(_write)


register_adapter(FilesystemProviderAdapter())
