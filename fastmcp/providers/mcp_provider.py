# MCP Provider - Minimal, scalable integration with external MCP servers
# Main functions: auto-discovery, JSON-RPC communication, dynamic tool registration
# Supports: Any MCP server via simple configuration

from __future__ import annotations

import json
import os
import uuid
from typing import Any, Dict, List
import asyncio

import httpx
from structlog import get_logger

from .base import ProviderAdapter, register_adapter

logger = get_logger(__name__)


class MCPProviderAdapter(ProviderAdapter):
    def __init__(self) -> None:
        super().__init__("mcp")
        # Simple server configuration - easy for juniors to extend
        self.servers = self._load_server_config()
        self.session_id = str(uuid.uuid4())
        logger.info("mcp_provider.init", servers=list(self.servers.keys()))

    def _load_server_config(self) -> Dict[str, str]:
        """Load MCP server configuration - super simple format"""
        # Option 1: Environment variables (simplest)
        servers = {}
        
        # Auto-discover from environment variables
        for key, value in os.environ.items():
            if key.startswith("MCP_") and key.endswith("_URL"):
                # MCP_FILESYSTEM_URL -> filesystem
                server_name = key[4:-4].lower()  # Remove MCP_ and _URL
                servers[server_name] = value
        
        # Option 2: Default servers if no env vars
        if not servers:
            servers = {
                "filesystem": "http://localhost:3001",
                "database": "http://localhost:3002", 
                "git": "http://localhost:3003"
            }
        
        return servers

    async def exchange(self, scopes: list[str], subject: str, tenant: str, purpose: str) -> dict:
        """Simple auth - MCP servers don't need complex auth"""
        return {
            "access_token": f"mcp_{self.session_id}",
            "token_type": "Bearer",
            "expires_in": 3600,
            "audience": "mcp"
        }

    async def call(self, endpoint: str, payload: dict) -> dict:
        """Route calls to MCP servers - format: server:tool"""
        try:
            # Parse endpoint: "filesystem:readFile"
            if ":" not in endpoint:
                raise ValueError(f"Invalid MCP endpoint format. Use 'server:tool', got: {endpoint}")
            
            server_name, tool_name = endpoint.split(":", 1)
            server_url = self.servers.get(server_name)
            
            if not server_url:
                available = ", ".join(self.servers.keys())
                raise ValueError(f"MCP server '{server_name}' not found. Available: {available}")
            
            return await self._call_mcp_server(server_url, tool_name, payload)
            
        except Exception as e:
            logger.error("mcp_provider.call_error", endpoint=endpoint, error=str(e))
            raise

    async def _call_mcp_server(self, server_url: str, tool_name: str, payload: dict) -> dict:
        """Make JSON-RPC call to MCP server"""
        request_id = str(uuid.uuid4())
        
        # Standard MCP JSON-RPC 2.0 request
        mcp_request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": payload
            }
        }
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{server_url}/mcp",
                    json=mcp_request,
                    headers={"Content-Type": "application/json"}
                )
                response.raise_for_status()
                
                result = response.json()
                
                # Handle MCP errors
                if "error" in result:
                    error = result["error"]
                    raise Exception(f"MCP Error [{error.get('code', 'unknown')}]: {error.get('message', 'Unknown error')}")
                
                logger.info("mcp_provider.call_success", 
                           server_url=server_url, 
                           tool=tool_name, 
                           request_id=request_id)
                
                return result.get("result", {})
                
        except httpx.RequestError as e:
            raise Exception(f"Failed to connect to MCP server {server_url}: {str(e)}")
        except httpx.HTTPStatusError as e:
            raise Exception(f"MCP server error {e.response.status_code}: {e.response.text}")

    async def discover_tools(self) -> List[Dict[str, Any]]:
        """Auto-discover tools from all MCP servers"""
        all_tools = []
        
        for server_name, server_url in self.servers.items():
            try:
                tools = await self._discover_server_tools(server_name, server_url)
                all_tools.extend(tools)
                logger.info("mcp_provider.discovery_success", 
                           server=server_name, 
                           tools_found=len(tools))
            except Exception as e:
                logger.warning("mcp_provider.discovery_failed", 
                              server=server_name, 
                              error=str(e))
        
        return all_tools

    async def _discover_server_tools(self, server_name: str, server_url: str) -> List[Dict[str, Any]]:
        """Discover tools from a single MCP server with retry/backoff"""
        max_attempts = int(os.getenv("MCP_DISCOVERY_RETRIES", "3"))
        backoff_ms = int(os.getenv("MCP_DISCOVERY_BACKOFF_MS", "500"))
        attempt = 1
        last_error: Exception | None = None

        while attempt <= max_attempts:
            request_id = str(uuid.uuid4())
            list_request = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/list",
            }

            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.post(
                        f"{server_url}/mcp",
                        json=list_request,
                        headers={"Content-Type": "application/json"},
                    )
                    response.raise_for_status()

                    result = response.json()
                    if "error" in result:
                        raise Exception(f"MCP list error: {result['error']}")

                    # Convert MCP tools to FastMCP manifests
                    mcp_tools = result.get("result", {}).get("tools", [])
                    manifests = []

                    for tool in mcp_tools:
                        manifest = self._create_manifest(server_name, tool)
                        manifests.append(manifest)

                    return manifests

            except Exception as e:
                last_error = e
                logger.warning(
                    "mcp_provider.discovery_retry",
                    server=server_name,
                    attempt=attempt,
                    max_attempts=max_attempts,
                    backoff_ms=backoff_ms,
                    error=str(e),
                )
                if attempt >= max_attempts:
                    break
                await asyncio.sleep(backoff_ms / 1000.0)
                backoff_ms *= 2  # exponential backoff
                attempt += 1

        raise Exception(
            f"Failed to discover tools from {server_name} after {max_attempts} attempts: {last_error}"
        )

    def _create_manifest(self, server_name: str, mcp_tool: dict) -> dict:
        """Convert MCP tool to FastMCP manifest - minimal but complete"""
        tool_name = mcp_tool.get("name", "unknown")
        
        return {
            "toolId": f"mcp:{server_name}:{tool_name}",
            "name": f"{server_name.title()} {tool_name}",
            "description": mcp_tool.get("description", f"MCP tool {tool_name} from {server_name} server"),
            "inputs": mcp_tool.get("inputSchema", {
                "type": "object",
                "properties": {},
                "additionalProperties": True
            }),
            "outputs": {
                "type": "object",
                "properties": {},
                "additionalProperties": True
            },
            "required_scopes": [f"mcp.{server_name}"],
            "safety_tags": ["mcp_external"],
            "provider_id": "mcp",
            "cost_estimate": {"currency": "USD", "estimate": 0.001},
            "latency_estimate_ms": 200,
            "tenant": "public",
            "examples": []
        }


# Auto-register on import
register_adapter(MCPProviderAdapter())
