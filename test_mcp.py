#!/usr/bin/env python3
"""Test MCP integration - minimal test for auto-discovered tools"""

import sys
import os
sys.path.insert(0, os.path.abspath('.'))

import requests
import time
from jose import jwt
from fastmcp.core.config import get_dev_crypto_material

# Generate JWT token with mcp-user role
_, private_key = get_dev_crypto_material()
now = int(time.time())

payload = {
    "iss": "https://idp.local",
    "aud": "fastmcp", 
    "sub": "mcp-agent",
    "tenant": "public",
    "roles": ["mcp-user"],
    "scopes": ["mcp.filesystem", "mcp.database", "mcp.git", "tools.invoke:write", "tools.query:catalog"],
    "iat": now,
    "exp": now + 3600
}

token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "dev-key"})
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

print("🔌 Testing FastMCP MCP Integration...")
print(f"Token: {token[:50]}...")

# Test catalog for MCP tools
print("\n1. Testing catalog for MCP tools...")
try:
    response = requests.get("http://localhost:8001/tool-catalog", headers=headers)
    print(f"Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        mcp_tools = [tool for tool in data['tools'] if tool['toolId'].startswith('mcp:')]
        
        print(f"✅ Found {len(mcp_tools)} MCP tools:")
        for tool in mcp_tools:
            print(f"  - {tool['toolId']}: {tool['name']}")
            
        if not mcp_tools:
            print("ℹ️  No MCP tools found. This means:")
            print("   - MCP servers are not running, or")
            print("   - MCP discovery failed during startup")
            print("   - Check server logs for discovery errors")
    else:
        print(f"❌ Catalog failed: {response.text}")
        
except Exception as e:
    print(f"❌ Error: {e}")

# Test MCP tool call (if any tools were discovered)
print("\n2. Testing MCP tool call...")
try:
    # Try to call a common MCP tool (this will fail if no MCP servers are running)
    response = requests.post(
        "http://localhost:8001/tools/mcp:filesystem:readFile/invoke",
        headers=headers,
        json={"path": "test.txt"}
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        print("✅ MCP tool call successful!")
    elif response.status_code == 404:
        print("ℹ️  Tool not found - MCP filesystem server not running")
    elif response.status_code == 403:
        print("ℹ️  Access denied - check RBAC configuration")
    else:
        print(f"❌ MCP tool call failed: {response.text}")
        
except Exception as e:
    print(f"❌ Error: {e}")

print("\n📋 How to add new MCP servers:")
print("1. Add to .env: MCP_NEWSERVER_URL=http://localhost:3004")
print("2. Restart FastMCP - tools auto-discovered!")
print("3. No code changes needed!")

print("\n🔧 To test with real MCP servers:")
print("1. Start MCP servers on ports 3001, 3002, 3003")
print("2. Restart FastMCP to discover tools")
print("3. Run this test again")
