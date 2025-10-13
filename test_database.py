#!/usr/bin/env python3
"""Test Database integration directly"""

import sys
import os
sys.path.insert(0, os.path.abspath('.'))

import requests
import time
import json
from jose import jwt
from fastmcp.core.config import get_dev_crypto_material

# Generate proper JWT token with data-analyst role
_, private_key = get_dev_crypto_material()
now = int(time.time())

payload = {
    "iss": "https://idp.local",
    "aud": "fastmcp", 
    "sub": "data-agent",
    "tenant": "public",
    "roles": ["data-analyst"],
    "scopes": ["database.read", "database.execute", "tools.invoke:write", "tools.query:catalog"],
    "iat": now,
    "exp": now + 3600
}

token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "dev-key"})
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# Ensure UTF-8 capable stdout and avoid emojis for Windows consoles
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

print("Testing FastMCP Database Integration...")
print(f"Token (truncated): {token[:24]}...")

# Test catalog
print("\n1. Testing catalog...")
try:
    response = requests.get("http://localhost:8001/tool-catalog", headers=headers)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Found {len(data['tools'])} tools")
        for tool in data['tools']:
            if 'database' in tool['toolId']:
                print(f"  - {tool['toolId']}: {tool['name']}")
    else:
        print(f"Error: {response.text}")
except Exception as e:
    print(f"Error: {e}")

# Test list tables
print("\n2. Testing database:listTables...")
try:
    response = requests.post(
        "http://localhost:8001/tools/database:listTables/invoke",
        headers=headers,
        json={}
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        result = response.json()
        print(f"[OK] Found {result.get('result', {}).get('count', 0)} tables")
        for table in result.get('result', {}).get('tables', []):
            print(f"  - {table['name']}: {table['row_count']} rows")
    else:
        print(f"[ERR] Failed: {response.text}")
        
except Exception as e:
    print(f"Error: {e}")

# Test get schema
print("\n3. Testing database:getSchema...")
try:
    response = requests.post(
        "http://localhost:8001/tools/database:getSchema/invoke",
        headers=headers,
        json={"table_name": "users"}
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        result = response.json()
        schema = result.get('result', {})
        print(f"✅ Table '{schema.get('table_name')}' has {schema.get('column_count')} columns")
        for col in schema.get('columns', []):
            print(f"  - {col['name']}: {col['type']} {'(PK)' if col['primary_key'] else ''}")
    else:
        print(f"❌ Failed: {response.text}")
        
except Exception as e:
    print(f"Error: {e}")

# Test execute query - SELECT
print("\n4. Testing database:executeQuery (SELECT)...")
try:
    response = requests.post(
        "http://localhost:8001/tools/database:executeQuery/invoke",
        headers=headers,
        json={"query": "SELECT * FROM users LIMIT 5"}
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        result = response.json()
        query_result = result.get('result', {})
        print(f"✅ Query returned {query_result.get('count')} rows")
        for row in query_result.get('rows', []):
            print(f"  - {row}")
    else:
        print(f"❌ Failed: {response.text}")
        
except Exception as e:
    print(f"Error: {e}")

# Test execute query - INSERT (will fail for data-analyst, need data-admin)
print("\n5. Testing database:executeQuery (INSERT - should fail for data-analyst)...")
try:
    response = requests.post(
        "http://localhost:8001/tools/database:executeQuery/invoke",
        headers=headers,
        json={
            "query": "INSERT INTO users (name, email) VALUES (?, ?)",
            "params": ["Test User", "test@example.com"]
        }
    )
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Insert successful: {result}")
    else:
        print(f"❌ Expected failure (data-analyst can't write): {response.text}")
        
except Exception as e:
    print(f"Error: {e}")

print("\n6. Check audit logs in .audit/ directory")
print("\n7. To test INSERT/UPDATE/DELETE, generate token with 'data-admin' role")
