# FastMCP

FastMCP is a production-shaped orchestration plane for enterprise agent tooling. It wires manifests, RBAC/ABAC enforcement, confirmation gates, token brokering, rate limits, and immutable audit trails on top of FastAPI.

## Prerequisites

- Python 3.12
- OpenSSL (optional, to inspect the generated JWKS)

## Quickstart

```bash
# create and hydrate a virtualenv
python3 -m venv .venv --without-pip
.venv/bin/python get-pip.py
.venv/bin/pip install fastapi uvicorn sqlmodel pydantic pydantic-settings "python-jose[cryptography]" \
  cryptography httpx tenacity structlog redis jsonschema python-dotenv opentelemetry-api \
  opentelemetry-sdk pyyaml pytest anyio

# run the API
PYTHONPATH=. .venv/bin/python -m uvicorn fastmcp.main:app --reload
```

Startup generates a development RSA keypair (`.runtime/dev-jwks.*`), seeds the sample manifest, and loads policies from `policies/policies.yml`.

## Sample JWT (dev only)

Use this finance operator token in the `Authorization` header when exploring locally:

```
eyJhbGciOiJSUzI1NiIsImtpZCI6ImRldi1rZXkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2lkcC5sb2NhbCIsImF1ZCI6ImZhc3RtY3AiLCJzdWIiOiJhZ2VudC0xIiwidGVuYW50IjoicHVibGljIiwicm9sZXMiOlsiZmluYW5jZS13cml0ZSJdLCJzY29wZXMiOlsiYWRzLndyaXRlIiwidG9vbHMuaW52b2tlOndyaXRlIiwidG9vbHMucXVlcnk6Y2F0YWxvZyJdfQ.iD5iBw7VONjaQDq66jAKcCI9iRe92mssrxeiQY5NlqW_T5Cc0HAi6EEYXMkPId3Kk5oIKpLev64mUrFSai19lZfYo7x1w26QJLkFeNUrodjw60hCFZ86HvMA-CDVOvZmsX5nPZ4tVNPmwjozKqsn5bnWiiPsns60vp580fa21jkBN99Urz58Sn7UDjEifwiEegC7-xNiH9c-crSVwlAN9yZCppjuy-eEcDai96UGRYkW99QyQVBGpAGPdKE9DCVB3KXqoXbBCgWC-r_o-mnajNTYqTY7lrJVhWHVKca7alknVB-ltNtB7gODjFPwXqh9asxTLPIKs8WYTPxYaJrEUA
```

## cURL walkthrough

```bash
AUTH="Authorization: Bearer <paste-token>"

# catalog (RBAC enforced)
curl -s -H "$AUTH" http://localhost:8000/tool-catalog | jq

# invoke destructive tool – requires confirmation
curl -s -X POST -H "$AUTH" \
  -H "Content-Type: application/json" \
  http://localhost:8000/tools/ads:createCampaign/invoke \
  -d '{"name":"LaunchX","budget":1200,"startDate":"2025-10-10"}'

# confirm once humans approve
curl -s -X POST -H "$AUTH" \
  -H "Content-Type: application/json" \
  http://localhost:8000/tools/ads:createCampaign/confirm \
  -d '{"action_token":"<token-from-invoke>","name":"LaunchX","budget":1200,"startDate":"2025-10-10"}'

# drop a health probe
curl -s http://localhost:8000/health
```

Audit events stream to `.audit/audit-YYYYMMDD.jsonl` with hash chaining and correlation ids; the confirmation pathway emits paired `tools.invoke` and `tools.confirm` entries.

## Tests

```bash
PYTHONPATH=. .venv/bin/python -m pytest -q fastmcp/tests
```

Suite coverage:

- `test_happy_path.py` – catalog → invoke (202) → confirm (200) with audit verification
- `test_policy_denial.py` – RBAC denial for agents lacking `finance-write`
- `test_confirmation_flow.py` – invalid or expired confirmation tokens are rejected
- `test_idempotency.py` – repeated invoke with the same `Idempotency-Key` replays the cached result

## Notes

- JWKS + RSA private key live under `.runtime/`; deleting them forces regeneration.
- Policies can be reloaded with `SIGHUP` and include confirmation hints.
- Rate limiting defaults to in-memory buckets; set `REDIS_URL` for Redis-backed tokens.
- Logs use `structlog` JSON with correlation ids and never include provider secrets.
