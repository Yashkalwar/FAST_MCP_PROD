import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from sqlmodel import Session, delete

from fastmcp.core.config import get_dev_crypto_material, get_settings
from fastmcp.db.schemas_sqlmodel import ConfirmationRequest, IdempotencyRecord, Manifest
from fastmcp.db.session import engine
from fastmcp.main import SAMPLE_MANIFEST, app, seed_database


@pytest.fixture(scope="session")
def settings():
    return get_settings()


@pytest.fixture(scope="session")
def client(settings):
    seed_database()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def reset_state(settings):
    # Reset db tables and manifest to default sample
    with Session(engine) as session:
        session.exec(delete(IdempotencyRecord))
        session.exec(delete(ConfirmationRequest))
        manifest = session.get(Manifest, SAMPLE_MANIFEST["toolId"])
        if manifest:
            manifest.manifest = json.loads(json.dumps(SAMPLE_MANIFEST))
            manifest.tenant = SAMPLE_MANIFEST["tenant"]
            manifest.provider_id = SAMPLE_MANIFEST["provider_id"]
            session.add(manifest)
        session.commit()
    audit_dir = Path(settings.AUDIT_WORM_DIR)
    if audit_dir.exists():
        for file in audit_dir.glob("audit-*.jsonl"):
            file.unlink()
    yield


def make_agent_jwt(sub="agent-1", roles=None, scopes=None, tenant="public"):
    roles = roles or []
    scopes = scopes or []
    settings = get_settings()
    _, pem = get_dev_crypto_material()
    payload = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "sub": sub,
        "tenant": tenant,
        "roles": roles,
        "scopes": scopes,
    }
    token = jwt.encode(payload, pem, algorithm=settings.JWT_ALG, headers={"kid": "dev-key"})
    return token


@pytest.fixture
def auth_header():
    token = make_agent_jwt(roles=["finance-write"], scopes=["ads.write", "tools.invoke:write", "tools.query:catalog"])
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def agent_header():
    token = make_agent_jwt(roles=["agent"], scopes=["tools.invoke:read"])
    return {"Authorization": f"Bearer {token}"}
