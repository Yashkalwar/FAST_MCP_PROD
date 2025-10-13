import secrets

from sqlmodel import Session

from fastmcp.db.schemas_sqlmodel import Manifest
from fastmcp.db.session import engine


def test_idempotent_invoke_without_confirmation(client, auth_header, reset_state):
    with Session(engine) as session:
        manifest_row = session.get(Manifest, "ads:createCampaign")
        data = dict(manifest_row.manifest)
        data["safety_tags"] = []
        manifest_row.manifest = data
        session.add(manifest_row)
        session.commit()

    payload = {"name": "Quick", "budget": 200, "startDate": "2025-10-11"}
    idem_key = secrets.token_hex(8)
    headers = {**auth_header, "Idempotency-Key": idem_key}

    first = client.post("/tools/ads:createCampaign/invoke", headers=headers, json=payload)
    assert first.status_code == 200
    body = first.json()
    assert "result" in body

    second = client.post("/tools/ads:createCampaign/invoke", headers=headers, json=payload)
    assert second.status_code == 200
    assert second.headers.get("X-Idempotent-Replay") == "true"
    assert second.json() == body
