import datetime as dt

from sqlmodel import Session, select

from fastmcp.db.schemas_sqlmodel import ConfirmationRequest
from fastmcp.db.session import engine


def test_confirmation_flow_errors(client, auth_header, reset_state):
    payload = {"name": "LaunchX", "budget": 1200, "startDate": "2025-10-10"}
    invoke = client.post("/tools/ads:createCampaign/invoke", headers=auth_header, json=payload)
    token = invoke.json()["action_token"]

    wrong = client.post(
        "/tools/ads:createCampaign/confirm",
        headers=auth_header,
        json={"action_token": "bad-token", **payload},
    )
    assert wrong.status_code == 401

    with Session(engine) as session:
        confirmation = session.exec(
            select(ConfirmationRequest).where(ConfirmationRequest.action_token == token)
        ).first()
        confirmation.expires_at = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(seconds=1)
        session.add(confirmation)
        session.commit()

    expired = client.post(
        "/tools/ads:createCampaign/confirm",
        headers=auth_header,
        json={"action_token": token, **payload},
    )
    assert expired.status_code == 409
    assert expired.json()["error"]["code"] == "CONFLICT"
