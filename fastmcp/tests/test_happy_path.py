from pathlib import Path


def test_happy_path(client, auth_header, reset_state, settings):
    catalog = client.get("/tool-catalog", headers=auth_header)
    assert catalog.status_code == 200
    tools = catalog.json()["tools"]
    assert any(tool["toolId"] == "ads:createCampaign" for tool in tools)

    payload = {"name": "LaunchX", "budget": 1200, "startDate": "2025-10-10"}
    invoke = client.post("/tools/ads:createCampaign/invoke", headers=auth_header, json=payload)
    assert invoke.status_code == 202
    body = invoke.json()
    assert body["requires_confirmation"] is True
    action_token = body["action_token"]

    confirm_body = {"action_token": action_token, **payload}
    confirm = client.post("/tools/ads:createCampaign/confirm", headers=auth_header, json=confirm_body)
    assert confirm.status_code == 200
    result = confirm.json()
    assert result["result"]["status"] in {"CREATED", "CONFIRMED"}

    audit_dir = Path(settings.AUDIT_WORM_DIR)
    files = sorted(audit_dir.glob("audit-*.jsonl"))
    assert files, "expected audit file"
    lines = files[-1].read_text().strip().splitlines()
    actions = [__import__("json").loads(line)["action"] for line in lines]
    assert "tools.invoke" in actions
    assert "tools.confirm" in actions
