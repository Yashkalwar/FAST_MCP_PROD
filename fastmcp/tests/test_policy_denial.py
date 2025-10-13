def test_policy_denial(client, agent_header, reset_state):
    payload = {"name": "LaunchX", "budget": 1200, "startDate": "2025-10-10"}
    resp = client.post("/tools/ads:createCampaign/invoke", headers=agent_header, json=payload)
    assert resp.status_code == 403
    body = resp.json()
    assert body["error"]["code"] == "FORBIDDEN"
