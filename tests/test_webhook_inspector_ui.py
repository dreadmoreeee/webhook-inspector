import json
import time

from fastapi.testclient import TestClient

from webhook_inspector.app import create_app
from webhook_inspector.signatures import github_signature, stripe_signature

STRIPE_SECRET = "whsec_test_secret"
GITHUB_SECRET = "gh-test-secret"
BODY = json.dumps({
    "id": "evt_1", "type": "payment_intent.succeeded",
    "data": {"object": {"amount": 1000, "client_secret": "pi_1_secret_SHOULDHIDE",
                        "metadata": {"accessToken": "tok_SHOULDHIDE", "tokenization_method": "apple_pay"}}},
}).encode()


def _post_stripe(client, body=BODY, t=None):
    headers = {"Stripe-Signature": stripe_signature(STRIPE_SECRET, body, t), "Content-Type": "application/json",
               "Authorization": "Bearer SHOULDHIDE-auth", "Cookie": "session=SHOULDHIDE-cookie",
               "X-Api-Key": "SHOULDHIDE-apikey", "User-Agent": "Stripe/1.0"}
    return client.post("/hooks/stripe?debug=1&api_key=SHOULDHIDE-query", content=body, headers=headers)


def test_receive_stores_everything_and_acks(client):
    r = _post_stripe(client)
    assert r.status_code == 200
    ack = r.json()
    assert ack["ok"] is True and ack["hook"] == "stripe" and ack["verification"] == "verified"
    rec = client.app.state.store.get(ack["id"])
    assert rec.method == "POST" and rec.path == "/hooks/stripe"
    assert rec.query == "debug=1&api_key=SHOULDHIDE-query"
    assert rec.body == BODY
    assert rec.header("user-agent") == "Stripe/1.0"
    assert rec.client_ip
    assert abs(rec.received_at - time.time()) < 60


def test_any_method_and_statuses(client):
    assert client.put("/hooks/plain", content=b"x").json()["verification"] == "unsigned"
    assert client.get("/hooks/github").json()["reason"] == "X-Hub-Signature-256 header missing"
    assert client.delete("/hooks/nosecret").json()["verification"] == "no-secret"
    ack = client.patch("/hooks/unknown-hook", content=b"{}").json()
    assert (ack["verification"], ack["reason"]) == ("unsigned", "hook not in config")
    old = _post_stripe(client, t=int(time.time()) - 412).json()
    assert old["verification"] == "invalid" and old["reason"].startswith("timestamp outside tolerance")


def test_unknown_hooks_can_be_refused_and_big_bodies_rejected(config):
    config.allow_unknown_hooks = False
    config.max_body_bytes = 10
    with TestClient(create_app(config)) as c:
        assert c.post("/hooks/nope", content=b"{}").status_code == 404
        assert c.post("/hooks/plain", content=b"x" * 11).status_code == 413
        assert c.app.state.store.count() == 0


def test_list_page(client):
    _post_stripe(client)
    body = b'{"a": 1}'
    client.post("/hooks/github", content=body, headers={"X-Hub-Signature-256": github_signature("wrong", body)})
    page = client.get("/")
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    html = page.text
    assert "2 stored requests" in html
    assert 'class="badge verified"' in html and 'class="badge invalid"' in html
    assert "signature mismatch" in html
    assert f"{len(BODY)} B" in html
    only = client.get("/?hook=github").text
    assert "/requests/2" in only and "/requests/1\"" not in only


def test_detail_page_redacts_by_default(client):
    rid = _post_stripe(client).json()["id"]
    html = client.get(f"/requests/{rid}").text
    assert "SHOULDHIDE" not in html
    assert "[redacted]" in html
    assert "payment_intent.succeeded" in html          # body is shown, pretty-printed
    assert "&#34;amount&#34;: 1000" in html or '"amount": 1000' in html
    assert "apple_pay" in html                         # tokenization_method is not a secret
    assert "v1 signature matches" in html
    assert "debug" in html                             # query table


def test_detail_page_reveal(client):
    rid = _post_stripe(client).json()["id"]
    html = client.get(f"/requests/{rid}?reveal=1").text
    for secret in ("pi_1_secret_SHOULDHIDE", "tok_SHOULDHIDE", "Bearer SHOULDHIDE-auth",
                   "session=SHOULDHIDE-cookie", "SHOULDHIDE-apikey", "SHOULDHIDE-query", "t="):
        assert secret in html
    assert "Hide secrets" in html


def test_detail_escapes_html_and_handles_binary(client):
    rid = client.post("/hooks/plain", content=b"<script>alert(1)</script>",
                      headers={"Content-Type": "text/plain"}).json()["id"]
    assert "<script>alert(1)</script>" not in client.get(f"/requests/{rid}").text
    rid = client.post("/hooks/plain", content=b"\xff\xfe\x00binary").json()["id"]
    assert "shown as base64" in client.get(f"/requests/{rid}").text


def test_form_bodies_are_redacted(client):
    rid = client.post("/hooks/plain", content=b"user=bob&password=hunter2",
                      headers={"Content-Type": "application/x-www-form-urlencoded"}).json()["id"]
    assert "hunter2" not in client.get(f"/requests/{rid}").text
    assert "hunter2" in client.get(f"/requests/{rid}?reveal=1").text


def test_api_detail_redaction(client):
    rid = _post_stripe(client).json()["id"]
    red = client.get(f"/api/requests/{rid}").json()
    assert "SHOULDHIDE" not in json.dumps(red)
    assert red["verification"]["status"] == "verified"
    full = client.get(f"/api/requests/{rid}?reveal=1").json()
    assert full["body"].encode() == BODY
    assert client.get("/api/requests").json()[0]["id"] == rid
    assert client.get("/api/requests/999").status_code == 404
    assert client.get("/requests/999").status_code == 404


def test_ui_refuses_unexpected_host(config):
    with TestClient(create_app(config), base_url="http://evil.example") as c:
        assert c.get("/").status_code == 403
        assert c.post("/hooks/plain", content=b"{}").status_code == 200  # receiver stays open


def test_replay_form_refuses_cross_site_posts(client):
    rid = client.post("/hooks/plain", content=b"{}").json()["id"]
    r = client.post(f"/requests/{rid}/replay", data={"to": "http://127.0.0.1:9/"},
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403
    r = client.post(f"/requests/{rid}/replay", data={"to": "http://127.0.0.1:9/"},
                    headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    assert client.app.state.store.replays(rid) == []
