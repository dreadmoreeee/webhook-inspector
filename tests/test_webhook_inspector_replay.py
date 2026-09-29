import socket
import time

from webhook_inspector.cli import main as cli_main
from webhook_inspector.replay import replay, replay_headers, strip_hop_by_hop
from webhook_inspector.signatures import VERIFIED, stripe_signature, verify

STRIPE_SECRET = "whsec_test_secret"
BODY = b'{"id": "evt_replay", "type": "invoice.paid", "amount": 4200}'


def _headers(captured):
    return {k.lower(): v for k, v in captured["headers"]}


def _store_stripe(client, t):
    headers = {"Stripe-Signature": stripe_signature(STRIPE_SECRET, BODY, t),
               "Content-Type": "application/json", "Connection": "keep-alive, X-Drop-Me",
               "X-Drop-Me": "1", "Keep-Alive": "timeout=5", "User-Agent": "Stripe/1.0 (+https://stripe.com)"}
    return client.post("/hooks/stripe?src=test", content=BODY, headers=headers).json()["id"]


def test_strip_hop_by_hop():
    headers = [("Host", "x"), ("Connection", "close, X-Custom"), ("X-Custom", "1"), ("TE", "trailers"),
               ("Transfer-Encoding", "chunked"), ("Content-Length", "3"), ("Upgrade", "h2c"),
               ("Keep-Alive", "5"), ("Content-Type", "a/b"), ("X-Keep", "yes")]
    assert strip_hop_by_hop(headers) == [("Content-Type", "a/b"), ("X-Keep", "yes")]


def test_receiving_never_replays_automatically(config, receiver, client):
    config.hooks["stripe"].replay_to = receiver.url + "/auto"
    _store_stripe(client, int(time.time()))
    client.get("/")
    time.sleep(0.2)
    assert receiver.captured == []


def test_replay_sends_original_request(client, receiver):
    rid = _store_stripe(client, int(time.time()))
    rec = client.app.state.store.get(rid)
    result = replay(rec, receiver.url + "/webhooks/stripe?x=1")
    assert (result.status_code, result.error) == (202, None)
    assert result.response_body == '{"received": true}'
    got = receiver.captured[0]
    assert got["method"] == "POST" and got["path"] == "/webhooks/stripe?x=1"
    assert got["body"] == BODY
    h = _headers(got)
    assert h["stripe-signature"] == rec.header("stripe-signature")      # untouched
    assert h["user-agent"] == "Stripe/1.0 (+https://stripe.com)"
    assert "x-drop-me" not in h and "keep-alive" not in h
    assert h["host"] == receiver.url.split("//")[1]                      # recomputed for the target
    assert h["content-length"] == str(len(BODY))


def test_stripe_resign_is_accepted_by_our_verifier(client, receiver):
    old = int(time.time()) - 3600
    rid = _store_stripe(client, old)
    rec = client.app.state.store.get(rid)
    assert rec.status == "invalid" and "tolerance" in rec.reason

    replay(rec, receiver.url)                                   # plain replay: still stale
    replay(rec, receiver.url, stripe_secret=STRIPE_SECRET)      # fresh t= and v1=
    stale, fresh = (_headers(c)["stripe-signature"] for c in receiver.captured)
    assert verify("stripe", STRIPE_SECRET, {"stripe-signature": stale}, BODY).status == "invalid"
    v = verify("stripe", STRIPE_SECRET, {"stripe-signature": fresh}, receiver.captured[1]["body"])
    assert v.status == VERIFIED, v.reason
    assert fresh.count("v1=") == 1 and int(fresh.split(",")[0][2:]) >= old + 3000


def test_resigned_headers_replace_signature_once(client):
    rec = client.app.state.store.get(_store_stripe(client, 1))
    headers = replay_headers(rec, stripe_secret=STRIPE_SECRET, now=1_790_000_000)
    sigs = [v for k, v in headers if k.lower() == "stripe-signature"]
    assert sigs == [stripe_signature(STRIPE_SECRET, BODY, 1_790_000_000)]


def test_replay_form_records_status_and_resign(client, receiver):
    rid = _store_stripe(client, int(time.time()) - 3600)
    r = client.post(f"/requests/{rid}/replay", data={"to": receiver.url + "/in", "resign": "1"},
                    headers={"Origin": "http://127.0.0.1"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/requests/{rid}#replays"
    got = receiver.captured[0]
    assert verify("stripe", STRIPE_SECRET, _headers(got), got["body"]).status == VERIFIED
    (rep,) = client.app.state.store.replays(rid)
    assert (rep.status_code, rep.resigned, rep.target) == (202, True, receiver.url + "/in")
    html = client.get(f"/requests/{rid}").text
    assert "<strong>202</strong>" in html and receiver.url + "/in" in html


def test_replay_api_and_errors(client, receiver):
    rid = client.post("/hooks/github", content=b"{}").json()["id"]
    r = client.post(f"/api/requests/{rid}/replay", json={"to": receiver.url})
    assert r.status_code == 200 and r.json()["status_code"] == 202
    # re-signing only makes sense for Stripe hooks
    r = client.post(f"/api/requests/{rid}/replay", json={"to": receiver.url, "resign_stripe": True})
    assert r.status_code == 400 and "cannot re-sign" in r.json()["detail"]
    r = client.post(f"/api/requests/{rid}/replay", json={"to": "file:///etc/passwd"})
    assert r.status_code == 400
    r = client.post(f"/requests/{rid}/replay", data={"to": "ftp://x"})
    assert r.status_code == 400 and "http://" in r.text
    assert len(receiver.captured) == 1


def test_replay_to_closed_port_records_error(client):
    rid = client.post("/hooks/plain", content=b"{}").json()["id"]
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    r = client.post(f"/api/requests/{rid}/replay", json={"to": f"http://127.0.0.1:{port}/"}).json()
    assert r["status_code"] is None and r["error"].startswith("ConnectError")
    assert client.app.state.store.replays(rid)[0].error


def test_cli_replay_and_list(client, receiver, config, capsys, tmp_path):
    rid = _store_stripe(client, int(time.time()) - 3600)
    cfg_file = tmp_path / "c.toml"
    cfg_file.write_text(
        f'db = "hooks.db"\n[hooks.stripe]\nprovider = "stripe"\nsecret = "{STRIPE_SECRET}"\n', encoding="utf-8")
    assert cli_main(["replay", str(rid), "--to", receiver.url + "/cli", "--resign",
                     "--config", str(cfg_file)]) == 0
    out = capsys.readouterr().out
    assert f"replay #{rid} -> {receiver.url}/cli (Stripe re-signed): HTTP 202" in out
    got = receiver.captured[0]
    assert verify("stripe", STRIPE_SECRET, _headers(got), got["body"]).status == VERIFIED

    assert cli_main(["list", "--db", config.db]) == 0
    assert "invalid" in capsys.readouterr().out
    assert cli_main(["replay", "999", "--to", receiver.url, "--db", config.db]) == 1
