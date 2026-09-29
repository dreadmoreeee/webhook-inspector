"""End to end: real uvicorn on a free port, the bundled example script, then a replay."""

import os
import re
import subprocess
import sys
from pathlib import Path

import httpx

from webhook_inspector.app import create_app
from webhook_inspector.config import load_config

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def test_examples_against_real_server(tmp_path, live_server):
    cfg = load_config(EXAMPLES / "config.toml")
    cfg.db = str(tmp_path / "e2e.db")
    base = live_server(create_app(cfg))

    env = dict(os.environ, PYTHONUTF8="1")
    out = subprocess.run([sys.executable, str(EXAMPLES / "send_test_webhooks.py"), "--base", base],
                         capture_output=True, text=True, timeout=60, env=env)
    assert out.returncode == 0, out.stderr
    lines = out.stdout.splitlines()
    assert len(lines) == 9
    expected = [
        ("stripe valid", "verified"), ("stripe two v1", "verified"),
        ("stripe expired", "invalid"), ("stripe tampered", "invalid"),
        ("github valid", "verified"), ("github wrong", "invalid"),
        ("shopify valid", "verified"), ("shopify no header", "unsigned"),
        ("plain", "unsigned"),
    ]
    for line, (label, status) in zip(lines, expected):
        assert line.startswith(label) and f" {status} " in line, line
    assert re.search(r"timestamp outside tolerance \(41[2-5]s > 300s\)", out.stdout)  # 412s + send time
    assert "v1 #2 of 2" in out.stdout

    with httpx.Client(base_url=base, timeout=10) as http:
        page = http.get("/")
        assert page.status_code == 200 and "9 stored requests" in page.text
        listing = http.get("/api/requests").json()
        expired = next(r for r in listing if r["reason"].startswith("timestamp outside"))
        assert "client_secret" in http.get(f"/requests/{expired['id']}").text
        assert "FakeFakeFake" not in http.get(f"/requests/{expired['id']}").text

        # Replay the expired Stripe event to the inspector itself, re-signed: now it verifies.
        r = http.post(f"/api/requests/{expired['id']}/replay",
                      json={"to": f"{base}/hooks/stripe-test", "resign_stripe": True})
        assert r.status_code == 200 and r.json()["status_code"] == 200
        assert '"verification":"verified"' in r.json()["response_body"]
        newest = http.get("/api/requests?limit=1").json()[0]
        assert (newest["hook"], newest["status"]) == ("stripe-test", "verified")
