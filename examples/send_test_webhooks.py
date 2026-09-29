"""Send signed test webhooks to a local webhook-inspector.

Standard library only, and it signs payloads with its own HMAC code (not the
package's), so it also cross-checks the verifier.

    python -m webhook_inspector serve --config examples/config.toml
    python examples/send_test_webhooks.py --base http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.request
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

HERE = Path(__file__).resolve().parent


def sig(secret: str, message: bytes) -> bytes:
    return hmac.new(secret.encode(), message, hashlib.sha256).digest()


def stripe_header(secret: str, body: bytes, t: int, extra_v1: str | None = None) -> str:
    v1 = sig(secret, f"{t}.".encode() + body).hex()
    return f"t={t},v1={extra_v1},v1={v1}" if extra_v1 else f"t={t},v1={v1}"


def post(base: str, hook: str, body: bytes, headers: dict[str, str]) -> dict:
    req = urllib.request.Request(f"{base}/hooks/{hook}", data=body, method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--config", default=str(HERE / "config.toml"))
    args = parser.parse_args()

    hooks = tomllib.loads(Path(args.config).read_text(encoding="utf-8"))["hooks"]
    stripe_secret = hooks["stripe-test"]["secret"]
    github_secret = hooks["github-test"]["secret"]
    shopify_secret = hooks["shopify-test"]["secret"]
    stripe = (HERE / "payloads" / "stripe_payment_intent_succeeded.json").read_bytes()
    github = (HERE / "payloads" / "github_push.json").read_bytes()
    shopify = (HERE / "payloads" / "shopify_orders_create.json").read_bytes()
    now = int(time.time())

    cases = [
        ("stripe valid", "stripe-test", stripe, {"Stripe-Signature": stripe_header(stripe_secret, stripe, now)}),
        ("stripe two v1 (rotated)", "stripe-test", stripe,
         {"Stripe-Signature": stripe_header(stripe_secret, stripe, now, extra_v1="00" * 32)}),
        ("stripe expired", "stripe-test", stripe,
         {"Stripe-Signature": stripe_header(stripe_secret, stripe, now - 412)}),
        ("stripe tampered body", "stripe-test", stripe.replace(b"11498", b"1"),
         {"Stripe-Signature": stripe_header(stripe_secret, stripe, now)}),
        ("github valid", "github-test", github,
         {"X-Hub-Signature-256": "sha256=" + sig(github_secret, github).hex(), "X-GitHub-Event": "push"}),
        ("github wrong secret", "github-test", github,
         {"X-Hub-Signature-256": "sha256=" + sig("not-the-secret", github).hex(), "X-GitHub-Event": "push"}),
        ("shopify valid", "shopify-test", shopify,
         {"X-Shopify-Hmac-Sha256": base64.b64encode(sig(shopify_secret, shopify)).decode(),
          "X-Shopify-Topic": "orders/create"}),
        ("shopify no header", "shopify-test", shopify, {"X-Shopify-Topic": "orders/create"}),
        ("plain (no provider)", "plain", b'{"hello": "world", "api_key": "abc123"}', {}),
    ]
    for label, hook, body, headers in cases:
        ack = post(args.base, hook, body, headers)
        print(f"{label:24} -> #{ack['id']:<3} {ack['verification']:9} {ack['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
