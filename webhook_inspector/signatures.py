"""Signature schemes for Stripe, GitHub and Shopify webhooks.

All comparisons go through hmac.compare_digest. `headers` arguments are
mappings with lower-case header names.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from collections.abc import Mapping
from dataclasses import dataclass

VERIFIED = "verified"
INVALID = "invalid"
UNSIGNED = "unsigned"
NO_SECRET = "no-secret"

SIGNATURE_HEADERS = {
    "stripe": "stripe-signature",
    "github": "x-hub-signature-256",
    "shopify": "x-shopify-hmac-sha256",
}


@dataclass(frozen=True)
class Verification:
    status: str
    reason: str


def _hmac_sha256(secret: str, message: bytes) -> bytes:
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8", "replace"), b.encode("utf-8", "replace"))


# -- signing (used by replay re-signing and by tests) -----------------------

def stripe_signature(secret: str, body: bytes, timestamp: int | None = None) -> str:
    """Build a Stripe-Signature header value: "t=<unix>,v1=<hex>"."""
    t = int(time.time()) if timestamp is None else int(timestamp)
    v1 = _hmac_sha256(secret, f"{t}.".encode("ascii") + body).hex()
    return f"t={t},v1={v1}"


def github_signature(secret: str, body: bytes) -> str:
    return "sha256=" + _hmac_sha256(secret, body).hex()


def shopify_signature(secret: str, body: bytes) -> str:
    return base64.b64encode(_hmac_sha256(secret, body)).decode("ascii")


# -- verification ------------------------------------------------------------

def verify(
    provider: str,
    secret: str,
    headers: Mapping[str, str],
    body: bytes,
    *,
    tolerance: int = 300,
    now: float | None = None,
) -> Verification:
    provider = (provider or "none").lower()
    if provider == "none":
        return Verification(UNSIGNED, "no provider configured for this hook")
    if provider not in SIGNATURE_HEADERS:
        return Verification(INVALID, f"unknown provider {provider!r}")
    if not secret:
        return Verification(NO_SECRET, f"provider {provider} configured but no secret set")
    header_name = SIGNATURE_HEADERS[provider]
    value = headers.get(header_name)
    if value is None:
        if provider == "github" and "x-hub-signature" in headers:
            return Verification(UNSIGNED, "X-Hub-Signature-256 header missing (only legacy sha1 X-Hub-Signature sent)")
        return Verification(UNSIGNED, f"{_title(header_name)} header missing")
    if provider == "stripe":
        return verify_stripe(secret, value, body, tolerance=tolerance, now=now)
    if provider == "github":
        return verify_github(secret, value, body)
    return verify_shopify(secret, value, body)


def verify_stripe(
    secret: str, header: str, body: bytes, *, tolerance: int = 300, now: float | None = None
) -> Verification:
    timestamp = None
    v1s: list[str] = []
    for item in header.split(","):
        key, sep, val = item.strip().partition("=")
        if not sep:
            continue
        if key == "t":
            try:
                timestamp = int(val)
            except ValueError:
                return Verification(INVALID, "malformed Stripe-Signature (t= is not an integer)")
        elif key == "v1":
            v1s.append(val.strip())
    if timestamp is None:
        return Verification(INVALID, "malformed Stripe-Signature (no t= timestamp)")
    if not v1s:
        return Verification(INVALID, "no v1 signature in Stripe-Signature")

    expected = _hmac_sha256(secret, f"{timestamp}.".encode("ascii") + body).hex()
    match = 0
    for i, candidate in enumerate(v1s, 1):
        if _same(expected, candidate) and not match:
            match = i
    if not match:
        return Verification(INVALID, "signature mismatch")

    now = time.time() if now is None else now
    age = int(round(now - timestamp))
    if tolerance > 0 and abs(age) > tolerance:
        if age >= 0:
            return Verification(INVALID, f"timestamp outside tolerance ({age}s > {tolerance}s)")
        return Verification(INVALID, f"timestamp outside tolerance ({-age}s in the future > {tolerance}s)")
    which = f" (v1 #{match} of {len(v1s)})" if len(v1s) > 1 else ""
    when = f"{age}s old" if age >= 0 else f"{-age}s in the future"
    return Verification(VERIFIED, f"v1 signature matches{which}, timestamp {when}")


def verify_github(secret: str, header: str, body: bytes) -> Verification:
    scheme, sep, digest = header.strip().partition("=")
    if not sep or scheme != "sha256" or not digest:
        return Verification(INVALID, "malformed X-Hub-Signature-256 (expected sha256=<hex>)")
    if _same(_hmac_sha256(secret, body).hex(), digest):
        return Verification(VERIFIED, "sha256 HMAC matches")
    return Verification(INVALID, "signature mismatch")


def verify_shopify(secret: str, header: str, body: bytes) -> Verification:
    if _same(shopify_signature(secret, body), header.strip()):
        return Verification(VERIFIED, "base64 HMAC-SHA256 matches")
    return Verification(INVALID, "signature mismatch")


def _title(header: str) -> str:
    special = {"stripe-signature": "Stripe-Signature", "x-hub-signature-256": "X-Hub-Signature-256",
               "x-shopify-hmac-sha256": "X-Shopify-Hmac-Sha256"}
    return special.get(header, header)
