import base64
import hashlib
import hmac

import pytest

from webhook_inspector.signatures import (
    INVALID, NO_SECRET, UNSIGNED, VERIFIED,
    github_signature, shopify_signature, stripe_signature, verify,
)

SECRET = "whsec_unit"
BODY = b'{"id":"evt_1","object":"event","amount":1000}'
NOW = 1_790_000_000


def _stripe(body=BODY, secret=SECRET, t=NOW, extra=None):
    v1 = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    parts = [f"t={t}"] + [f"v1={x}" for x in (extra or [])] + [f"v1={v1}"]
    return {"stripe-signature": ",".join(parts)}


def check(provider, headers, body=BODY, secret=SECRET, **kw):
    return verify(provider, secret, headers, body, now=NOW, **kw)


# -- Stripe ------------------------------------------------------------------

def test_stripe_valid():
    v = check("stripe", _stripe())
    assert v.status == VERIFIED
    assert "timestamp 0s old" in v.reason


def test_stripe_signature_helper_matches_independent_hmac():
    assert {"stripe-signature": stripe_signature(SECRET, BODY, NOW)} == _stripe()


def test_stripe_tampered_body():
    v = check("stripe", _stripe(), body=BODY.replace(b"1000", b"1"))
    assert (v.status, v.reason) == (INVALID, "signature mismatch")


def test_stripe_wrong_secret():
    v = check("stripe", _stripe(secret="whsec_other"))
    assert (v.status, v.reason) == (INVALID, "signature mismatch")


def test_stripe_missing_header():
    v = check("stripe", {})
    assert (v.status, v.reason) == (UNSIGNED, "Stripe-Signature header missing")


def test_stripe_expired_timestamp():
    v = check("stripe", _stripe(t=NOW - 412))
    assert (v.status, v.reason) == (INVALID, "timestamp outside tolerance (412s > 300s)")


def test_stripe_future_timestamp():
    v = check("stripe", _stripe(t=NOW + 900))
    assert (v.status, v.reason) == (INVALID, "timestamp outside tolerance (900s in the future > 300s)")


def test_stripe_within_custom_tolerance():
    assert check("stripe", _stripe(t=NOW - 412), tolerance=600).status == VERIFIED
    assert check("stripe", _stripe(t=NOW - 10_000), tolerance=0).status == VERIFIED  # 0 disables


def test_stripe_multiple_v1_values():
    v = check("stripe", _stripe(extra=["ab" * 32, "cd" * 32]))
    assert v.status == VERIFIED
    assert "v1 #3 of 3" in v.reason
    # none of several v1 values match
    bad = {"stripe-signature": f"t={NOW},v1={'ab' * 32},v1={'cd' * 32}"}
    assert check("stripe", bad).status == INVALID


def test_stripe_ignores_v0_and_needs_v1():
    v0_only = {"stripe-signature": f"t={NOW},v0=" + "a" * 64}
    assert check("stripe", v0_only).reason == "no v1 signature in Stripe-Signature"


@pytest.mark.parametrize("header,reason", [
    ("v1=abc", "malformed Stripe-Signature (no t= timestamp)"),
    ("t=soon,v1=abc", "malformed Stripe-Signature (t= is not an integer)"),
])
def test_stripe_malformed(header, reason):
    v = check("stripe", {"stripe-signature": header})
    assert (v.status, v.reason) == (INVALID, reason)


def test_signature_mismatch_is_reported_before_timestamp():
    v = check("stripe", _stripe(t=NOW - 412, secret="whsec_other"))
    assert v.reason == "signature mismatch"


# -- GitHub ------------------------------------------------------------------

def test_github_valid():
    header = "sha256=" + hmac.new(SECRET.encode(), BODY, hashlib.sha256).hexdigest()
    assert header == github_signature(SECRET, BODY)
    v = check("github", {"x-hub-signature-256": header})
    assert (v.status, v.reason) == (VERIFIED, "sha256 HMAC matches")


def test_github_tampered_body_and_wrong_secret():
    header = {"x-hub-signature-256": github_signature(SECRET, BODY)}
    assert check("github", header, body=BODY + b" ").reason == "signature mismatch"
    wrong = {"x-hub-signature-256": github_signature("nope", BODY)}
    assert check("github", wrong).status == INVALID


def test_github_missing_and_malformed_header():
    assert check("github", {}).reason == "X-Hub-Signature-256 header missing"
    legacy = check("github", {"x-hub-signature": "sha1=abc"})
    assert legacy.status == UNSIGNED and "legacy sha1" in legacy.reason
    bad = check("github", {"x-hub-signature-256": "md5=abc"})
    assert bad.status == INVALID and "malformed" in bad.reason


# -- Shopify -----------------------------------------------------------------

def test_shopify_valid():
    header = base64.b64encode(hmac.new(SECRET.encode(), BODY, hashlib.sha256).digest()).decode()
    assert header == shopify_signature(SECRET, BODY)
    v = check("shopify", {"x-shopify-hmac-sha256": header})
    assert v.status == VERIFIED


def test_shopify_tampered_wrong_secret_missing():
    header = {"x-shopify-hmac-sha256": shopify_signature(SECRET, BODY)}
    assert check("shopify", header, body=b"{}").reason == "signature mismatch"
    assert check("shopify", {"x-shopify-hmac-sha256": shopify_signature("x", BODY)}).status == INVALID
    assert check("shopify", {}).reason == "X-Shopify-Hmac-Sha256 header missing"


def test_non_ascii_header_value_does_not_crash():
    v = check("shopify", {"x-shopify-hmac-sha256": "caf" + chr(0xE9)})
    assert v.status == INVALID


# -- statuses without verification -------------------------------------------

def test_no_secret_and_no_provider():
    assert check("stripe", _stripe(), secret="").status == NO_SECRET
    v = check("none", {})
    assert (v.status, v.reason) == (UNSIGNED, "no provider configured for this hook")
