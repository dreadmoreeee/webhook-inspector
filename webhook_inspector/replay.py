"""Re-send a stored request to a target URL. Only ever called on explicit request."""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from .config import Config
from .signatures import stripe_signature
from .storage import Store, StoredRequest

# RFC 9110 section 7.6.1 hop-by-hop headers, plus the ones the HTTP client
# must compute itself for the new connection.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
})


@dataclass
class ReplayResult:
    target: str
    resigned: bool
    status_code: int | None
    error: str | None
    elapsed_ms: float | None
    response_body: str = ""


def strip_hop_by_hop(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    listed = set()
    for name, value in headers:
        if name.lower() == "connection":
            listed.update(tok.strip().lower() for tok in value.split(",") if tok.strip())
    return [(k, v) for k, v in headers if k.lower() not in HOP_BY_HOP and k.lower() not in listed]


def replay_headers(rec: StoredRequest, *, stripe_secret: str | None = None,
                   now: float | None = None) -> list[tuple[str, str]]:
    """Original headers minus hop-by-hop; with `stripe_secret`, a fresh Stripe-Signature."""
    headers = strip_hop_by_hop(rec.headers)
    if stripe_secret:
        headers = [(k, v) for k, v in headers if k.lower() != "stripe-signature"]
        t = int(time.time() if now is None else now)
        headers.append(("Stripe-Signature", stripe_signature(stripe_secret, rec.body, t)))
    return headers


def check_target(target: str) -> str:
    parts = urlsplit(target.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("target must be an absolute http:// or https:// URL")
    return target.strip()


def replay(rec: StoredRequest, target: str, *, stripe_secret: str | None = None,
           timeout: float = 10.0) -> ReplayResult:
    target = check_target(target)
    headers = replay_headers(rec, stripe_secret=stripe_secret)
    started = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            resp = client.request(rec.method, target, headers=headers, content=rec.body)
    except httpx.HTTPError as exc:
        elapsed = (time.perf_counter() - started) * 1000
        return ReplayResult(target, bool(stripe_secret), None, f"{type(exc).__name__}: {exc}", round(elapsed, 1))
    elapsed = (time.perf_counter() - started) * 1000
    return ReplayResult(target, bool(stripe_secret), resp.status_code, None, round(elapsed, 1),
                        resp.text[:2000])


def replay_and_record(store: Store, config: Config, rec: StoredRequest, target: str, *,
                      resign: bool = False, timeout: float = 10.0) -> ReplayResult:
    """Replay `rec` and log the attempt. `resign` needs a Stripe hook with a secret."""
    secret = None
    if resign:
        hook = config.hooks.get(rec.hook)
        if hook is None or hook.provider != "stripe" or not hook.secret:
            raise ValueError(f"cannot re-sign: hook {rec.hook!r} is not a Stripe hook with a secret")
        secret = hook.secret
    target = check_target(target)
    sent_at = time.time()
    result = replay(rec, target, stripe_secret=secret, timeout=timeout)
    store.add_replay(rec.id, target, result.resigned, sent_at, result.status_code, result.error,
                     result.elapsed_ms)
    return result
