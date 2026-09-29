"""Turn a stored request into something readable (optionally redacted)."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode

from .redact import redact_headers, redact_json, query_pairs, is_sensitive, REDACTED
from .storage import StoredRequest

PREVIEW_BYTES = 64 * 1024


@dataclass
class BodyView:
    kind: str  # "empty" | "json" | "form" | "text" | "binary"
    text: str
    redacted: bool


def body_view(rec: StoredRequest, redact: bool) -> BodyView:
    body = rec.body
    if not body:
        return BodyView("empty", "", False)
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        data = _NOT_JSON
    if data is not _NOT_JSON:
        shown = redact_json(data) if redact else data
        return BodyView("json", json.dumps(shown, indent=2, ensure_ascii=False), redact and shown != data)
    ctype = (rec.header("content-type") or "").lower()
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        chunk = body[:PREVIEW_BYTES]
        note = "" if len(body) <= PREVIEW_BYTES else f"\n... ({len(body) - PREVIEW_BYTES} more bytes)"
        return BodyView("binary", base64.b64encode(chunk).decode("ascii") + note, False)
    if ctype.startswith("application/x-www-form-urlencoded"):
        pairs = parse_qsl(text, keep_blank_values=True)
        hidden = [(k, REDACTED if redact and is_sensitive(k) else v) for k, v in pairs]
        return BodyView("form", "\n".join(f"{k} = {v}" for k, v in hidden), hidden != pairs)
    return BodyView("text", text, False)


def redacted_body(rec: StoredRequest) -> bytes:
    """Body bytes with sensitive JSON/form fields replaced (changes the bytes)."""
    try:
        data = json.loads(rec.body)
    except (ValueError, UnicodeDecodeError):
        data = _NOT_JSON
    if data is not _NOT_JSON:
        clean = redact_json(data)
        return rec.body if clean == data else json.dumps(clean).encode("utf-8")
    if (rec.header("content-type") or "").lower().startswith("application/x-www-form-urlencoded"):
        try:
            pairs = parse_qsl(rec.body.decode("utf-8"), keep_blank_values=True)
        except UnicodeDecodeError:
            return rec.body
        clean_pairs = [(k, REDACTED if is_sensitive(k) else v) for k, v in pairs]
        return rec.body if clean_pairs == pairs else urlencode(clean_pairs).encode("ascii")
    return rec.body


def headers_view(rec: StoredRequest, redact: bool) -> list[tuple[str, str]]:
    return redact_headers(rec.headers) if redact else list(rec.headers)


def query_view(rec: StoredRequest, redact: bool) -> list[tuple[str, str]]:
    return query_pairs(rec.query, redact)


def as_dict(rec: StoredRequest, redact: bool) -> dict:
    """JSON-friendly representation for the API."""
    view = body_view(rec, redact)
    body = redacted_body(rec) if redact else rec.body
    try:
        body_text, body_b64 = body.decode("utf-8"), None
    except UnicodeDecodeError:
        body_text, body_b64 = None, base64.b64encode(body).decode("ascii")
    return {
        "id": rec.id,
        "hook": rec.hook,
        "method": rec.method,
        "path": rec.path,
        "query": rec.query if not redact else urlencode(query_view(rec, True)),
        "headers": [list(h) for h in headers_view(rec, redact)],
        "body": body_text,
        "body_base64": body_b64,
        "body_kind": view.kind,
        "size": rec.size,
        "client_ip": rec.client_ip,
        "received_at": rec.received_at,
        "received": rec.received_iso,
        "verification": {"status": rec.status, "reason": rec.reason},
        "redacted": redact,
    }


class _Missing:
    pass


_NOT_JSON = _Missing()
