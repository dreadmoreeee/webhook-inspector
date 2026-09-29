"""Hide secrets before showing a stored request."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl

REDACTED = "[redacted]"

_WORDS = (
    "token|secret|password|passwd|pwd|api_?key|apikey|private_?key|credentials?"
    "|authorization|auth|cookie|set_cookie|signature|hmac|session"
)
_SENSITIVE = re.compile(rf"(?:^|_)(?:{_WORDS})s?(?:_|$)")
_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_SEPARATORS = re.compile(r"[^a-z0-9]+")


def normalize(name: str) -> str:
    """'X-Api-Key' -> 'x_api_key', 'accessToken' -> 'access_token'."""
    return _SEPARATORS.sub("_", _CAMEL.sub(r"\1_\2", name).lower()).strip("_")


def is_sensitive(name: str) -> bool:
    return bool(_SENSITIVE.search(normalize(name)))


def redact_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(k, REDACTED if is_sensitive(k) else v) for k, v in headers]


def redact_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (REDACTED if is_sensitive(str(k)) and v not in (None, "") else redact_json(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact_json(v) for v in value]
    return value


def query_pairs(query: str, redact: bool) -> list[tuple[str, str]]:
    pairs = parse_qsl(query, keep_blank_values=True)
    if not redact:
        return pairs
    return [(k, REDACTED if is_sensitive(k) else v) for k, v in pairs]
