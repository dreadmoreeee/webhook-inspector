"""Export a stored request as a curl command or a pytest fixture."""

from __future__ import annotations

import base64
import shlex

from .redact import redact_headers
from .replay import strip_hop_by_hop
from .storage import StoredRequest
from .views import redacted_body


def _parts(rec: StoredRequest, redact: bool) -> tuple[list[tuple[str, str]], bytes]:
    headers = strip_hop_by_hop(rec.headers)
    if redact:
        return redact_headers(headers), redacted_body(rec)
    return headers, rec.body


def default_url(rec: StoredRequest, base: str = "http://127.0.0.1:8000") -> str:
    url = base.rstrip("/") + rec.path
    return f"{url}?{rec.query}" if rec.query else url


def to_curl(rec: StoredRequest, url: str | None = None, *, redact: bool = False) -> str:
    """A POSIX-shell curl command that re-sends the request byte for byte.

    Text bodies go through --data-raw (no '@file' interpretation). Bodies that
    are not UTF-8 are piped in from base64 so the command stays copy-pastable.
    """
    url = url or default_url(rec)
    headers, body = _parts(rec, redact)
    opts: list[tuple[str, str]] = []
    if rec.method != ("POST" if body else "GET"):
        opts.append(("-X", rec.method))
    opts += [("-H", f"{name}: {value}") for name, value in headers]
    prefix = ""
    if body:
        text = _text_or_none(body)
        if text is not None:
            opts.append(("--data-raw", text))
        else:
            b64 = base64.b64encode(body).decode("ascii")
            prefix = f"printf %s {shlex.quote(b64)} | base64 -d | "
            opts.append(("--data-binary", "@-"))
    lines = ["curl -sS"] + [f"{flag} {shlex.quote(value)}" for flag, value in opts] + [shlex.quote(url)]
    return prefix + " \\\n  ".join(lines)


def _text_or_none(body: bytes) -> str | None:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return None if "\x00" in text else text


def to_pytest_fixture(rec: StoredRequest, *, redact: bool = False) -> str:
    """Python source for a pytest fixture holding the exact request."""
    headers, body = _parts(rec, redact)
    const = f"WEBHOOK_{rec.id}"
    header_lines = "".join(f"        ({k!r}, {v!r}),\n" for k, v in headers)
    body_repr = _bytes_literal(body)
    note = " Sensitive values were redacted, so signatures will not verify." if redact else ""
    return (
        f"# Captured by webhook-inspector: request #{rec.id} to hook {rec.hook!r}\n"
        f"# {rec.method} {rec.path} at {rec.received_iso}, verification: {rec.status} ({rec.reason}).{note}\n"
        "import pytest\n"
        "\n"
        f"{const} = {{\n"
        f"    \"method\": {rec.method!r},\n"
        f"    \"path\": {rec.path!r},\n"
        f"    \"query\": {rec.query!r},\n"
        "    \"headers\": [\n"
        f"{header_lines}"
        "    ],\n"
        f"    \"body\": {body_repr},\n"
        "}\n"
        "\n"
        "\n"
        "@pytest.fixture\n"
        f"def webhook_{rec.id}():\n"
        f"    \"\"\"Use with a TestClient: client.request(w['method'], w['path'], headers=w['headers'], content=w['body']).\"\"\"\n"
        f"    return dict({const})\n"
    )


def _bytes_literal(body: bytes, width: int = 72) -> str:
    """repr() of bytes, split across lines when long (always ASCII)."""
    if len(body) <= width:
        return repr(body)
    chunks = [repr(body[i:i + width]) for i in range(0, len(body), width)]
    return "(\n        " + "\n        ".join(chunks) + "\n    )"
