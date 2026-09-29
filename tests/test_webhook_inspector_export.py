import shlex
import subprocess
import shutil

import pytest

from webhook_inspector.export import to_curl, to_pytest_fixture
from webhook_inspector.storage import StoredRequest

TRICKY = b'{"msg": "it\'s $HOME `id` \\"quoted\\"\\nline2", "api_key": "k-123", "at": "@file"}'


def _rec(body=TRICKY, method="POST", headers=None, query="a=1&b=two words"):
    return StoredRequest(
        id=7, hook="github", method=method, path="/hooks/github", query=query,
        headers=headers or [
            ("host", "127.0.0.1:8000"), ("content-length", str(len(body))), ("connection", "keep-alive"),
            ("content-type", "application/json"), ("x-hub-signature-256", "sha256=abc"),
            ("x-note", "it's"),
        ],
        body=body, client_ip="127.0.0.1", received_at=1_790_000_000.0, status="verified", reason="ok",
    )


def test_curl_quotes_and_roundtrips_through_shlex():
    cmd = to_curl(_rec(), "http://127.0.0.1:9000/hook?x='y'")
    argv = shlex.split(cmd.replace("\\\n", " "))
    assert argv[0] == "curl"
    assert argv[argv.index("--data-raw") + 1].encode() == TRICKY
    headers = [argv[i + 1] for i, a in enumerate(argv) if a == "-H"]
    assert headers == ["content-type: application/json", "x-hub-signature-256: sha256=abc", "x-note: it's"]
    assert argv[-1] == "http://127.0.0.1:9000/hook?x='y'"
    assert "-X" not in argv  # POST with a body is curl's default


def test_curl_default_url_method_and_empty_body():
    cmd = to_curl(_rec(body=b"", method="DELETE"))
    argv = shlex.split(cmd.replace("\\\n", " "))
    assert argv[argv.index("-X") + 1] == "DELETE"
    assert argv[-1] == "http://127.0.0.1:8000/hooks/github?a=1&b=two words"
    assert "--data-raw" not in argv


def test_curl_binary_body_uses_base64_pipe():
    cmd = to_curl(_rec(body=b"\x00\xff\x10"), "http://127.0.0.1:1/")
    assert cmd.startswith("printf %s AP8Q | base64 -d | curl")
    assert "--data-binary @-" in cmd


def test_curl_redacted():
    cmd = to_curl(_rec(), "http://127.0.0.1:1/", redact=True)
    assert "sha256=abc" not in cmd and "k-123" not in cmd
    assert "[redacted]" in cmd


def _bash():
    # Full path from PATH: on Windows a bare "bash" can hit the WSL stub in System32.
    bash = shutil.which("bash")
    if bash is None:
        return None
    try:
        probe = subprocess.run([bash, "-c", "printf ok"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return bash if probe.stdout == b"ok" else None


def test_curl_command_survives_a_real_shell():
    bash = _bash()
    if bash is None:
        pytest.skip("no working bash")
    cmd = to_curl(_rec(), "http://127.0.0.1:1/")
    # Replace curl with a printer of the --data-raw argument to check the shell sees exact bytes.
    script = "curl() { while [ $# -gt 0 ]; do if [ \"$1\" = --data-raw ]; then printf %s \"$2\"; fi; shift; done; }\n"
    out = subprocess.run([bash, "-c", script + cmd], capture_output=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert out.stdout == TRICKY


def test_pytest_fixture_is_valid_python_with_exact_bytes():
    body = TRICKY + b"\x00\xff" + b"x" * 200
    src = to_pytest_fixture(_rec(body=body))
    assert src.isascii()
    ns = {}
    exec(compile(src, "<fixture>", "exec"), ns)
    data = ns["WEBHOOK_7"]
    assert data["body"] == body
    assert data["method"] == "POST" and data["path"] == "/hooks/github" and data["query"] == "a=1&b=two words"
    assert ("x-hub-signature-256", "sha256=abc") in data["headers"]
    assert not any(k in ("host", "content-length", "connection") for k, _ in data["headers"])
    assert "def webhook_7():" in src and "@pytest.fixture" in src


def test_pytest_fixture_redacted():
    src = to_pytest_fixture(_rec(), redact=True)
    assert "k-123" not in src and "sha256=abc" not in src
    assert "signatures will not verify" in src


def test_export_endpoints(client):
    rid = client.post("/hooks/plain?x=1", content=b'{"password": "pw-1", "n": 1}',
                      headers={"Content-Type": "application/json"}).json()["id"]
    curl = client.get(f"/requests/{rid}/curl").text
    assert "pw-1" not in curl and "http://127.0.0.1/hooks/plain?x=1" in curl
    curl = client.get(f"/requests/{rid}/curl?reveal=1&to=http://127.0.0.1:5000/x").text
    assert "pw-1" in curl and "http://127.0.0.1:5000/x" in curl
    fixture = client.get(f"/requests/{rid}/fixture?reveal=1").text
    ns = {}
    exec(fixture, ns)
    assert ns[f"WEBHOOK_{rid}"]["body"] == b'{"password": "pw-1", "n": 1}'
