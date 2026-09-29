from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from webhook_inspector.app import create_app
from webhook_inspector.config import parse_config

STRIPE_SECRET = "whsec_test_secret"
GITHUB_SECRET = "gh-test-secret"
SHOPIFY_SECRET = "shop-test-secret"

CONFIG = {
    "retention": 100,
    "hooks": {
        "stripe": {"provider": "stripe", "secret": STRIPE_SECRET, "tolerance": 300},
        "github": {"provider": "github", "secret": GITHUB_SECRET},
        "shopify": {"provider": "shopify", "secret": SHOPIFY_SECRET},
        "nosecret": {"provider": "stripe"},
        "plain": {"provider": "none"},
    },
}


@pytest.fixture
def config(tmp_path):
    cfg = parse_config(CONFIG)
    cfg.db = str(tmp_path / "hooks.db")
    return cfg


@pytest.fixture
def client(config):
    # The UI only answers to loopback Host names, so talk to it as 127.0.0.1.
    with TestClient(create_app(config), base_url="http://127.0.0.1") as c:
        yield c


class _Capture(BaseHTTPRequestHandler):
    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.captured.append(  # type: ignore[attr-defined]
            {"method": self.command, "path": self.path, "headers": list(self.headers.items()), "body": body}
        )
        payload = b'{"received": true}'
        self.send_response(self.server.reply_status)  # type: ignore[attr-defined]
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_POST = do_PUT = do_PATCH = do_DELETE = do_GET = _handle

    def log_message(self, *args) -> None:  # keep test output quiet
        pass


@pytest.fixture
def receiver():
    """A local HTTP server on a free port that records every request it gets."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Capture)
    server.captured = []  # type: ignore[attr-defined]
    server.reply_status = 202  # type: ignore[attr-defined]
    server.url = f"http://127.0.0.1:{server.server_address[1]}"  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def live_server():
    """Start a real uvicorn server for an app on a free port: live_server(app) -> base URL."""
    import uvicorn

    started = []

    def start(app) -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        deadline = time.time() + 10
        while not server.started:
            if time.time() > deadline:
                raise RuntimeError("uvicorn did not start")
            time.sleep(0.02)
        started.append((server, thread, sock))
        return f"http://127.0.0.1:{port}"

    yield start
    for server, thread, sock in started:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
