import time

import pytest

from webhook_inspector.config import ConfigError, load_config, parse_config
from webhook_inspector.storage import Store


def _add(store, n, hook="h"):
    return store.add(hook=hook, method="POST", path=f"/hooks/{hook}", query="a=1",
                     headers=[("content-type", "application/json"), ("x-n", str(n))],
                     body=f'{{"n": {n}}}'.encode(), client_ip="127.0.0.1",
                     received_at=time.time(), status="unsigned", reason="test")


def test_roundtrip_keeps_bytes_and_header_order(tmp_path):
    store = Store(tmp_path / "s.db")
    body = bytes(range(256))
    rid = store.add(hook="bin", method="PUT", path="/hooks/bin", query="x=%20y",
                    headers=[("x-dup", "1"), ("X-Dup", "2"), ("content-type", "application/octet-stream")],
                    body=body, client_ip="10.0.0.5", received_at=1_790_000_000.5,
                    status="verified", reason="ok")
    rec = store.get(rid)
    assert rec.body == body and rec.size == 256
    assert rec.headers == [("x-dup", "1"), ("X-Dup", "2"), ("content-type", "application/octet-stream")]
    assert rec.header("X-DUP") == "1"
    assert (rec.method, rec.query, rec.client_ip, rec.status) == ("PUT", "x=%20y", "10.0.0.5", "verified")
    assert rec.received_iso == "2026-09-21 14:13:20 UTC"
    assert store.get(rid + 1) is None


def test_retention_keeps_newest_n(tmp_path):
    store = Store(tmp_path / "s.db", retention=3)
    ids = [_add(store, n) for n in range(7)]
    assert store.count() == 3
    assert [r.id for r in store.list()] == ids[-3:][::-1]
    assert store.get(ids[0]) is None
    # ids are never reused after trimming
    assert _add(store, 99) == ids[-1] + 1


def test_retention_drops_replay_rows_of_deleted_requests(tmp_path):
    store = Store(tmp_path / "s.db", retention=1)
    first = _add(store, 1)
    store.add_replay(first, "http://127.0.0.1:1/", False, time.time(), 200, None, 1.0)
    assert len(store.replays(first)) == 1
    _add(store, 2)
    assert store.replays(first) == []


def test_retention_zero_is_unlimited(tmp_path):
    store = Store(tmp_path / "s.db", retention=0)
    for n in range(5):
        _add(store, n)
    assert store.count() == 5


def test_list_filters_by_hook(tmp_path):
    store = Store(tmp_path / "s.db")
    _add(store, 1, hook="a")
    _add(store, 2, hook="b")
    assert [r.hook for r in store.list(hook="b")] == ["b"]


def test_http_insert_enforces_retention(tmp_path):
    from fastapi.testclient import TestClient
    from webhook_inspector.app import create_app

    cfg = parse_config({"retention": 2})
    with TestClient(create_app(cfg, db_path=str(tmp_path / "r.db"))) as client:
        ids = [client.post("/hooks/x", content=b"%d" % i).json()["id"] for i in range(5)]
        store = client.app.state.store
        assert store.count() == 2
        assert [r.id for r in store.list()] == [ids[4], ids[3]]


def test_load_config_file(tmp_path, monkeypatch):
    monkeypatch.setenv("WI_TEST_SECRET", "from-env")
    path = tmp_path / "c.toml"
    path.write_text(
        'db = "data/x.db"\nretention = 5\n'
        '[hooks.s]\nprovider = "stripe"\nsecret = "inline"\nsecret_env = "WI_TEST_SECRET"\ntolerance = 60\n'
        '[hooks.g]\nprovider = "GitHub"\nsecret = "g"\n',
        encoding="utf-8",
    )
    cfg = load_config(path)
    assert cfg.db == str(tmp_path / "data" / "x.db")
    assert cfg.retention == 5
    assert (cfg.hooks["s"].secret, cfg.hooks["s"].tolerance) == ("from-env", 60)
    assert cfg.hooks["g"].provider == "github"
    assert cfg.hooks["g"].tolerance == 300


@pytest.mark.parametrize("data", [
    {"hooks": {"x": {"provider": "paypal"}}},
    {"hooks": {"bad name": {"provider": "none"}}},
    {"retention": -1},
    {"hooks": {"x": {"provider": "stripe", "tolerance": "300"}}},
])
def test_bad_config(data):
    with pytest.raises(ConfigError):
        parse_config(data)
