"""Command line: serve, list, show, export, replay."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .config import Config, ConfigError, load_config
from .storage import Store

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _config(args: argparse.Namespace) -> Config:
    cfg = load_config(args.config) if args.config else Config()
    if args.db:
        cfg.db = args.db
    return cfg


def _store(cfg: Config) -> Store:
    return Store(cfg.db, retention=cfg.retention)


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .app import create_app

    cfg = _config(args)
    if args.host not in LOOPBACK and args.host not in ("0.0.0.0", "::") and args.host not in cfg.ui_hosts:
        cfg.ui_hosts.append(args.host)
    if args.host not in LOOPBACK:
        print(f"warning: binding to {args.host}; the UI has no login, keep it off the public internet",
              file=sys.stderr)
    hooks = ", ".join(f"{h.name} ({h.provider})" for h in cfg.hooks.values()) or "none configured"
    print(f"webhook-inspector {__version__}: db={cfg.db} retention={cfg.retention or 'unlimited'} hooks: {hooks}")
    print(f"UI: http://{args.host}:{args.port}/   receive at http://{args.host}:{args.port}/hooks/<name>")
    uvicorn.run(create_app(cfg), host=args.host, port=args.port, log_level=args.log_level)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    rows = _store(_config(args)).list(limit=args.limit, hook=args.hook)
    if not rows:
        print("no stored requests")
        return 0
    print(f"{'ID':>4}  {'RECEIVED (UTC)':19}  {'HOOK':16} {'METHOD':6} {'STATUS':9} {'SIZE':>6}  REASON")
    for r in rows:
        print(f"{r.id:>4}  {r.received_iso[:19]:19}  {r.hook[:16]:16} {r.method:6} {r.status:9} "
              f"{r.size:>6}  {r.reason}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    from .views import as_dict

    rec = _store(_config(args)).get(args.id)
    if rec is None:
        print(f"request {args.id} not found", file=sys.stderr)
        return 1
    print(json.dumps(as_dict(rec, redact=not args.reveal), indent=2, ensure_ascii=True))
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from .export import default_url, to_curl, to_pytest_fixture

    rec = _store(_config(args)).get(args.id)
    if rec is None:
        print(f"request {args.id} not found", file=sys.stderr)
        return 1
    if args.format == "curl":
        print(to_curl(rec, args.to or default_url(rec), redact=args.redact))
    else:
        print(to_pytest_fixture(rec, redact=args.redact), end="")
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    from .replay import replay_and_record

    cfg = _config(args)
    store = _store(cfg)
    rec = store.get(args.id)
    if rec is None:
        print(f"request {args.id} not found", file=sys.stderr)
        return 1
    try:
        result = replay_and_record(store, cfg, rec, args.to, resign=args.resign, timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    signed = " (Stripe re-signed)" if result.resigned else ""
    if result.error:
        print(f"replay #{rec.id} -> {result.target}{signed}: {result.error}")
        return 1
    print(f"replay #{rec.id} -> {result.target}{signed}: HTTP {result.status_code} in {result.elapsed_ms} ms")
    if result.response_body:
        print(result.response_body)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="webhook_inspector", description="Local webhook receiver and debugger.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--config", help="TOML config file")
        p.add_argument("--db", help="SQLite file (overrides the config)")

    p = sub.add_parser("serve", help="run the receiver and web UI")
    common(p)
    p.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--log-level", default="info")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("list", help="print stored requests, newest first")
    common(p)
    p.add_argument("--hook")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("show", help="print one stored request as JSON")
    common(p)
    p.add_argument("id", type=int)
    p.add_argument("--reveal", action="store_true", help="do not redact secrets")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("export", help="print a stored request as curl or a pytest fixture")
    common(p)
    p.add_argument("id", type=int)
    p.add_argument("--format", choices=["curl", "pytest"], default="curl")
    p.add_argument("--to", help="URL for the curl command (default http://127.0.0.1:8000 + original path)")
    p.add_argument("--redact", action="store_true", help="hide secrets (breaks signatures)")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("replay", help="send a stored request to a URL, once")
    common(p)
    p.add_argument("id", type=int)
    p.add_argument("--to", required=True, help="target URL")
    p.add_argument("--resign", action="store_true", help="fresh Stripe-Signature using the hook's secret")
    p.add_argument("--timeout", type=float, default=10.0)
    p.set_defaults(func=cmd_replay)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
