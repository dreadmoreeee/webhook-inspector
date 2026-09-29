"""TOML configuration: hooks, secrets, database path and retention."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on Python 3.10
    import tomli as tomllib

PROVIDERS = ("stripe", "github", "shopify", "none")
DEFAULT_DB = "webhook_inspector.db"
DEFAULT_RETENTION = 1000
DEFAULT_TOLERANCE = 300
DEFAULT_MAX_BODY = 5 * 1024 * 1024
DEFAULT_UI_HOSTS = ("127.0.0.1", "localhost", "::1")

_HOOK_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


class ConfigError(ValueError):
    """Raised when the config file is not valid."""


@dataclass
class Hook:
    name: str
    provider: str = "none"
    secret: str = ""
    tolerance: int = DEFAULT_TOLERANCE
    replay_to: str = ""


@dataclass
class Config:
    db: str = DEFAULT_DB
    retention: int = DEFAULT_RETENTION
    max_body_bytes: int = DEFAULT_MAX_BODY
    allow_unknown_hooks: bool = True
    ui_hosts: list[str] = field(default_factory=lambda: list(DEFAULT_UI_HOSTS))
    hooks: dict[str, Hook] = field(default_factory=dict)


def load_config(path: str | os.PathLike[str]) -> Config:
    """Read a TOML file. A relative `db` is resolved against the file's folder."""
    path = Path(path)
    with path.open("rb") as fh:
        try:
            data = tomllib.load(fh)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: {exc}") from exc
    return parse_config(data, base_dir=path.parent)


def parse_config(data: dict[str, Any], base_dir: Path | None = None) -> Config:
    cfg = Config()
    if "db" in data:
        db = Path(str(data["db"]))
        if base_dir is not None and not db.is_absolute():
            db = base_dir / db
        cfg.db = str(db)
    cfg.retention = _int(data, "retention", DEFAULT_RETENTION, minimum=0)
    cfg.max_body_bytes = _int(data, "max_body_bytes", DEFAULT_MAX_BODY, minimum=1)
    cfg.allow_unknown_hooks = bool(data.get("allow_unknown_hooks", True))
    if "ui_hosts" in data:
        cfg.ui_hosts = [str(h) for h in data["ui_hosts"]]

    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ConfigError("[hooks] must be a table")
    for name, raw in hooks.items():
        if not _HOOK_NAME.match(name):
            raise ConfigError(f"hook name {name!r}: use letters, digits, '.', '_' or '-'")
        if not isinstance(raw, dict):
            raise ConfigError(f"[hooks.{name}] must be a table")
        provider = str(raw.get("provider", "none")).lower()
        if provider not in PROVIDERS:
            raise ConfigError(f"hook {name!r}: provider must be one of {', '.join(PROVIDERS)}")
        secret = str(raw.get("secret", ""))
        env_name = raw.get("secret_env")
        if env_name and os.environ.get(str(env_name)):
            secret = os.environ[str(env_name)]
        cfg.hooks[name] = Hook(
            name=name,
            provider=provider,
            secret=secret,
            tolerance=_int(raw, "tolerance", DEFAULT_TOLERANCE, minimum=0),
            replay_to=str(raw.get("replay_to", "")),
        )
    return cfg


def _int(data: dict[str, Any], key: str, default: int, minimum: int) -> int:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConfigError(f"{key} must be an integer >= {minimum}")
    return value
