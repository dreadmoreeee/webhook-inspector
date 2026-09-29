# webhook-inspector

A local, self-hosted **webhook receiver and debugger**. Point Stripe, GitHub or Shopify (or anything else) at `/hooks/<name>`; every request is stored in SQLite byte for byte, its **signature is checked**, and you get a small HTML UI to read it, **replay** it to your app and **export** it as curl or a pytest fixture.

```
python -m webhook_inspector serve --config examples/config.toml
# UI:       http://127.0.0.1:8000/
# receiver: http://127.0.0.1:8000/hooks/<name>   (any method, answers 200 + JSON ack)
```

Why another webhook bin:

- **It tells you why a signature fails.** "timestamp outside tolerance (412s > 300s)", "signature mismatch", "X-Hub-Signature-256 header missing", or "v1 signature matches (v1 #2 of 2)" during a Stripe secret rotation. Stripe (`t=` / `v1=` with tolerance), GitHub (`sha256=` hex) and Shopify (base64) are implemented with `hmac.compare_digest`.
- **Raw bytes, not a parsed copy.** Signatures are over the exact body, so that is what is stored, replayed and exported.
- **Replay on demand only**: original method, headers and body minus hop-by-hop headers. For Stripe it can **re-sign** with a fresh `t=` and `v1=` so an old event passes your handler's tolerance check again.
- **Secrets hidden by default** in the UI: signature headers, `Authorization`, `Cookie`, and any header, query or JSON key that looks like token/secret/password/api_key. `?reveal=1` shows everything.
- **Turn a real delivery into a test**: export as a copy-pastable curl command or a pytest fixture with the exact body bytes and headers.
- **Local and small.** FastAPI + SQLite + server-rendered HTML, no JS framework, no account, nothing leaves your machine. Binds to 127.0.0.1 by default.

## Install

```
pip install .            # from this folder; Python 3.10+
pip install ".[test]"    # plus pytest
```

Dependencies: fastapi, uvicorn, httpx, jinja2 (and tomli on Python 3.10).

## Configure

```toml
db = "webhooks.db"        # relative to the config file
retention = 500           # keep the newest 500 requests, trimmed on every insert (0 = unlimited)

[hooks.stripe-test]
provider = "stripe"       # stripe | github | shopify | none
secret = "whsec_..."      # or: secret_env = "STRIPE_WEBHOOK_SECRET"
tolerance = 300           # seconds, Stripe only (0 disables the check)
replay_to = "http://127.0.0.1:3000/webhooks/stripe"   # pre-fills the replay form

[hooks.github-test]
provider = "github"
secret = "..."
```

Other keys: `allow_unknown_hooks` (default true: unknown names are stored as `unsigned`), `max_body_bytes` (default 5 MiB, larger bodies get 413), `ui_hosts` (Host names the UI answers to, default loopback only).

Each request gets one status: `verified`, `invalid`, `unsigned` (no signature header, or no provider) or `no-secret` (provider set but no secret), plus a human reason.

## Usage

```
python -m webhook_inspector serve --port 8000 [--host 127.0.0.1] [--config file.toml] [--db path]
python -m webhook_inspector list [--hook NAME] [--limit 50]
python -m webhook_inspector show ID [--reveal]
python -m webhook_inspector export ID [--format curl|pytest] [--to URL] [--redact]
python -m webhook_inspector replay ID --to URL [--resign]
```

In the UI: the list page shows hook, method, time, status badge and size; the detail page shows headers, query, pretty-printed JSON body and the verification result, with export links and a replay form (one POST per click). JSON API: `GET /api/requests`, `GET /api/requests/{id}[?reveal=1]`, `POST /api/requests/{id}/replay` with `{"to": "...", "resign_stripe": false}`.

`examples/` has a config with fake secrets, three sample payloads and `send_test_webhooks.py`, which signs them with its own stdlib HMAC code (a cross-check of the verifier) and posts valid, rotated, expired, tampered, wrong-secret and unsigned variants.

## Measured result

Real output on Windows 10, Python 3.12, against a local instance (`serve --port 8411 --config examples/config.toml --db demo.db`, where `demo.db` was a scratch file). Only 127.0.0.1 was contacted.

```
$ python examples/send_test_webhooks.py --base http://127.0.0.1:8411
stripe valid             -> #1   verified  v1 signature matches, timestamp 0s old
stripe two v1 (rotated)  -> #2   verified  v1 signature matches (v1 #2 of 2), timestamp 0s old
stripe expired           -> #3   invalid   timestamp outside tolerance (412s > 300s)
stripe tampered body     -> #4   invalid   signature mismatch
github valid             -> #5   verified  sha256 HMAC matches
github wrong secret      -> #6   invalid   signature mismatch
shopify valid            -> #7   verified  base64 HMAC-SHA256 matches
shopify no header        -> #8   unsigned  X-Shopify-Hmac-Sha256 header missing
plain (no provider)      -> #9   unsigned  no provider configured for this hook

$ python -m webhook_inspector list --db demo.db
  ID  RECEIVED (UTC)       HOOK             METHOD STATUS      SIZE  REASON
   9  2026-09-29 06:25:02  plain            POST   unsigned      39  no provider configured for this hook
   8  2026-09-29 06:25:02  shopify-test     POST   unsigned     298  X-Shopify-Hmac-Sha256 header missing
   7  2026-09-29 06:25:02  shopify-test     POST   verified     298  base64 HMAC-SHA256 matches
   6  2026-09-29 06:25:02  github-test      POST   invalid      415  signature mismatch
   5  2026-09-29 06:25:02  github-test      POST   verified     415  sha256 HMAC matches
   4  2026-09-29 06:25:02  stripe-test      POST   invalid      510  signature mismatch
   3  2026-09-29 06:25:02  stripe-test      POST   invalid      514  timestamp outside tolerance (412s > 300s)
   2  2026-09-29 06:25:02  stripe-test      POST   verified     514  v1 signature matches (v1 #2 of 2), timestamp 0s old
   1  2026-09-29 06:25:02  stripe-test      POST   verified     514  v1 signature matches, timestamp 0s old

# replay the expired Stripe event to the inspector itself, freshly re-signed
$ python -m webhook_inspector replay 3 --to http://127.0.0.1:8411/hooks/stripe-test --resign --config examples/config.toml --db demo.db
replay #3 -> http://127.0.0.1:8411/hooks/stripe-test (Stripe re-signed): HTTP 200 in 420.1 ms
{"ok":true,"id":10,"hook":"stripe-test","verification":"verified","reason":"v1 signature matches, timestamp 1s old"}

# export the GitHub delivery as curl and run it: same bytes, signature still valid
$ python -m webhook_inspector export 5 --to http://127.0.0.1:8411/hooks/github-test --db demo.db > replay5.sh
$ sh replay5.sh
{"ok":true,"id":11,"hook":"github-test","verification":"verified","reason":"sha256 HMAC matches"}

# redaction: the PaymentIntent client_secret is hidden unless ?reveal=1
$ curl -s http://127.0.0.1:8411/requests/1 | grep -c FakeFakeFake
0
$ curl -s "http://127.0.0.1:8411/requests/1?reveal=1" | grep -c FakeFakeFake
1

$ python -m pytest -q -p no:cacheprovider --import-mode=importlib webhook-inspector
............................................................             [100%]
60 passed in 10.00s
```

The tests need no internet: signature schemes (valid, tampered, wrong secret, missing header, expired and future Stripe timestamps, several `v1` values), storage and retention, replay into a local capture server (including Stripe re-signing checked by the verifier), UI pages, redaction on and off, curl (also run through a real bash) and fixture export, and one end-to-end run with uvicorn on a free port.

## Limitations

- **No login.** The UI answers only to loopback Host names and refuses cross-site replay posts, but anyone who can reach the port can read stored requests. If you expose `/hooks/` through a tunnel, keep the UI private.
- Secrets in `config.toml` are plain text; prefer `secret_env`. The SQLite file stores bodies and headers unredacted (redaction is display-only).
- Redaction is name-based (header, query and JSON/form keys). A secret inside a free-text value or a non-JSON body is not detected; it may also hide harmless fields with names like `session`.
- Only Stripe, GitHub (`X-Hub-Signature-256`; the legacy sha1 header is reported, not verified) and Shopify. No Stripe `v0` scheme, no Slack/Twilio/Svix-style schemes yet.
- Re-signing on replay is Stripe only; GitHub and Shopify signatures have no timestamp, so the original header stays valid when the body is unchanged.
- Bodies are read fully into memory (capped by `max_body_bytes`). One SQLite connection per operation: fine for debugging traffic, not a production ingest queue.
- Exported curl commands target POSIX shells (bash, zsh, Git Bash), not cmd.exe or PowerShell.

## Author

Marvin Palencia, founder of [DeMark Studio](https://demarkstudio.ca), Miramichi, New Brunswick, Canada. Portfolio: [marvin.demarkstudio.ca](https://marvin.demarkstudio.ca)

MIT License.
