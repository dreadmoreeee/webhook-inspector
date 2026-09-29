"""webhook-inspector: a local webhook receiver and debugger (Stripe, GitHub, Shopify)."""

__version__ = "0.1.0"

from .config import Config, Hook, load_config  # noqa: E402
from .signatures import Verification, verify  # noqa: E402

__all__ = ["Config", "Hook", "load_config", "Verification", "verify", "create_app", "__version__"]


def create_app(*args, **kwargs):  # type: ignore[no-untyped-def]
    """Build the FastAPI app (imported lazily so the signature helpers need no web stack)."""
    from .app import create_app as _create_app

    return _create_app(*args, **kwargs)
