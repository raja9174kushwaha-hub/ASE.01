import logging
from typing import Optional


_LOGGING_CONFIGURED = False


def configure_logging(level: int = logging.INFO) -> None:
    """Configure basic logging for the ASE app.

    This should be called once (e.g., from app.py).
    Subsequent calls are no-ops.
    """
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    _LOGGING_CONFIGURED = True
    logging.getLogger(__name__).info("Logging configured at level %s", logging.getLevelName(level))


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Convenience helper to get a logger with the ASE configuration applied."""
    return logging.getLogger(name if name is not None else __name__)
