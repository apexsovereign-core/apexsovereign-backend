"""Compatibility entrypoint for the existing Render service start command.

Legacy compute and simulated payment routes are intentionally not mounted in production.
"""

from app.main import app

__all__ = ["app"]
