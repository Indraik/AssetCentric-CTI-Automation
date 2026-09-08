"""CTI package exports for app loading and WSGI integration."""

from web_app import app


def create_app():
	"""Return the configured Flask app instance."""
	return app


__all__ = ["app", "create_app"]
