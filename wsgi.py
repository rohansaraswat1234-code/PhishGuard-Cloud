"""WSGI entry point for Gunicorn and production hosting."""
from backend.app import app

__all__ = ["app"]
