"""Keystone public API app for gunicorn. oslo.config parses sys.argv, so hide gunicorn's flags."""
import sys

sys.argv = [sys.argv[0]]
from keystone.server.wsgi import initialize_public_application  # noqa: E402

application = initialize_public_application()
