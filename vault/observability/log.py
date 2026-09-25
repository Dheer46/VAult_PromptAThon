"""Structured JSON logging via structlog."""
import logging
import os
import sys

import structlog

_level = getattr(logging, os.environ.get("VAULT_LOG_LEVEL", "INFO").upper(), logging.INFO)
logging.basicConfig(format="%(message)s", stream=sys.stdout, level=_level)

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(_level),
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

log = structlog.get_logger().bind(node=os.environ.get("VAULT_NODE_NAME", os.environ.get("HOSTNAME", "local")))
