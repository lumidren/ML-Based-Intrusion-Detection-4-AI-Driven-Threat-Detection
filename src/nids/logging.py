"""Structured JSON logging via structlog, with trace-id propagation when OpenTelemetry is active."""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog


def _add_trace_context(
    _: Any, __: str, event_dict: structlog.typing.EventDict
) -> structlog.typing.EventDict:
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx is not None and ctx.is_valid:
            event_dict["trace_id"] = format(ctx.trace_id, "032x")
            event_dict["span_id"] = format(ctx.span_id, "016x")
    except Exception:
        pass
    return event_dict


def configure_logging(json_output: bool = True, level: int = logging.INFO) -> None:
    """Configure structlog + stdlib logging. Idempotent."""
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _add_trace_context,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    renderer: Any = (
        structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=False,
    )
    logging.basicConfig(level=level, stream=sys.stderr, format="%(message)s")


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
