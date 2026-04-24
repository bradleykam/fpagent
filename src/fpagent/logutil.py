"""Logging configuration for fpagent.

Two output modes:

- human: the current checkmark-style pretty output the CLI already prints.
  Emitted via the `fpagent.human` logger at INFO, formatted as plain text.
- json: one JSON object per line on stderr with `timestamp`, `level`,
  `logger`, `event`, and event-specific fields. Everything uses `stderr` so
  stdout stays clean for data (e.g., `fpagent schema`).

**Privacy invariant:** no log record may carry raw record content or
fingerprint values. Emitters use counts, field names, and short digest
prefixes only. test_logging.py enforces this with a scanning test.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any, Optional

ROOT_LOGGER = "fpagent"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        # Promote any 'extra' fields attached via logger.info(..., extra={...}).
        # We only keep simple JSON-serializable types; anything else becomes str.
        reserved = {
            "args", "asctime", "created", "exc_info", "exc_text", "filename",
            "funcName", "levelname", "levelno", "lineno", "message", "module",
            "msecs", "msg", "name", "pathname", "process", "processName",
            "relativeCreated", "stack_info", "thread", "threadName",
            "taskName",
        }
        for k, v in record.__dict__.items():
            if k in reserved or k in base or k.startswith("_"):
                continue
            try:
                json.dumps(v)
                base[k] = v
            except TypeError:
                base[k] = str(v)
        return json.dumps(base, separators=(",", ":"))


class HumanFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


def configure(fmt: str = "human", level: str = "INFO") -> None:
    """Configure the root `fpagent` logger. Idempotent."""
    root = logging.getLogger(ROOT_LOGGER)
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(stream=sys.stderr)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    elif fmt == "human":
        handler.setFormatter(HumanFormatter())
    else:
        raise ValueError(f"unknown log format: {fmt}")
    root.addHandler(handler)
    root.setLevel(level.upper())
    # Don't propagate to the Python root logger; callers embedding fpagent as a
    # library keep full control of their own logging setup.
    root.propagate = False


def get(name: str) -> logging.Logger:
    """Return a child logger of `fpagent.<name>`."""
    return logging.getLogger(f"{ROOT_LOGGER}.{name}")
