"""fpagent: record-level content fingerprinting for structured data."""

from .version import (
    AGENT_IMPLEMENTATION,
    AGENT_VERSION,
    CANONICALIZATION_VERSION,
    SPEC_VERSION,
)

__version__ = AGENT_VERSION

__all__ = [
    "AGENT_IMPLEMENTATION",
    "AGENT_VERSION",
    "CANONICALIZATION_VERSION",
    "SPEC_VERSION",
    "__version__",
]
