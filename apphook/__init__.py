"""AppHook — Mobile application runtime instrumentation and security testing."""

from .instrumentor import RuntimeInstrumentor
from .models import (
    HookResult,
    HookState,
    Platform,
    Session,
    SessionState,
    TargetApp,
    TraceCategory,
    TraceEvent,
    TraceSession,
    Vulnerability,
    VulnReport,
)

__all__ = [
    "RuntimeInstrumentor",
    "Platform",
    "TargetApp",
    "Session",
    "SessionState",
    "HookResult",
    "HookState",
    "TraceCategory",
    "TraceEvent",
    "TraceSession",
    "Vulnerability",
    "VulnReport",
]

__version__ = "0.1.0"
