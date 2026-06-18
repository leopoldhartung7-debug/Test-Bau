"""Data models for AppHook runtime instrumentation platform."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class Platform(str, enum.Enum):
    IOS = "ios"
    ANDROID = "android"


class TraceCategory(str, enum.Enum):
    CRYPTO = "crypto"
    FILESYSTEM = "filesystem"
    KEYCHAIN = "keychain"
    NETWORK = "network"
    BIOMETRICS = "biometrics"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SessionState(str, enum.Enum):
    ATTACHED = "attached"
    DETACHED = "detached"
    ERROR = "error"


class HookState(str, enum.Enum):
    ACTIVE = "active"
    FAILED = "failed"
    REPLACED = "replaced"


@dataclass
class TargetApp:
    bundle_id: str
    platform: Platform
    pid: int | None = None
    name: str = ""
    version: str = ""
    spawn: bool = False  # True → spawn fresh, False → attach to running


@dataclass
class Session:
    session_id: str
    target: TargetApp
    state: SessionState
    attached_at: datetime = field(default_factory=datetime.utcnow)
    # Opaque handle to the underlying frida.Session
    _frida_session: Any = field(default=None, repr=False)
    # Injected frida.Script handles, keyed by script name
    _scripts: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def is_active(self) -> bool:
        return self.state == SessionState.ATTACHED


@dataclass
class HookResult:
    hook_id: str
    class_name: str
    method_name: str
    platform: Platform
    state: HookState
    hook_type: str = "intercept"   # "intercept" | "replace"
    call_count: int = 0
    error: str = ""


@dataclass
class TraceEvent:
    event_id: str
    category: TraceCategory
    timestamp: datetime
    class_name: str
    method_name: str
    args: list[Any]
    return_value: Any
    thread_id: int
    call_stack: list[str] = field(default_factory=list)
    # Enriched fields set by post-processors
    sensitive_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class TraceSession:
    trace_id: str
    session: Session
    categories: list[TraceCategory]
    started_at: datetime
    events: list[TraceEvent] = field(default_factory=list)
    active: bool = True

    def events_by_category(self, cat: TraceCategory) -> list[TraceEvent]:
        return [e for e in self.events if e.category == cat]

    def to_json_records(self) -> list[dict[str, Any]]:
        out = []
        for ev in self.events:
            out.append({
                "event_id": ev.event_id,
                "category": ev.category.value,
                "timestamp": ev.timestamp.isoformat(),
                "class": ev.class_name,
                "method": ev.method_name,
                "args": ev.args,
                "return_value": ev.return_value,
                "thread_id": ev.thread_id,
                "call_stack": ev.call_stack,
                "sensitive_data": ev.sensitive_data,
            })
        return out


@dataclass
class Vulnerability:
    vuln_id: str
    title: str
    description: str
    severity: Severity
    category: str           # OWASP MASVS category: e.g. "MASVS-STORAGE-1"
    evidence: list[str]     # observed artefacts / log lines
    remediation: str
    cwe_id: str = ""        # e.g. "CWE-312"
    confidence: float = 1.0  # 0.0–1.0


@dataclass
class VulnReport:
    report_id: str
    app: TargetApp
    generated_at: datetime
    vulnerabilities: list[Vulnerability]
    scan_duration_seconds: float = 0.0

    def by_severity(self, sev: Severity) -> list[Vulnerability]:
        return [v for v in self.vulnerabilities if v.severity == sev]

    @property
    def critical_count(self) -> int:
        return len(self.by_severity(Severity.CRITICAL))

    @property
    def high_count(self) -> int:
        return len(self.by_severity(Severity.HIGH))

    def summary(self) -> str:
        counts = {s: len(self.by_severity(s)) for s in Severity}
        return (
            f"App: {self.app.bundle_id} ({self.app.platform.value.upper()})\n"
            + "\n".join(
                f"  {s.value.upper():8}: {counts[s]}" for s in Severity if counts[s]
            )
        )
