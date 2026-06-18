"""Tests for AppHook data models."""

import pytest
from datetime import datetime

from apphook.models import (
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
    Severity,
)


def _make_session(state=SessionState.ATTACHED) -> Session:
    app = TargetApp(bundle_id="com.example.test", platform=Platform.ANDROID)
    return Session(session_id="s-001", target=app, state=state)


def _make_trace(events=None) -> TraceSession:
    session = _make_session()
    return TraceSession(
        trace_id="t-001",
        session=session,
        categories=[TraceCategory.NETWORK, TraceCategory.CRYPTO],
        started_at=datetime.utcnow(),
        events=events or [],
    )


class TestTargetApp:
    def test_defaults(self):
        app = TargetApp(bundle_id="com.foo.bar", platform=Platform.IOS)
        assert app.pid is None
        assert app.spawn is False

    def test_platform_values(self):
        assert Platform.IOS.value == "ios"
        assert Platform.ANDROID.value == "android"


class TestSession:
    def test_is_active_attached(self):
        session = _make_session(SessionState.ATTACHED)
        assert session.is_active is True

    def test_is_active_detached(self):
        session = _make_session(SessionState.DETACHED)
        assert session.is_active is False

    def test_is_active_error(self):
        session = _make_session(SessionState.ERROR)
        assert session.is_active is False


class TestHookResult:
    def test_creation(self):
        hook = HookResult(
            hook_id="h-001",
            class_name="NSURLSession",
            method_name="dataTaskWithRequest:completionHandler:",
            platform=Platform.IOS,
            state=HookState.ACTIVE,
        )
        assert hook.call_count == 0
        assert hook.state == HookState.ACTIVE

    def test_states(self):
        assert HookState.ACTIVE.value == "active"
        assert HookState.FAILED.value == "failed"
        assert HookState.REPLACED.value == "replaced"


class TestTraceSession:
    def _make_event(self, category: TraceCategory) -> TraceEvent:
        return TraceEvent(
            event_id=f"ev-{category.value}",
            category=category,
            timestamp=datetime.utcnow(),
            class_name="TestClass",
            method_name="testMethod",
            args={},
            return_value=None,
            thread_id=1,
        )

    def test_events_by_category(self):
        events = [
            self._make_event(TraceCategory.NETWORK),
            self._make_event(TraceCategory.CRYPTO),
            self._make_event(TraceCategory.NETWORK),
        ]
        trace = _make_trace(events=events)
        net_events = trace.events_by_category(TraceCategory.NETWORK)
        assert len(net_events) == 2

    def test_to_json_records(self):
        events = [self._make_event(TraceCategory.CRYPTO)]
        trace = _make_trace(events=events)
        records = trace.to_json_records()
        assert len(records) == 1
        rec = records[0]
        assert rec["category"] == "crypto"
        assert rec["class"] == "TestClass"
        assert "timestamp" in rec

    def test_empty_trace(self):
        trace = _make_trace(events=[])
        assert trace.to_json_records() == []
        assert trace.events_by_category(TraceCategory.NETWORK) == []


class TestVulnReport:
    def _make_vuln(self, severity: Severity) -> Vulnerability:
        return Vulnerability(
            vuln_id=f"v-{severity.value}",
            title=f"Test {severity.value}",
            description="desc",
            severity=severity,
            category="MASVS-STORAGE",
            evidence=["evidence line"],
            remediation="fix it",
        )

    def test_by_severity_filtering(self):
        app = TargetApp(bundle_id="com.test", platform=Platform.IOS)
        report = VulnReport(
            report_id="r-001",
            app=app,
            generated_at=datetime.utcnow(),
            vulnerabilities=[
                self._make_vuln(Severity.CRITICAL),
                self._make_vuln(Severity.HIGH),
                self._make_vuln(Severity.HIGH),
                self._make_vuln(Severity.LOW),
            ],
        )
        assert report.critical_count == 1
        assert report.high_count == 2
        assert len(report.by_severity(Severity.LOW)) == 1

    def test_summary_contains_bundle_id(self):
        app = TargetApp(bundle_id="com.example.banking", platform=Platform.ANDROID)
        report = VulnReport(
            report_id="r-002",
            app=app,
            generated_at=datetime.utcnow(),
            vulnerabilities=[self._make_vuln(Severity.HIGH)],
        )
        summary = report.summary()
        assert "com.example.banking" in summary
        assert "ANDROID" in summary
