"""Tests for AppHook vulnerability scanner."""

import pytest
from datetime import datetime

from apphook.models import (
    Platform,
    Session,
    SessionState,
    Severity,
    TargetApp,
    TraceCategory,
    TraceEvent,
    TraceSession,
)
from apphook.vuln.scanner import VulnerabilityScanner, SECRET_PATTERNS


def _make_app(platform=Platform.ANDROID) -> TargetApp:
    return TargetApp(bundle_id="com.example.testapp", platform=platform)


def _make_session() -> Session:
    app = _make_app()
    return Session(session_id="s-test", target=app, state=SessionState.ATTACHED)


def _make_trace(events=None) -> TraceSession:
    return TraceSession(
        trace_id="t-test",
        session=_make_session(),
        categories=list(TraceCategory),
        started_at=datetime.utcnow(),
        events=events or [],
    )


def _event(
    category: TraceCategory,
    cls: str = "TestClass",
    method: str = "testMethod",
    args: dict | None = None,
    ret=None,
) -> TraceEvent:
    return TraceEvent(
        event_id=f"ev-{category.value}",
        category=category,
        timestamp=datetime.utcnow(),
        class_name=cls,
        method_name=method,
        args=args or {},
        return_value=ret,
        thread_id=1,
    )


class TestSecretPatterns:
    def test_aws_key_detected(self):
        text = "key = AKIAIOSFODNN7EXAMPLE"
        assert SECRET_PATTERNS["AWS Access Key"].search(text) is not None

    def test_google_api_key_detected(self):
        text = "api_key=AIzaSyD-9tSrke72I6e0DVblZugFC"
        assert SECRET_PATTERNS["Google API Key"].search(text) is not None

    def test_jwt_detected(self):
        # Minimal valid JWT structure
        text = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert SECRET_PATTERNS["JWT Token"].search(text) is not None

    def test_generic_password_detected(self):
        text = 'password: "s3cr3tP@ssw0rd"'
        assert SECRET_PATTERNS["Generic Password"].search(text) is not None

    def test_pem_private_key_detected(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCA..."
        assert SECRET_PATTERNS["Private Key (PEM)"].search(text) is not None

    def test_clean_text_no_match(self):
        text = "Hello world, this is a normal string with no secrets"
        for pattern in SECRET_PATTERNS.values():
            assert pattern.search(text) is None


class TestInsecureStorageDetection:
    def test_sensitive_sharedprefs_key_flagged(self):
        ev = _event(
            TraceCategory.FILESYSTEM,
            cls="SharedPreferences",
            method="putString",
            args={"key": "userPassword", "value_preview": "s3cr3t"},
        )
        trace = _make_trace(events=[ev])
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        storage_vulns = [v for v in report.vulnerabilities if "Storage" in v.title or "STORAGE" in v.category]
        assert len(storage_vulns) >= 1

    def test_sql_with_sensitive_column_flagged(self):
        ev = _event(
            TraceCategory.FILESYSTEM,
            cls="SQLiteDatabase",
            method="execSQL",
            args={"sql": "INSERT INTO users (username, password) VALUES (?, ?)"},
        )
        trace = _make_trace(events=[ev])
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        storage_vulns = [v for v in report.vulnerabilities if "STORAGE" in v.category]
        assert len(storage_vulns) >= 1

    def test_external_storage_write_flagged(self):
        ev = _event(
            TraceCategory.FILESYSTEM,
            cls="FileOutputStream",
            method="<init>",
            args={"path": "/sdcard/Download/credentials.json"},
        )
        trace = _make_trace(events=[ev])
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        assert any("Storage" in v.title or "storage" in v.category.lower()
                   for v in report.vulnerabilities)

    def test_clean_filesystem_events_not_flagged(self):
        ev = _event(
            TraceCategory.FILESYSTEM,
            cls="FileOutputStream",
            method="<init>",
            args={"path": "/data/app/com.example/cache/image.png"},
        )
        trace = _make_trace(events=[ev])
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        storage_vulns = [v for v in report.vulnerabilities
                         if "MASVS-STORAGE-1" == v.vuln_id]
        assert len(storage_vulns) == 0


class TestWeakCryptoDetection:
    def test_rc4_flagged_as_high(self):
        ev = _event(
            TraceCategory.CRYPTO,
            cls="Cipher",
            method="getInstance",
            args={"transformation": "RC4"},
        )
        trace = _make_trace(events=[ev])
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        rc4_vulns = [v for v in report.vulnerabilities if "RC4" in v.title]
        assert len(rc4_vulns) == 1
        assert rc4_vulns[0].severity == Severity.HIGH

    def test_ecb_mode_flagged(self):
        ev = _event(
            TraceCategory.CRYPTO,
            cls="Cipher",
            method="getInstance",
            args={"transformation": "AES/ECB/PKCS5Padding"},
        )
        trace = _make_trace(events=[ev])
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        ecb_vulns = [v for v in report.vulnerabilities if "ECB" in v.title]
        assert len(ecb_vulns) >= 1

    def test_aes_gcm_not_flagged(self):
        ev = _event(
            TraceCategory.CRYPTO,
            cls="Cipher",
            method="getInstance",
            args={"transformation": "AES/GCM/NoPadding"},
        )
        trace = _make_trace(events=[ev])
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        crypto_vulns = [v for v in report.vulnerabilities if "Weak Crypto" in v.title]
        assert len(crypto_vulns) == 0


class TestCleartextNetworkDetection:
    def test_http_url_flagged(self):
        ev = _event(
            TraceCategory.NETWORK,
            cls="okhttp3.RealCall",
            method="execute",
            args={"url": "http://api.example.com/login", "method": "POST"},
        )
        trace = _make_trace(events=[ev])
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        net_vulns = [v for v in report.vulnerabilities if "NETWORK" in v.category]
        assert len(net_vulns) >= 1
        assert net_vulns[0].severity == Severity.HIGH

    def test_https_url_not_flagged(self):
        ev = _event(
            TraceCategory.NETWORK,
            cls="okhttp3.RealCall",
            method="execute",
            args={"url": "https://api.example.com/login", "method": "POST"},
        )
        trace = _make_trace(events=[ev])
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        net_vulns = [v for v in report.vulnerabilities
                     if v.vuln_id == "MASVS-NETWORK-1"]
        assert len(net_vulns) == 0


class TestBiometricBypassRiskDetection:
    def test_biometric_without_crypto_object_flagged(self):
        ev = _event(
            TraceCategory.BIOMETRICS,
            cls="BiometricPrompt",
            method="authenticate",
            args={"has_crypto": False},
        )
        trace = _make_trace(events=[ev])
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        bio_vulns = [v for v in report.vulnerabilities if "AUTH" in v.category]
        assert len(bio_vulns) == 1
        assert bio_vulns[0].severity == Severity.HIGH

    def test_biometric_with_crypto_object_not_flagged(self):
        ev = _event(
            TraceCategory.BIOMETRICS,
            cls="BiometricPrompt",
            method="authenticate",
            args={"has_crypto": True},
        )
        trace = _make_trace(events=[ev])
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        bio_vulns = [v for v in report.vulnerabilities
                     if v.vuln_id == "MASVS-AUTH-2"]
        assert len(bio_vulns) == 0


class TestHardcodedSecretScanning:
    def test_aws_key_in_trace_args_flagged(self):
        ev = _event(
            TraceCategory.NETWORK,
            args={"header": "Authorization: AWS AKIAIOSFODNN7EXAMPLE/20230101"},
        )
        trace = _make_trace(events=[ev])
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        secret_vulns = [v for v in report.vulnerabilities
                        if "AWS Access Key" in v.title]
        assert len(secret_vulns) == 1

    def test_memory_scan_finds_api_key(self):
        scanner = VulnerabilityScanner(_make_app(), trace=_make_trace())
        scanner.add_memory_scan_results([
            'config = {"api_key": "AIzaSyD-9tSrke72I6e0DVblZugFC"}'
        ])
        report = scanner.scan()
        secret_vulns = [v for v in report.vulnerabilities
                        if "Google API Key" in v.title]
        assert len(secret_vulns) == 1
        assert secret_vulns[0].severity == Severity.HIGH

    def test_no_false_positive_for_clean_memory(self):
        scanner = VulnerabilityScanner(_make_app(), trace=_make_trace())
        scanner.add_memory_scan_results(["Hello world", "application started", "version 1.0"])
        report = scanner.scan()
        secret_vulns = [v for v in report.vulnerabilities
                        if "MASVS-STORAGE-2" in v.vuln_id]
        assert len(secret_vulns) == 0


class TestVulnDeduplication:
    def test_duplicate_vulns_not_added_twice(self):
        # Same pattern, two events — should only produce one finding
        events = [
            _event(TraceCategory.NETWORK,
                   args={"url": "http://example.com/a", "method": "GET"}),
            _event(TraceCategory.NETWORK,
                   args={"url": "http://example.com/b", "method": "POST"}),
        ]
        trace = _make_trace(events=events)
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        net_vulns = [v for v in report.vulnerabilities
                     if v.vuln_id == "MASVS-NETWORK-1"]
        assert len(net_vulns) == 1  # deduplicated


class TestReportSorting:
    def test_report_sorted_critical_first(self):
        events = [
            _event(TraceCategory.NETWORK,
                   args={"url": "http://insecure.example.com/", "method": "GET"}),
            _event(TraceCategory.CRYPTO,
                   args={"transformation": "RC4"}),
        ]
        trace = _make_trace(events=events)
        scanner = VulnerabilityScanner(_make_app(), trace=trace)
        report = scanner.scan()
        if len(report.vulnerabilities) >= 2:
            order = {Severity.CRITICAL: 0, Severity.HIGH: 1,
                     Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
            severities = [order[v.severity] for v in report.vulnerabilities]
            assert severities == sorted(severities)
