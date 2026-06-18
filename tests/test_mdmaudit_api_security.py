"""Tests for MDMAudit API security assessment — offline only."""

import pytest
from datetime import datetime

from mdmaudit.api_security.protocol import assess_mdm_api, _check_tls
from mdmaudit.models import AuthMethod, FindingSeverity


class TestAPISecurityNotAuthorized:
    def test_passive_only_info_finding(self):
        report = assess_mdm_api("https://mdm.example.com/api/v1", authorized=False)
        info_findings = [f for f in report.findings if f.severity == FindingSeverity.INFO]
        assert any("Not Authorized" in f.title or "Skipped" in f.title for f in info_findings)

    def test_no_active_probe_findings(self):
        report = assess_mdm_api("https://mdm.example.com/api/v1", authorized=False)
        active_probe_finding_ids = {"API-AUTH-001", "API-AUTH-002", "API-AUTH-003"}
        found_ids = {f.finding_id for f in report.findings}
        assert not found_ids.intersection(active_probe_finding_ids)

    def test_http_endpoint_critical_without_authorized(self):
        report = assess_mdm_api("http://mdm.example.com/api/v1", authorized=False)
        critical = [f for f in report.findings if f.severity == FindingSeverity.CRITICAL]
        assert any("Plaintext HTTP" in f.title for f in critical)

    def test_report_stores_endpoint(self):
        endpoint = "https://mdm.example.com/api/v1"
        report = assess_mdm_api(endpoint, authorized=False)
        assert report.endpoint == endpoint

    def test_report_has_tls_version(self):
        report = assess_mdm_api("https://mdm.example.com/api/v1", authorized=False)
        assert isinstance(report.tls_version, str)

    def test_report_has_scan_duration(self):
        report = assess_mdm_api("https://mdm.example.com/api/v1", authorized=False)
        assert report.scan_duration_seconds >= 0


class TestAPIReportProperties:
    def _make_report(self, **kwargs):
        from mdmaudit.models import APIFinding, APISecurityReport
        return APISecurityReport(
            report_id="r-001",
            endpoint="https://mdm.example.com/api",
            generated_at=datetime.utcnow(),
            tls_version="TLSv1.3",
            tls_ciphers=["TLS_AES_256_GCM_SHA384"],
            supports_certificate_pinning=False,
            has_rate_limiting=True,
            auth_method=AuthMethod.OAUTH2,
            findings=[
                APIFinding(
                    finding_id=f"F-{i}",
                    title=f"Finding {i}",
                    description="desc",
                    severity=s,
                    category="test",
                    evidence=[],
                    remediation="fix",
                    endpoint="https://mdm.example.com/api",
                )
                for i, s in enumerate([
                    FindingSeverity.CRITICAL,
                    FindingSeverity.HIGH,
                    FindingSeverity.MEDIUM,
                ])
            ],
        )

    def test_critical_count(self):
        report = self._make_report()
        assert report.critical_count == 1

    def test_by_severity_high(self):
        report = self._make_report()
        high = report.by_severity(FindingSeverity.HIGH)
        assert len(high) == 1

    def test_summary_contains_endpoint(self):
        report = self._make_report()
        assert "mdm.example.com" in report.summary()

    def test_summary_contains_tls_version(self):
        report = self._make_report()
        assert "TLSv1.3" in report.summary()


class TestAPISecurityHTTPEndpoint:
    def test_http_endpoint_flagged_critical(self):
        report = assess_mdm_api("http://internal-mdm.example.com/api/v1", authorized=False)
        critical_findings = [f for f in report.findings if f.severity == FindingSeverity.CRITICAL]
        assert len(critical_findings) >= 1
        assert any("HTTP" in f.title for f in critical_findings)

    def test_http_endpoint_cwe_319(self):
        report = assess_mdm_api("http://internal-mdm.example.com/api/v1", authorized=False)
        cwe_findings = [f for f in report.findings if f.cwe_id == "CWE-319"]
        assert len(cwe_findings) >= 1


class TestAPISecurityDeduplication:
    def test_no_duplicate_finding_ids(self):
        report = assess_mdm_api("https://mdm.example.com/api", authorized=False)
        ids = [f.finding_id for f in report.findings]
        assert len(ids) == len(set(ids))


class TestAPISecurityWithoutNetwork:
    """Tests that verify behaviour when network is unreachable (CI environment)."""

    def test_unreachable_https_does_not_raise(self):
        # TLS connection to unreachable host should not propagate exception
        try:
            report = assess_mdm_api(
                "https://mdm-nonexistent-host-12345.example.com/api",
                authorized=False,
                timeout=2,
            )
            assert report is not None
        except Exception as exc:
            pytest.fail(f"assess_mdm_api raised unexpectedly: {exc}")

    def test_unreachable_authorized_does_not_raise(self):
        try:
            report = assess_mdm_api(
                "https://mdm-nonexistent-host-12345.example.com/api",
                authorized=True,
                timeout=2,
            )
            assert report is not None
        except Exception as exc:
            pytest.fail(f"assess_mdm_api raised unexpectedly: {exc}")
