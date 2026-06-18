"""Tests for MDMAudit data models."""

import pytest
from datetime import datetime

from mdmaudit.models import (
    APIFinding,
    APISecurityReport,
    AttackEdge,
    AttackGraph,
    AttackNode,
    AttackPath,
    AuthMethod,
    DeviceOwnership,
    DevicePlatform,
    EnrollmentReport,
    Finding,
    FindingSeverity,
    MDMDeployment,
    MDMPlatform,
    ProfileFinding,
    ProfileReport,
    ProfileType,
    RogueProfile,
)


def _make_finding(severity: FindingSeverity, fid: str = "TEST-001") -> Finding:
    return Finding(
        finding_id=fid,
        title=f"Test Finding {fid}",
        description="Test description",
        severity=severity,
        category="test",
        evidence=["evidence 1"],
        remediation="Fix it",
        cwe_id="CWE-000",
    )


class TestFinding:
    def test_to_dict_contains_required_keys(self):
        f = _make_finding(FindingSeverity.HIGH)
        d = f.to_dict()
        assert "id" in d
        assert "title" in d
        assert "severity" in d
        assert "category" in d
        assert "remediation" in d

    def test_severity_value_in_dict(self):
        f = _make_finding(FindingSeverity.CRITICAL)
        assert f.to_dict()["severity"] == "critical"


class TestEnrollmentReport:
    def _make_report(self, findings=None) -> EnrollmentReport:
        return EnrollmentReport(
            report_id="r-001",
            mdm_platform=MDMPlatform.JAMF,
            generated_at=datetime.utcnow(),
            findings=findings or [],
        )

    def test_critical_count(self):
        findings = [
            _make_finding(FindingSeverity.CRITICAL, "C1"),
            _make_finding(FindingSeverity.CRITICAL, "C2"),
            _make_finding(FindingSeverity.HIGH, "H1"),
        ]
        report = self._make_report(findings)
        assert report.critical_count == 2
        assert report.high_count == 1

    def test_by_severity(self):
        findings = [
            _make_finding(FindingSeverity.HIGH, "H1"),
            _make_finding(FindingSeverity.MEDIUM, "M1"),
            _make_finding(FindingSeverity.MEDIUM, "M2"),
        ]
        report = self._make_report(findings)
        assert len(report.by_severity(FindingSeverity.MEDIUM)) == 2
        assert len(report.by_severity(FindingSeverity.LOW)) == 0

    def test_summary_contains_platform(self):
        report = self._make_report()
        summary = report.summary()
        assert "JAMF" in summary

    def test_empty_report(self):
        report = self._make_report()
        assert report.critical_count == 0
        assert "0 total" in report.summary()


class TestProfileReport:
    def _make_profile_finding(self, severity: FindingSeverity, profile_id: str = "com.example.test") -> ProfileFinding:
        return ProfileFinding(
            finding_id=f"PF-{severity.value}",
            title=f"Profile finding {severity.value}",
            description="desc",
            severity=severity,
            category="profile-test",
            evidence=["evidence"],
            remediation="fix",
            profile_identifier=profile_id,
            profile_type=ProfileType.WIFI,
        )

    def test_by_profile(self):
        findings = [
            self._make_profile_finding(FindingSeverity.HIGH, "profile-A"),
            self._make_profile_finding(FindingSeverity.MEDIUM, "profile-A"),
            self._make_profile_finding(FindingSeverity.HIGH, "profile-B"),
        ]
        report = ProfileReport(
            report_id="r-002",
            device_identifier="test-device",
            device_platform=DevicePlatform.IOS,
            generated_at=datetime.utcnow(),
            profiles_analyzed=2,
            findings=findings,
        )
        assert len(report.by_profile("profile-A")) == 2
        assert len(report.by_profile("profile-B")) == 1
        assert len(report.by_profile("nonexistent")) == 0

    def test_summary_contains_platform(self):
        report = ProfileReport(
            report_id="r-003",
            device_identifier="iphone-001",
            device_platform=DevicePlatform.IOS,
            generated_at=datetime.utcnow(),
            profiles_analyzed=3,
            findings=[],
        )
        assert "IOS" in report.summary()
        assert "iphone-001" in report.summary()


class TestAPISecurityReport:
    def test_creation(self):
        report = APISecurityReport(
            report_id="r-api-001",
            endpoint="https://mdm.example.com/api/v1",
            generated_at=datetime.utcnow(),
            tls_version="TLSv1.3",
            tls_ciphers=["TLS_AES_256_GCM_SHA384"],
            supports_certificate_pinning=True,
            has_rate_limiting=True,
            auth_method=AuthMethod.OAUTH2,
            findings=[],
        )
        assert report.critical_count == 0
        assert "mdm.example.com" in report.summary()

    def test_by_severity(self):
        findings = [
            APIFinding(
                finding_id="API-001",
                title="Test API Finding",
                description="desc",
                severity=FindingSeverity.HIGH,
                category="api-test",
                evidence=[],
                remediation="fix",
                endpoint="https://example.com",
                http_method="GET",
            )
        ]
        report = APISecurityReport(
            report_id="r-api-002",
            endpoint="https://example.com",
            generated_at=datetime.utcnow(),
            tls_version="TLSv1.3",
            tls_ciphers=[],
            supports_certificate_pinning=False,
            has_rate_limiting=False,
            auth_method=AuthMethod.USERNAME_PASSWORD,
            findings=findings,
        )
        assert len(report.by_severity(FindingSeverity.HIGH)) == 1
        assert len(report.by_severity(FindingSeverity.CRITICAL)) == 0


class TestAttackGraph:
    def _make_graph(self) -> AttackGraph:
        node_a = AttackNode(
            node_id="n-a", node_type="device", name="Device A", platform="ios"
        )
        node_b = AttackNode(
            node_id="n-b", node_type="service", name="MDM Server", platform="server"
        )
        edge = AttackEdge(
            edge_id="e-1",
            source_id="n-a",
            target_id="n-b",
            technique="Token Replay",
            mitre_id="T1550",
            description="Replay device token",
            difficulty="medium",
            impact="API access",
        )
        path = AttackPath(
            path_id="p-1",
            name="Device to MDM",
            node_ids=["n-a", "n-b"],
            edge_ids=["e-1"],
            severity=FindingSeverity.HIGH,
            description="Path description",
            remediation="Fix token validation",
        )
        return AttackGraph(
            graph_id="g-001",
            generated_at=datetime.utcnow(),
            nodes=[node_a, node_b],
            edges=[edge],
            attack_paths=[path],
        )

    def test_graph_properties(self):
        graph = self._make_graph()
        assert len(graph.nodes) == 2
        assert len(graph.edges) == 1
        assert len(graph.attack_paths) == 1

    def test_node_by_id(self):
        graph = self._make_graph()
        node = graph.node_by_id("n-a")
        assert node is not None
        assert node.name == "Device A"
        assert graph.node_by_id("nonexistent") is None

    def test_edges_from(self):
        graph = self._make_graph()
        edges = graph.edges_from("n-a")
        assert len(edges) == 1
        assert edges[0].target_id == "n-b"

    def test_critical_paths_empty(self):
        graph = self._make_graph()
        assert len(graph.critical_paths) == 0  # path is HIGH, not CRITICAL

    def test_summary(self):
        graph = self._make_graph()
        summary = graph.summary()
        assert "2" in summary  # nodes
        assert "1" in summary  # edges

    def test_high_impact_paths(self):
        graph = self._make_graph()
        assert len(graph.high_impact_paths) == 1


class TestRogueProfile:
    def test_is_suspicious(self):
        rogue = RogueProfile(
            profile_id="r-001",
            display_name="Suspicious MDM",
            organization="BadActor",
            server_url="https://evil.example.com",
            installed_at=None,
            profile_type=ProfileType.MDM,
            severity=FindingSeverity.CRITICAL,
            reason="Matches stalkerware signature",
        )
        assert rogue.is_suspicious is True

    def test_not_suspicious_low(self):
        rogue = RogueProfile(
            profile_id="r-002",
            display_name="Wi-Fi Profile",
            organization="Corp IT",
            server_url="https://mdm.corp.com",
            installed_at=None,
            profile_type=ProfileType.WIFI,
            severity=FindingSeverity.LOW,
            reason="Non-standard port",
        )
        assert rogue.is_suspicious is False

    def test_to_dict(self):
        rogue = RogueProfile(
            profile_id="r-003",
            display_name="Test Profile",
            organization="Test Org",
            server_url="https://mdm.test.com",
            installed_at=datetime(2024, 1, 15, 10, 0, 0),
            profile_type=ProfileType.MDM,
            severity=FindingSeverity.HIGH,
            reason="Unrecognised MDM server",
            indicators=["indicator1", "indicator2"],
        )
        d = rogue.to_dict()
        assert d["profile_id"] == "r-003"
        assert d["severity"] == "high"
        assert d["installed_at"] == "2024-01-15T10:00:00"
        assert len(d["indicators"]) == 2


class TestMDMDeployment:
    def test_creation(self):
        deployment = MDMDeployment(
            deployment_id="d-001",
            platform=MDMPlatform.INTUNE,
            server_url="https://intune.example.com",
            organization="Contoso",
            device_count=500,
            ldap_integrated=True,
            mfa_required=True,
            linked_services=["Azure AD", "SCCM"],
        )
        assert deployment.device_count == 500
        assert deployment.ldap_integrated is True
        assert len(deployment.linked_services) == 2
