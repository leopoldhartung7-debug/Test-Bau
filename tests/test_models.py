"""Tests for MobileAudit data models."""

import pytest
from mobileaudit.models import (
    ComplianceControl,
    ComplianceReport,
    ComplianceStatus,
    DeviceProfile,
    IOC,
    InstalledApp,
    Platform,
    Severity,
    Vulnerability,
    ConnectionType,
)
from datetime import datetime


def make_profile(platform=Platform.IOS, os_version="16.0") -> DeviceProfile:
    return DeviceProfile(
        platform=platform,
        udid="test-udid-001",
        serial_number="SN123456",
        model="iPhone14,3",
        os_version=os_version,
        build_number="20A362",
        connection_type=ConnectionType.USB,
    )


def make_report(pass_count=3, fail_count=2, warn_count=1) -> ComplianceReport:
    controls = []
    for i in range(pass_count):
        controls.append(ComplianceControl(
            control_id=f"CIS-{i}",
            framework="CIS",
            title=f"Control {i}",
            description="",
            status=ComplianceStatus.PASS,
            severity=Severity.HIGH,
        ))
    for i in range(fail_count):
        controls.append(ComplianceControl(
            control_id=f"CIS-F{i}",
            framework="CIS",
            title=f"Fail Control {i}",
            description="",
            status=ComplianceStatus.FAIL,
            severity=Severity.CRITICAL,
        ))
    for i in range(warn_count):
        controls.append(ComplianceControl(
            control_id=f"CIS-W{i}",
            framework="CIS",
            title=f"Warn Control {i}",
            description="",
            status=ComplianceStatus.WARN,
            severity=Severity.MEDIUM,
        ))
    return ComplianceReport(
        device_udid="test-udid-001",
        platform=Platform.IOS,
        generated_at=datetime.utcnow(),
        controls=controls,
    )


class TestDeviceProfile:
    def test_defaults(self):
        profile = make_profile()
        assert profile.platform == Platform.IOS
        assert profile.is_jailbroken is False
        assert profile.is_rooted is False
        assert profile.installed_apps == []
        assert profile.installed_profiles == []

    def test_jailbroken_flag(self):
        profile = make_profile()
        profile.is_jailbroken = True
        profile.root_method = "checkra1n (checkm8)"
        assert profile.is_jailbroken
        assert "checkra1n" in profile.root_method


class TestComplianceReport:
    def test_filter_methods(self):
        report = make_report(pass_count=3, fail_count=2, warn_count=1)
        assert len(report.passed()) == 3
        assert len(report.failed()) == 2
        assert len(report.warnings()) == 1

    def test_compute_score_all_pass(self):
        controls = [
            ComplianceControl(
                control_id="CIS-1",
                framework="CIS",
                title="A",
                description="",
                status=ComplianceStatus.PASS,
                severity=Severity.HIGH,
            )
        ]
        report = ComplianceReport(
            device_udid="x",
            platform=Platform.IOS,
            generated_at=datetime.utcnow(),
            controls=controls,
        )
        assert report.compute_score() == 100.0

    def test_compute_score_all_fail(self):
        controls = [
            ComplianceControl(
                control_id="CIS-1",
                framework="CIS",
                title="A",
                description="",
                status=ComplianceStatus.FAIL,
                severity=Severity.CRITICAL,
            )
        ]
        report = ComplianceReport(
            device_udid="x",
            platform=Platform.IOS,
            generated_at=datetime.utcnow(),
            controls=controls,
        )
        assert report.compute_score() == 0.0

    def test_compute_score_mixed(self):
        # 1 HIGH pass (weight 3), 1 CRITICAL fail (weight 4)
        # total_weight = 7, pass_weight = 3
        # score = 3/7 * 100 ≈ 42.9
        report = make_report(pass_count=0, fail_count=0, warn_count=0)
        report.controls = [
            ComplianceControl("C1", "CIS", "T", "", ComplianceStatus.PASS, severity=Severity.HIGH),
            ComplianceControl("C2", "CIS", "T", "", ComplianceStatus.FAIL, severity=Severity.CRITICAL),
        ]
        score = report.compute_score()
        assert 42.0 < score < 43.5

    def test_empty_report(self):
        report = ComplianceReport(
            device_udid="x",
            platform=Platform.IOS,
            generated_at=datetime.utcnow(),
            controls=[],
        )
        assert report.compute_score() == 0.0


class TestVulnerability:
    def test_creation(self):
        vuln = Vulnerability(
            cve_id="CVE-2023-41064",
            title="BLASTPASS",
            description="Zero-click exploit",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            affected_versions=["16.6"],
            platform=Platform.IOS,
            exploit_available=True,
            exploit_type="remote_code_execution",
        )
        assert vuln.severity == Severity.CRITICAL
        assert vuln.exploit_available is True
        assert vuln.cvss_score == 9.8


class TestIOC:
    def test_creation(self):
        ioc = IOC(
            ioc_id="test-001",
            name="Pegasus artefact",
            description="Found in /private/var/tmp",
            severity=Severity.CRITICAL,
            indicator_type="file",
            value="/private/var/tmp/com.apple.backboardd",
            threat_family="Pegasus",
            confidence=0.95,
        )
        assert ioc.confidence == 0.95
        assert ioc.threat_family == "Pegasus"
