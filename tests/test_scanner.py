"""Tests for MobileReconScanner core logic (offline, no device required)."""

from __future__ import annotations

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from mobileaudit.models import (
    ComplianceStatus,
    ConnectionType,
    DeviceProfile,
    InstalledApp,
    IOC,
    Platform,
    Severity,
    Vulnerability,
)
from mobileaudit.scanner import (
    DeviceConnection,
    MobileReconScanner,
    ScanResult,
    _compute_risk_score,
)


def _ios_profile(jailbroken=False, os_version="16.5", model="iPhone14,3") -> DeviceProfile:
    profile = DeviceProfile(
        platform=Platform.IOS,
        udid="UDID-TEST-IOS",
        serial_number="SN-IOS-001",
        model=model,
        os_version=os_version,
        build_number="20F66",
        connection_type=ConnectionType.USB,
        manufacturer="Apple",
        encryption_enabled=True,
    )
    profile.is_jailbroken = jailbroken
    if jailbroken:
        profile.root_method = "checkra1n (checkm8)"
    return profile


def _android_profile(rooted=False, os_version="13", bootloader_locked=True) -> DeviceProfile:
    profile = DeviceProfile(
        platform=Platform.ANDROID,
        udid="emulator-5554",
        serial_number="SERIAL-ANDROID",
        model="Pixel 7",
        os_version=os_version,
        build_number="TP1A.220624.014",
        connection_type=ConnectionType.USB,
        manufacturer="Google",
        security_patch_level="2023-01-05",
        bootloader_locked=bootloader_locked,
        encryption_enabled=True,
    )
    profile.is_rooted = rooted
    return profile


class TestMobileReconScannerInit:
    def test_offline_mode(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        assert scanner._nvd is None

    def test_online_mode(self):
        scanner = MobileReconScanner(fetch_nvd=True)
        assert scanner._nvd is not None


class TestAssessVulnerabilities:
    def test_ios_builtin_vulns_old_version(self):
        """Old iOS version should match multiple built-in CVEs."""
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _ios_profile(os_version="15.3")
        vulns = scanner.assess_vulnerabilities(profile)
        cve_ids = [v.cve_id for v in vulns]
        # CVE-2022-22620 affects ≤15.3
        assert "CVE-2022-22620" in cve_ids

    def test_ios_builtin_vulns_patched_version(self):
        """Patched iOS version should have no BLASTPASS match."""
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _ios_profile(os_version="17.0")
        vulns = scanner.assess_vulnerabilities(profile)
        cve_ids = [v.cve_id for v in vulns]
        # CVE-2023-41064 affects ≤16.6 — should NOT appear on 17.0
        assert "CVE-2023-41064" not in cve_ids

    def test_checkm8_applies_to_a11_model(self):
        """checkm8 CVE should match A11-era model regardless of iOS version."""
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _ios_profile(os_version="16.0", model="iPhone10,1")  # iPhone 8 (A11)
        vulns = scanner.assess_vulnerabilities(profile)
        cve_ids = [v.cve_id for v in vulns]
        assert "CVE-2019-8900" in cve_ids

    def test_sorted_exploitable_first(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _ios_profile(os_version="15.3")
        vulns = scanner.assess_vulnerabilities(profile)
        if len(vulns) >= 2:
            exploitable = [v for v in vulns if v.exploit_available]
            non_exploitable = [v for v in vulns if not v.exploit_available]
            # All exploitable vulns should appear before all non-exploitable ones
            if exploitable and non_exploitable:
                last_exploit_idx = max(vulns.index(v) for v in exploitable)
                first_non_idx = min(vulns.index(v) for v in non_exploitable)
                assert last_exploit_idx < first_non_idx

    def test_android_samsung_exynos_vuln(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _android_profile(os_version="12", bootloader_locked=True)
        profile.manufacturer = "Samsung"
        vulns = scanner.assess_vulnerabilities(profile)
        cve_ids = [v.cve_id for v in vulns]
        assert "CVE-2023-24033" in cve_ids

    def test_android_non_samsung_no_exynos_vuln(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _android_profile(os_version="12")
        profile.manufacturer = "Google"
        vulns = scanner.assess_vulnerabilities(profile)
        cve_ids = [v.cve_id for v in vulns]
        assert "CVE-2023-24033" not in cve_ids


class TestAuditConfiguration:
    def test_ios_jailbroken_fails_control(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _ios_profile(jailbroken=True)
        report = scanner.audit_configuration(profile)
        jb_control = next(
            (c for c in report.failed() if "Jailbreak" in c.title), None
        )
        assert jb_control is not None
        assert jb_control.severity == Severity.CRITICAL

    def test_ios_clean_device_score(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _ios_profile(jailbroken=False)
        profile.encryption_enabled = True
        report = scanner.audit_configuration(profile)
        # Encryption and no-jailbreak should both pass
        enc = next((c for c in report.passed() if "Encryption" in c.title or "Protection" in c.title), None)
        no_jb = next((c for c in report.passed() if "Jailbreak" in c.title), None)
        assert enc is not None or no_jb is not None

    def test_android_unlocked_bootloader_fails(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _android_profile(bootloader_locked=False)
        report = scanner.audit_configuration(profile)
        bl_control = next(
            (c for c in report.failed() if "Bootloader" in c.title), None
        )
        assert bl_control is not None
        assert bl_control.severity == Severity.CRITICAL

    def test_android_rooted_fails(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _android_profile(rooted=True)
        report = scanner.audit_configuration(profile)
        root_control = next(
            (c for c in report.failed() if "Rooted" in c.title or "Root" in c.title), None
        )
        assert root_control is not None

    def test_android_old_patch_fails(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _android_profile(os_version="12")
        profile.security_patch_level = "2020-01-05"  # very old
        report = scanner.audit_configuration(profile)
        patch_control = next(
            (c for c in report.failed() if "Patch" in c.title or "Security" in c.title), None
        )
        assert patch_control is not None


class TestDetectCompromiseIndicators:
    def test_ios_stalkerware_detected(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _ios_profile()
        profile.installed_apps = [
            InstalledApp(bundle_id="com.flexispy.ios", name="FlexiSpy", version="1.0"),
        ]
        iocs = scanner.detect_compromise_indicators(profile)
        assert any("flexispy" in i.ioc_id.lower() or "flexispy" in i.value.lower() for i in iocs)

    def test_ios_pegasus_entitlement_flagged(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _ios_profile()
        profile.installed_apps = [
            InstalledApp(
                bundle_id="com.suspicious.app",
                name="Suspicious",
                version="1.0",
                entitlements={
                    "com.apple.private.security.no-sandbox": True,
                    "com.apple.system-task-ports": True,
                },
                is_system=False,
            )
        ]
        iocs = scanner.detect_compromise_indicators(profile)
        assert any(i.threat_family == "Pegasus" for i in iocs)

    def test_android_stalkerware_detected(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _android_profile()
        profile.installed_apps = [
            InstalledApp(bundle_id="com.mspy.android", name="mSpy", version="1.0"),
        ]
        iocs = scanner.detect_compromise_indicators(profile)
        assert any("mspy" in i.ioc_id.lower() or "mspy" in i.value.lower() for i in iocs)

    def test_android_permission_abuse_detected(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _android_profile()
        # App with the full spyware permission set
        profile.installed_apps = [
            InstalledApp(
                bundle_id="com.example.shady",
                name="ShaDy",
                version="1.0",
                is_system=False,
                permissions=[
                    "android.permission.READ_SMS",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.READ_CONTACTS",
                    "android.permission.ACCESS_FINE_LOCATION",
                    "android.permission.RECORD_AUDIO",
                    "android.permission.READ_CALL_LOG",
                ],
            )
        ]
        iocs = scanner.detect_compromise_indicators(profile)
        assert any(i.indicator_type == "permission" for i in iocs)

    def test_android_system_mimic_detected(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _android_profile()
        profile.installed_apps = [
            InstalledApp(
                bundle_id="com.android.update.service",
                name="System Update",
                version="1.0",
                is_system=False,
            )
        ]
        iocs = scanner.detect_compromise_indicators(profile)
        assert any("system_mimic" in i.ioc_id.lower() or "mimic" in i.name.lower() for i in iocs)

    def test_iocs_sorted_by_confidence(self):
        scanner = MobileReconScanner(fetch_nvd=False)
        profile = _android_profile()
        profile.installed_apps = [
            InstalledApp(bundle_id="com.mspy.android", name="mSpy", version="1.0"),
            InstalledApp(
                bundle_id="com.android.fake",
                name="Fake",
                version="1.0",
                is_system=False,
            ),
        ]
        iocs = scanner.detect_compromise_indicators(profile)
        if len(iocs) >= 2:
            for i in range(len(iocs) - 1):
                assert iocs[i].confidence >= iocs[i + 1].confidence


class TestComputeRiskScore:
    def _make_compliance_report(self, crit_fails=0):
        from mobileaudit.models import ComplianceControl, ComplianceReport
        controls = [
            ComplianceControl(
                control_id=f"C{i}",
                framework="CIS",
                title="T",
                description="",
                status=ComplianceStatus.FAIL,
                severity=Severity.CRITICAL,
            )
            for i in range(crit_fails)
        ]
        return ComplianceReport(
            device_udid="x",
            platform=Platform.IOS,
            generated_at=datetime.utcnow(),
            controls=controls,
        )

    def test_clean_device_score_zero(self):
        profile = _ios_profile()
        report = self._make_compliance_report(crit_fails=0)
        score, level = _compute_risk_score(profile, [], report, [])
        assert score == 0.0
        assert level == Severity.INFO

    def test_jailbroken_adds_to_score(self):
        profile = _ios_profile(jailbroken=True)
        report = self._make_compliance_report(crit_fails=0)
        score, level = _compute_risk_score(profile, [], report, [])
        assert score >= 30

    def test_high_confidence_ioc_raises_score(self):
        profile = _ios_profile()
        report = self._make_compliance_report(crit_fails=0)
        ioc = IOC(
            ioc_id="test-ioc",
            name="Test IOC",
            description="",
            severity=Severity.CRITICAL,
            indicator_type="app",
            value="com.evil.app",
            threat_family="Test",
            confidence=0.95,
        )
        score, level = _compute_risk_score(profile, [], report, [ioc])
        assert score >= 20

    def test_score_capped_at_100(self):
        profile = _ios_profile(jailbroken=True)
        report = self._make_compliance_report(crit_fails=5)
        vulns = [
            Vulnerability(
                cve_id=f"CVE-FAKE-{i}",
                title="Fake",
                description="",
                severity=Severity.CRITICAL,
                cvss_score=10.0,
                affected_versions=["16.0"],
                platform=Platform.IOS,
                exploit_available=True,
            )
            for i in range(10)
        ]
        iocs = [
            IOC(
                ioc_id=f"ioc-{i}",
                name="IOC",
                description="",
                severity=Severity.CRITICAL,
                indicator_type="app",
                value="evil",
                threat_family="Pegasus",
                confidence=1.0,
            )
            for i in range(5)
        ]
        score, _ = _compute_risk_score(profile, vulns, report, iocs)
        assert score == 100.0
