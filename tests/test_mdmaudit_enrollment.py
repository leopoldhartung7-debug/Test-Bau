"""Tests for MDMAudit enrollment security analysis."""

import pytest

from mdmaudit.enrollment.apple_dep import (
    audit_apple_dep_enrollment,
    audit_dep_profile_download,
    _check_url_structure,
)
from mdmaudit.enrollment.android_enroll import (
    audit_android_enterprise_enrollment,
    check_enrollment_qr_security,
)
from mdmaudit.models import (
    DeviceOwnership,
    FindingSeverity,
    MDMPlatform,
)


class TestAppleDEPURLStructure:
    def _parsed(self, url: str):
        from urllib.parse import urlparse
        return urlparse(url)

    def test_http_enrollment_url_flagged_critical(self):
        url = "http://mdm.corp.example.com/enroll"
        report = audit_apple_dep_enrollment(url, authorized=False)
        critical = [f for f in report.findings if f.severity == FindingSeverity.CRITICAL]
        assert any("HTTP" in f.title or "Plaintext" in f.title for f in critical)

    def test_https_enrollment_url_no_transport_finding(self):
        # No TLS check against unreachable host — just no HTTP-specific finding
        url = "https://mdm.corp.example.com/enroll"
        report = audit_apple_dep_enrollment(url, authorized=False)
        http_findings = [f for f in report.findings if "Plaintext HTTP" in f.title]
        assert len(http_findings) == 0

    def test_credentials_in_url_flagged(self):
        url = "https://admin:password@mdm.corp.example.com/enroll"
        parsed = self._parsed(url)
        findings = _check_url_structure(url, parsed)
        assert any("Credentials" in f.title for f in findings)
        assert findings[0].severity == FindingSeverity.CRITICAL

    def test_ip_address_url_flagged(self):
        url = "https://10.0.0.1/enroll"
        parsed = self._parsed(url)
        findings = _check_url_structure(url, parsed)
        assert any("IP Address" in f.title for f in findings)

    def test_non_standard_port_flagged_low(self):
        url = "https://mdm.example.com:9090/enroll"
        parsed = self._parsed(url)
        findings = _check_url_structure(url, parsed)
        port_findings = [f for f in findings if "Port" in f.title]
        assert len(port_findings) == 1
        assert port_findings[0].severity == FindingSeverity.LOW

    def test_standard_https_url_no_findings(self):
        url = "https://mdm.example.com/enroll"
        parsed = self._parsed(url)
        findings = _check_url_structure(url, parsed)
        assert len(findings) == 0

    def test_not_authorized_produces_info_finding(self):
        url = "https://mdm.example.com/enroll"
        report = audit_apple_dep_enrollment(url, authorized=False)
        info_findings = [f for f in report.findings if f.severity == FindingSeverity.INFO]
        assert any("Authorized" in f.title or "Skipped" in f.title for f in info_findings)

    def test_report_platform_stored(self):
        url = "https://mdm.example.com/enroll"
        report = audit_apple_dep_enrollment(
            url, mdm_platform=MDMPlatform.JAMF, authorized=False
        )
        assert report.mdm_platform == MDMPlatform.JAMF

    def test_dep_profile_download_not_authorized_returns_empty(self):
        findings = audit_dep_profile_download(
            "https://mdm.example.com/profiles/enroll.mobileconfig",
            authorized=False,
        )
        assert findings == []


class TestAndroidEnterpriseEnrollment:
    def _minimal_config(self) -> dict:
        return {
            "require_device_attestation": True,
            "require_mfa_for_enrollment": True,
            "enforce_work_profile": True,
            "zero_touch_enabled": False,
            "dpc_package_name": "com.microsoft.intune",
        }

    def test_no_attestation_flagged(self):
        config = self._minimal_config()
        config["require_device_attestation"] = False
        report = audit_android_enterprise_enrollment(config)
        attest_findings = [f for f in report.findings if "Attestation" in f.title]
        assert len(attest_findings) == 1
        assert attest_findings[0].severity == FindingSeverity.MEDIUM

    def test_no_mfa_flagged(self):
        config = self._minimal_config()
        config["require_mfa_for_enrollment"] = False
        report = audit_android_enterprise_enrollment(config)
        mfa_findings = [f for f in report.findings if "MFA" in f.title]
        assert len(mfa_findings) == 1

    def test_byod_without_work_profile_critical(self):
        config = self._minimal_config()
        config["enforce_work_profile"] = False
        report = audit_android_enterprise_enrollment(
            config, ownership=DeviceOwnership.BYOD
        )
        critical = [f for f in report.findings if f.severity == FindingSeverity.CRITICAL]
        assert any("Work Profile" in f.title for f in critical)

    def test_byod_cross_profile_copy_paste_flagged(self):
        config = self._minimal_config()
        config["allow_cross_profile_copy_paste"] = True
        report = audit_android_enterprise_enrollment(
            config, ownership=DeviceOwnership.BYOD
        )
        cp_findings = [f for f in report.findings if "Copy-Paste" in f.title]
        assert len(cp_findings) == 1
        assert cp_findings[0].severity == FindingSeverity.HIGH

    def test_zero_touch_without_serial_restriction_flagged(self):
        config = self._minimal_config()
        config["zero_touch_enabled"] = True
        config["zero_touch_restrict_to_known_serials"] = False
        report = audit_android_enterprise_enrollment(config)
        zt_findings = [f for f in report.findings if "Zero-Touch" in f.title]
        assert len(zt_findings) == 1
        assert zt_findings[0].severity == FindingSeverity.HIGH

    def test_clean_config_no_critical_findings(self):
        config = self._minimal_config()
        config["require_device_attestation"] = True
        config["require_mfa_for_enrollment"] = True
        config["max_devices_per_user"] = 3
        config["blocks_reenrollment"] = True
        report = audit_android_enterprise_enrollment(config)
        critical = [f for f in report.findings if f.severity == FindingSeverity.CRITICAL]
        assert len(critical) == 0

    def test_unknown_dpc_package_flagged(self):
        config = self._minimal_config()
        config["dpc_package_name"] = "com.unknown.emm.agent"
        report = audit_android_enterprise_enrollment(config)
        dpc_findings = [f for f in report.findings if "DPC" in f.title]
        assert len(dpc_findings) == 1

    def test_platform_stored(self):
        config = self._minimal_config()
        report = audit_android_enterprise_enrollment(config)
        assert report.mdm_platform == MDMPlatform.ANDROID_ENTERPRISE


class TestQRCodeSecurity:
    def test_missing_checksum_flagged_high(self):
        qr = {
            "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME":
                "com.microsoft.intune/.DeviceAdminReceiver",
        }
        findings = check_enrollment_qr_security(qr)
        checksum_f = [f for f in findings if "Checksum" in f.title]
        assert len(checksum_f) == 1
        assert checksum_f[0].severity == FindingSeverity.HIGH

    def test_wifi_psk_in_qr_flagged(self):
        qr = {
            "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM": "abc123",
            "android.app.extra.PROVISIONING_WIFI_SSID": "CorpWifi",
            "android.app.extra.PROVISIONING_WIFI_SECURITY_TYPE": "WPA",
            "android.app.extra.PROVISIONING_WIFI_PASSWORD": "SuperSecretPSK",
        }
        findings = check_enrollment_qr_security(qr)
        psk_findings = [f for f in findings if "PSK" in f.title or "Wi-Fi" in f.title]
        assert len(psk_findings) >= 1
        assert psk_findings[0].severity == FindingSeverity.MEDIUM

    def test_skip_consent_flagged_info(self):
        qr = {
            "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM": "abc123",
            "android.app.extra.PROVISIONING_SKIP_USER_CONSENT": True,
        }
        findings = check_enrollment_qr_security(qr)
        consent_f = [f for f in findings if "Consent" in f.title]
        assert len(consent_f) == 1
        assert consent_f[0].severity == FindingSeverity.INFO

    def test_secure_qr_minimal_findings(self):
        qr = {
            "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM": "sha256:abc123",
            "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME":
                "com.microsoft.intune/.DeviceAdminReceiver",
        }
        findings = check_enrollment_qr_security(qr)
        high_or_critical = [f for f in findings
                            if f.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)]
        assert len(high_or_critical) == 0
