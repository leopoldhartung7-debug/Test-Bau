"""Tests for MDMAudit profile analysis — iOS and Android."""

import plistlib
import pytest
from datetime import datetime

from mdmaudit.profiles.ios_profiles import analyze_ios_profiles, _load_profile
from mdmaudit.profiles.android_profiles import (
    analyze_android_policies,
    check_managed_app_config,
)
from mdmaudit.models import DevicePlatform, FindingSeverity, ProfileType


def _make_ios_profile(payloads: list[dict], profile_id: str = "com.example.test") -> dict:
    return {
        "PayloadIdentifier": profile_id,
        "PayloadDisplayName": "Test Profile",
        "PayloadOrganization": "Test Corp",
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadContent": payloads,
    }


def _vpn_payload(auth_method: str = "Certificate", on_demand: int = 1,
                 psk: str = "") -> dict:
    payload = {
        "PayloadType": "com.apple.vpn.managed",
        "PayloadUUID": "vpn-uuid-001",
        "PayloadDisplayName": "Corporate VPN",
        "VPNType": "IKEv2",
    }
    if psk:
        payload["IKEv2"] = {"AuthenticationMethod": auth_method, "SharedSecret": psk}
    else:
        payload["IKEv2"] = {"AuthenticationMethod": auth_method}
    payload["OnDemandEnabled"] = on_demand
    return payload


def _wifi_payload(
    ssid: str = "CorpWifi",
    eap_types: list[int] | None = None,
    trusted_names: list[str] | None = None,
    encryption: str = "WPA2",
) -> dict:
    payload = {
        "PayloadType": "com.apple.wifi.managed",
        "PayloadUUID": "wifi-uuid-001",
        "PayloadDisplayName": f"WiFi {ssid}",
        "SSID_STR": ssid,
        "EncryptionType": encryption,
    }
    if eap_types is not None:
        eap_config: dict = {"AcceptEAPTypes": eap_types}
        if trusted_names is not None:
            eap_config["TLSTrustedServerNames"] = trusted_names
        payload["EAPClientConfiguration"] = eap_config
    return payload


def _restriction_payload(**kwargs) -> dict:
    payload = {
        "PayloadType": "com.apple.applicationaccess",
        "PayloadUUID": "restr-uuid-001",
        "PayloadDisplayName": "Restrictions",
    }
    payload.update(kwargs)
    return payload


def _mdm_payload(server_url: str = "https://mdm.example.com/server") -> dict:
    return {
        "PayloadType": "com.apple.mdm",
        "PayloadUUID": "mdm-uuid-001",
        "PayloadDisplayName": "MDM",
        "ServerURL": server_url,
        "CheckInURL": server_url,
        "AccessRights": 8191,
    }


class TestIOSProfileLoading:
    def test_load_dict(self):
        profile = {"PayloadIdentifier": "com.test", "PayloadContent": []}
        assert _load_profile(profile) == profile

    def test_load_bytes(self):
        data = {"PayloadIdentifier": "com.test", "PayloadContent": []}
        raw = plistlib.dumps(data)
        loaded = _load_profile(raw)
        assert loaded["PayloadIdentifier"] == "com.test"

    def test_load_invalid_bytes_returns_none(self):
        result = _load_profile(b"not a plist")
        assert result is None

    def test_load_unsupported_type_returns_none(self):
        result = _load_profile(42)
        assert result is None


class TestIOSVPNProfileAnalysis:
    def test_vpn_psk_flagged_high(self):
        profile = _make_ios_profile([_vpn_payload(psk="s3cr3tPSK")])
        report = analyze_ios_profiles([profile])
        psk_findings = [f for f in report.findings if "Pre-Shared Key" in f.title]
        assert len(psk_findings) == 1
        assert psk_findings[0].severity == FindingSeverity.HIGH

    def test_vpn_weak_auth_flagged(self):
        profile = _make_ios_profile([_vpn_payload(auth_method="Password")])
        report = analyze_ios_profiles([profile])
        auth_findings = [f for f in report.findings if "Weak Authentication" in f.title]
        assert len(auth_findings) == 1
        assert auth_findings[0].severity == FindingSeverity.MEDIUM

    def test_vpn_no_on_demand_flagged_low(self):
        profile = _make_ios_profile([_vpn_payload(on_demand=0)])
        report = analyze_ios_profiles([profile])
        od_findings = [f for f in report.findings if "On-Demand" in f.title]
        assert len(od_findings) == 1
        assert od_findings[0].severity == FindingSeverity.LOW

    def test_vpn_certificate_auth_on_demand_clean(self):
        profile = _make_ios_profile([_vpn_payload(auth_method="Certificate", on_demand=1)])
        report = analyze_ios_profiles([profile])
        high_or_critical = [f for f in report.findings
                            if f.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)
                            and f.profile_type == ProfileType.VPN]
        assert len(high_or_critical) == 0


class TestIOSWiFiProfileAnalysis:
    def test_peap_without_server_cert_flagged_high(self):
        profile = _make_ios_profile([_wifi_payload(eap_types=[25])])
        report = analyze_ios_profiles([profile])
        high = [f for f in report.findings if f.severity == FindingSeverity.HIGH
                and f.profile_type == ProfileType.WIFI]
        # Should flag both weak EAP and missing server cert
        assert len(high) >= 1

    def test_peap_missing_server_cert_pinning_flagged(self):
        profile = _make_ios_profile([_wifi_payload(eap_types=[25])])
        report = analyze_ios_profiles([profile])
        pin_findings = [f for f in report.findings if "Pin" in f.title or "Server Certificate" in f.title]
        assert len(pin_findings) >= 1

    def test_eap_tls_with_trusted_names_no_high_findings(self):
        profile = _make_ios_profile([
            _wifi_payload(eap_types=[13], trusted_names=["radius.corp.example.com"])
        ])
        report = analyze_ios_profiles([profile])
        wifi_high = [f for f in report.findings
                     if f.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)
                     and f.profile_type == ProfileType.WIFI]
        assert len(wifi_high) == 0

    def test_open_wifi_flagged_medium(self):
        profile = _make_ios_profile([_wifi_payload(ssid="GuestWifi", encryption="None")])
        report = analyze_ios_profiles([profile])
        open_findings = [f for f in report.findings if "Open" in f.title and "Wi-Fi" in f.title]
        assert len(open_findings) == 1
        assert open_findings[0].severity == FindingSeverity.MEDIUM


class TestIOSRestrictionProfileAnalysis:
    def test_usb_restricted_mode_disabled_flagged_high(self):
        profile = _make_ios_profile([_restriction_payload(allowUSBRestrictedMode=False)])
        report = analyze_ios_profiles([profile])
        usb_findings = [f for f in report.findings if "USB Restricted Mode" in f.title]
        assert len(usb_findings) == 1
        assert usb_findings[0].severity == FindingSeverity.HIGH

    def test_unencrypted_backup_flagged_high(self):
        profile = _make_ios_profile([_restriction_payload(forceEncryptedBackup=False)])
        report = analyze_ios_profiles([profile])
        backup_findings = [f for f in report.findings if "Backup" in f.title and "Encrypted" in f.title]
        assert len(backup_findings) == 1
        assert backup_findings[0].severity == FindingSeverity.HIGH

    def test_icloud_backup_permitted_flagged_medium(self):
        profile = _make_ios_profile([_restriction_payload(allowCloudBackup=True)])
        report = analyze_ios_profiles([profile])
        cloud_findings = [f for f in report.findings if "iCloud" in f.title]
        assert len(cloud_findings) == 1
        assert cloud_findings[0].severity == FindingSeverity.MEDIUM


class TestIOSMDMPayloadAnalysis:
    def test_http_mdm_url_flagged_critical(self):
        profile = _make_ios_profile([_mdm_payload("http://mdm.example.com/server")])
        report = analyze_ios_profiles([profile])
        critical = [f for f in report.findings if f.severity == FindingSeverity.CRITICAL]
        assert any("HTTP" in f.title for f in critical)

    def test_all_access_rights_flagged_low(self):
        profile = _make_ios_profile([_mdm_payload()])
        report = analyze_ios_profiles([profile])
        rights_findings = [f for f in report.findings if "Access Rights" in f.title]
        assert len(rights_findings) == 1
        assert rights_findings[0].severity == FindingSeverity.LOW


class TestMultipleProfiles:
    def test_multiple_profiles_analyzed(self):
        profiles = [
            _make_ios_profile([_vpn_payload(psk="psk1")], "com.example.vpn"),
            _make_ios_profile([_wifi_payload(eap_types=[25])], "com.example.wifi"),
        ]
        report = analyze_ios_profiles(profiles)
        assert report.profiles_analyzed == 2
        assert len(report.findings) >= 2

    def test_report_device_platform(self):
        report = analyze_ios_profiles([_make_ios_profile([])])
        assert report.device_platform == DevicePlatform.IOS


class TestAndroidPolicyAnalysis:
    def _secure_policies(self) -> dict:
        return {
            "passwordQuality": 0x00060000,  # COMPLEX
            "passwordMinimumLength": 8,
            "maximumFailedPasswordsForWipe": 10,
            "maxInactivityTimeoutMinutes": 5,
            "storageEncryption": True,
            "allowNonMarketApps": False,
            "ensureVerifyApps": True,
            "crossProfileCopyPaste": False,
            "usbFileTransferDisabled": True,
        }

    def test_weak_password_quality_flagged(self):
        policies = self._secure_policies()
        policies["passwordQuality"] = 0x00020000  # NUMERIC
        report = analyze_android_policies(policies)
        pw_findings = [f for f in report.findings if "Password Quality" in f.title]
        assert len(pw_findings) == 1
        assert pw_findings[0].severity == FindingSeverity.HIGH

    def test_short_password_flagged(self):
        policies = self._secure_policies()
        policies["passwordMinimumLength"] = 4
        report = analyze_android_policies(policies)
        len_findings = [f for f in report.findings if "Length" in f.title]
        assert len(len_findings) == 1

    def test_no_wipe_limit_flagged(self):
        policies = self._secure_policies()
        policies["maximumFailedPasswordsForWipe"] = 0
        report = analyze_android_policies(policies)
        wipe_findings = [f for f in report.findings if "Wipe" in f.title]
        assert len(wipe_findings) == 1
        assert wipe_findings[0].severity == FindingSeverity.HIGH

    def test_sideloading_enabled_flagged_high(self):
        policies = self._secure_policies()
        policies["allowNonMarketApps"] = True
        report = analyze_android_policies(policies)
        sl_findings = [f for f in report.findings if "Sideloading" in f.title]
        assert len(sl_findings) == 1
        assert sl_findings[0].severity == FindingSeverity.HIGH

    def test_cross_profile_copy_paste_flagged(self):
        policies = self._secure_policies()
        policies["crossProfileCopyPaste"] = True
        report = analyze_android_policies(policies)
        cp_findings = [f for f in report.findings if "Copy-Paste" in f.title]
        assert len(cp_findings) == 1
        assert cp_findings[0].severity == FindingSeverity.HIGH

    def test_no_encryption_flagged_high(self):
        policies = self._secure_policies()
        policies["storageEncryption"] = False
        report = analyze_android_policies(policies)
        enc_findings = [f for f in report.findings if "Encryption" in f.title]
        assert len(enc_findings) == 1
        assert enc_findings[0].severity == FindingSeverity.HIGH

    def test_secure_policies_no_high_findings(self):
        policies = self._secure_policies()
        policies["max_devices_per_user"] = 3
        report = analyze_android_policies(policies)
        high_or_critical = [f for f in report.findings
                            if f.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)]
        assert len(high_or_critical) == 0


class TestManagedAppConfig:
    def test_password_key_flagged(self):
        findings = check_managed_app_config(
            "com.example.app",
            {"server_url": "https://example.com", "api_password": "s3cr3t"},
        )
        assert len(findings) == 1
        assert "api_password" in findings[0].title

    def test_token_key_flagged(self):
        findings = check_managed_app_config(
            "com.example.app",
            {"auth_token": "eyJhbGci...", "max_connections": 5},
        )
        token_findings = [f for f in findings if "token" in f.title.lower()]
        assert len(token_findings) >= 1

    def test_clean_config_no_findings(self):
        findings = check_managed_app_config(
            "com.example.app",
            {"server_url": "https://example.com", "max_retries": 3, "log_level": "info"},
        )
        assert len(findings) == 0
