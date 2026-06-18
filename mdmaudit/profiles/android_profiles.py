"""
Android Enterprise managed configuration and policy analysis.

Analyses Work Profile policies, Device Owner (fully managed) policies,
and managed app configurations for security misconfigurations.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from ..models import (
    DevicePlatform,
    Finding,
    FindingSeverity,
    ProfileFinding,
    ProfileReport,
    ProfileType,
)

logger = logging.getLogger(__name__)

# Password quality constants (Android DevicePolicyManager)
_PASSWORD_QUALITY = {
    0x00000000: "UNSPECIFIED",
    0x00010000: "SOMETHING",        # Any non-empty password
    0x00020000: "NUMERIC",
    0x00030000: "NUMERIC_COMPLEX",
    0x00040000: "ALPHABETIC",
    0x00050000: "ALPHANUMERIC",
    0x00060000: "COMPLEX",          # Requires symbol, number, letter
    0x000E0000: "BIOMETRIC_WEAK",   # Fingerprint or above
}

_WEAK_PASSWORD_QUALITIES = {0x00000000, 0x00010000, 0x00020000}

# Permissions that are high-risk in managed configurations
_HIGH_RISK_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}

# Managed config key patterns suggesting credential storage
_CREDENTIAL_KEY_PATTERNS = ["password", "secret", "token", "key", "credential", "api_key"]


def analyze_android_policies(
    policies: dict,
    device_identifier: str = "unknown",
) -> ProfileReport:
    """
    Analyse Android Enterprise device and work profile policies.

    ``policies`` is a dict representing the EMM policy configuration —
    typically as exported from Intune, Workspace ONE, or the Android
    Management API policy object.
    """
    start = datetime.utcnow()
    findings: list[ProfileFinding] = []

    findings.extend(_check_password_policy(policies))
    findings.extend(_check_encryption_policy(policies))
    findings.extend(_check_app_policies(policies))
    findings.extend(_check_data_sharing_policy(policies))
    findings.extend(_check_network_policy(policies))
    findings.extend(_check_hardware_policy(policies))
    findings.extend(_check_managed_configs(policies.get("managedConfigurations", {})))

    _order = {FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1,
               FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 3,
               FindingSeverity.INFO: 4}
    findings.sort(key=lambda f: (_order[f.severity], f.title))

    return ProfileReport(
        report_id=str(uuid.uuid4()),
        device_identifier=device_identifier,
        device_platform=DevicePlatform.ANDROID,
        generated_at=datetime.utcnow(),
        profiles_analyzed=1,
        findings=findings,
        scan_duration_seconds=(datetime.utcnow() - start).total_seconds(),
    )


def check_managed_app_config(
    package_name: str,
    managed_config: dict,
) -> list[ProfileFinding]:
    """
    Check a single app's managed configuration for embedded credentials
    or insecure settings.
    """
    findings: list[ProfileFinding] = []
    for key, value in managed_config.items():
        key_lower = key.lower()
        if any(p in key_lower for p in _CREDENTIAL_KEY_PATTERNS):
            val_preview = str(value)[:30] if value else "(empty)"
            findings.append(ProfileFinding(
                finding_id=f"AE-MCONF-001-{package_name[:20]}-{key[:10]}",
                title=f"Credential-Like Key in Managed Config: {key}",
                description=(
                    f"Managed configuration for '{package_name}' contains a key "
                    f"'{key}' whose name suggests it holds a credential or secret. "
                    "Managed configs are stored in the EMM and pushed to devices in "
                    "plaintext; they are readable by the app and visible to MDM admins."
                ),
                severity=FindingSeverity.MEDIUM,
                category="android-managed-config",
                evidence=[
                    f"Package: {package_name}",
                    f"Key: {key}",
                    f"Value (preview): {val_preview}",
                ],
                remediation=(
                    "Do not store plaintext credentials in managed configurations. "
                    "Use token vending from a backend service, or distribute "
                    "credentials via the Android Keystore through a secure channel "
                    "rather than the MDM configuration payload."
                ),
                cwe_id="CWE-312",
                profile_identifier=package_name,
                profile_type=ProfileType.OTHER,
            ))
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Policy checkers
# ─────────────────────────────────────────────────────────────────────────────

def _check_password_policy(policies: dict) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []

    pw_quality = policies.get("passwordQuality", 0)
    pw_min_len = policies.get("passwordMinimumLength", 0)
    max_failed = policies.get("maximumFailedPasswordsForWipe", 0)
    max_inactivity = policies.get("maxInactivityTimeoutMinutes", 0)

    if pw_quality in _WEAK_PASSWORD_QUALITIES:
        quality_name = _PASSWORD_QUALITY.get(pw_quality, hex(pw_quality))
        findings.append(ProfileFinding(
            finding_id="AE-PW-001",
            title=f"Weak Password Quality Requirement: {quality_name}",
            description=(
                f"The device password quality is set to '{quality_name}' "
                f"(value: {hex(pw_quality)}). This permits trivially guessable "
                "PINs and patterns that provide minimal brute-force resistance."
            ),
            severity=FindingSeverity.HIGH,
            category="android-password",
            evidence=[f"passwordQuality: {hex(pw_quality)} ({quality_name})"],
            remediation=(
                "Set passwordQuality to PASSWORD_QUALITY_ALPHANUMERIC or "
                "PASSWORD_QUALITY_COMPLEX. Require at least 8 characters with "
                "mixed case, numbers, and symbols for high-sensitivity devices."
            ),
            cwe_id="CWE-521",
            cvss_score=7.3,
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    if pw_min_len < 6:
        findings.append(ProfileFinding(
            finding_id="AE-PW-002",
            title=f"Minimum Password Length Too Short: {pw_min_len} characters",
            description=(
                f"The minimum password length is {pw_min_len} characters (0 = no minimum). "
                "Short passwords are quickly exhausted by brute force."
            ),
            severity=FindingSeverity.MEDIUM,
            category="android-password",
            evidence=[f"passwordMinimumLength: {pw_min_len}"],
            remediation=(
                "Set passwordMinimumLength to at least 8 characters. "
                "For high-sensitivity corporate devices, 12+ characters is recommended."
            ),
            cwe_id="CWE-521",
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    if max_failed == 0:
        findings.append(ProfileFinding(
            finding_id="AE-PW-003",
            title="No Failed Password Wipe Limit Configured",
            description=(
                "maximumFailedPasswordsForWipe is 0 (disabled). A lost or stolen "
                "device can be brute-forced indefinitely without triggering a wipe."
            ),
            severity=FindingSeverity.HIGH,
            category="android-password",
            evidence=["maximumFailedPasswordsForWipe: 0"],
            remediation=(
                "Set maximumFailedPasswordsForWipe to 10 or less. Balance security "
                "against accidental wipe for shared devices used by multiple staff."
            ),
            cwe_id="CWE-307",
            cvss_score=6.5,
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    if max_inactivity == 0 or max_inactivity > 5:
        findings.append(ProfileFinding(
            finding_id="AE-PW-004",
            title=f"Screen Lock Timeout Too Long or Not Set: {max_inactivity} min",
            description=(
                f"The screen inactivity timeout is {max_inactivity} minutes "
                "(0 = no timeout). Unattended devices remain unlocked, allowing "
                "physical access to corporate data."
            ),
            severity=FindingSeverity.MEDIUM,
            category="android-password",
            evidence=[f"maxInactivityTimeoutMinutes: {max_inactivity}"],
            remediation="Set maxInactivityTimeoutMinutes to 5 or less.",
            cwe_id="CWE-613",
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    return findings


def _check_encryption_policy(policies: dict) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []

    require_encryption = policies.get("storageEncryption", True)
    if not require_encryption:
        findings.append(ProfileFinding(
            finding_id="AE-ENC-001",
            title="Storage Encryption Not Required by Policy",
            description=(
                "The policy does not require device storage encryption. "
                "On devices running Android 6+ encryption is mandatory, but "
                "explicitly requiring it in policy ensures compliance is verified "
                "at enrollment and reported in the EMM console."
            ),
            severity=FindingSeverity.HIGH,
            category="android-encryption",
            evidence=["storageEncryption: false"],
            remediation=(
                "Set storageEncryption to true. Enrol only devices running "
                "Android 6.0 or later with full-disk or file-based encryption."
            ),
            cwe_id="CWE-311",
            cvss_score=7.5,
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    return findings


def _check_app_policies(policies: dict) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []

    allow_unknown_sources = policies.get("allowNonMarketApps", False)
    if allow_unknown_sources:
        findings.append(ProfileFinding(
            finding_id="AE-APP-001",
            title="Sideloading (Unknown Sources) Permitted by Policy",
            description=(
                "The policy allows installation of apps from sources other than "
                "Google Play (allowNonMarketApps = true). This exposes managed "
                "devices to malware distributed outside the Play Store."
            ),
            severity=FindingSeverity.HIGH,
            category="android-app",
            evidence=["allowNonMarketApps: true"],
            remediation=(
                "Set allowNonMarketApps to false. Distribute all corporate apps "
                "through the Managed Google Play Store or a private Play channel."
            ),
            cwe_id="CWE-494",
            cvss_score=7.8,
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    play_protect = policies.get("ensureVerifyApps", True)
    if not play_protect:
        findings.append(ProfileFinding(
            finding_id="AE-APP-002",
            title="Google Play Protect Verification Disabled",
            description=(
                "ensureVerifyApps is false — Play Protect app scanning is not "
                "enforced. Malicious apps already installed will not be flagged."
            ),
            severity=FindingSeverity.MEDIUM,
            category="android-app",
            evidence=["ensureVerifyApps: false"],
            remediation="Set ensureVerifyApps to true to enforce Play Protect scanning.",
            cwe_id="CWE-494",
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    return findings


def _check_data_sharing_policy(policies: dict) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []

    cross_profile_copy = policies.get("crossProfileCopyPaste", True)
    if cross_profile_copy:
        findings.append(ProfileFinding(
            finding_id="AE-DATA-001",
            title="Cross-Profile Copy-Paste Permitted",
            description=(
                "Cross-profile clipboard sharing is enabled. Users can copy "
                "corporate data from work profile apps and paste into personal "
                "apps, creating a data exfiltration path."
            ),
            severity=FindingSeverity.HIGH,
            category="android-data",
            evidence=["crossProfileCopyPaste: true (or unset)"],
            remediation=(
                "Set crossProfileCopyPaste to false (setCrossProfileCopyPasteDisabled). "
                "Apply consistent DLP controls at the app and profile level."
            ),
            cwe_id="CWE-200",
            cvss_score=6.5,
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    allow_data_roaming = policies.get("dataRoamingDisabled", False)
    if not allow_data_roaming:
        findings.append(ProfileFinding(
            finding_id="AE-DATA-002",
            title="Data Roaming Not Disabled",
            description=(
                "International data roaming is not disabled by policy. Devices "
                "may incur unexpected data charges and, more critically, traffic "
                "may transit foreign networks with less trustworthy routing."
            ),
            severity=FindingSeverity.LOW,
            category="android-data",
            evidence=["dataRoamingDisabled: false or absent"],
            remediation=(
                "Set dataRoamingDisabled to true for corporate-owned devices. "
                "For employee devices, consider a managed roaming allowance "
                "combined with VPN enforcement."
            ),
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    return findings


def _check_network_policy(policies: dict) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []

    wifi_direct = policies.get("wifiDirectDisabled", False)
    if not wifi_direct:
        findings.append(ProfileFinding(
            finding_id="AE-NET-001",
            title="Wi-Fi Direct Not Disabled",
            description=(
                "Wi-Fi Direct is not disabled. Devices can establish direct "
                "peer-to-peer Wi-Fi connections with nearby devices, bypassing "
                "corporate network controls and potentially exposing managed data."
            ),
            severity=FindingSeverity.LOW,
            category="android-network",
            evidence=["wifiDirectDisabled: false or absent"],
            remediation="Set wifiDirectDisabled to true on corporate-owned devices.",
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    bluetooth = policies.get("bluetoothContactSharingDisabled", False)
    if not bluetooth:
        findings.append(ProfileFinding(
            finding_id="AE-NET-002",
            title="Bluetooth Contact Sharing Not Disabled",
            description=(
                "Bluetooth contact sharing is permitted. Work profile contacts "
                "could be shared to personal Bluetooth headsets or paired devices "
                "that are not under corporate management."
            ),
            severity=FindingSeverity.LOW,
            category="android-network",
            evidence=["bluetoothContactSharingDisabled: false or absent"],
            remediation=(
                "Set bluetoothContactSharingDisabled to true on devices that "
                "handle sensitive corporate contacts."
            ),
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    return findings


def _check_hardware_policy(policies: dict) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []

    camera_disabled = policies.get("cameraDisabled", False)
    if not camera_disabled:
        findings.append(ProfileFinding(
            finding_id="AE-HW-001",
            title="Camera Not Disabled (High-Sensitivity Environments)",
            description=(
                "The camera is not disabled by policy. For environments that "
                "handle classified, regulated, or highly confidential data, "
                "camera access enables covert data exfiltration via photography."
            ),
            severity=FindingSeverity.INFO,
            category="android-hardware",
            evidence=["cameraDisabled: false or absent"],
            remediation=(
                "Evaluate whether camera access is required. For high-security "
                "environments, set cameraDisabled to true. For standard deployments, "
                "a DLP policy restricting camera in managed apps may suffice."
            ),
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    usb_file_transfer = policies.get("usbFileTransferDisabled", False)
    if not usb_file_transfer:
        findings.append(ProfileFinding(
            finding_id="AE-HW-002",
            title="USB File Transfer Not Disabled",
            description=(
                "USB file transfer (MTP/PTP) is not disabled. Corporate data "
                "can be copied to any connected computer, bypassing DLP controls."
            ),
            severity=FindingSeverity.MEDIUM,
            category="android-hardware",
            evidence=["usbFileTransferDisabled: false or absent"],
            remediation=(
                "Set usbFileTransferDisabled to true on corporate-owned devices. "
                "For BYOD, apply managed app controls to prevent corporate data "
                "from being accessible via the file system."
            ),
            cwe_id="CWE-284",
            profile_identifier="device-policy",
            profile_type=ProfileType.RESTRICTION,
        ))

    return findings


def _check_managed_configs(managed_configs: dict) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []
    for package, config in managed_configs.items():
        if isinstance(config, dict):
            findings.extend(check_managed_app_config(package, config))
    return findings
