"""
Android Enterprise enrollment security analysis.

Checks zero-touch enrollment, DPC identifier requirements, Work Profile
provisioning controls, and attestation requirements.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Optional

from ..models import (
    AuthMethod,
    DeviceOwnership,
    EnrollmentReport,
    Finding,
    FindingSeverity,
    MDMPlatform,
)

logger = logging.getLogger(__name__)

# Provisioning extra keys that signal security-conscious configuration
_SECURE_PROVISIONING_EXTRAS = {
    "android.app.extra.PROVISIONING_SKIP_USER_CONSENT": False,
    "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM": True,
}

# Device policy controller packages for known EMM vendors
KNOWN_DPC_PACKAGES = {
    "com.microsoft.intune": "Microsoft Intune",
    "com.mobileiron": "MobileIron/Ivanti",
    "com.vmware.android.boxer": "VMware Workspace ONE",
    "com.jamf.management.jamfnow": "Jamf Now",
    "com.kandji.android": "Kandji",
    "com.blackberry.hub": "BlackBerry UEM",
    "com.soti.mobicontrol": "SOTI MobiControl",
    "com.cisco.meraki.systems.manager": "Cisco Meraki",
}


def audit_android_enterprise_enrollment(
    emm_config: dict,
    ownership: DeviceOwnership = DeviceOwnership.CORPORATE,
    *,
    authorized: bool = False,
) -> EnrollmentReport:
    """
    Assess Android Enterprise enrollment configuration security.

    Args:
        emm_config: EMM configuration dict as exported from your zero-touch
                    or EMM console. Keys vary by vendor; common keys documented
                    below in individual checks.
        ownership: CORPORATE, BYOD, or COPE — affects which checks apply.
        authorized: Reserved for future active API probing.
    """
    start = datetime.utcnow()
    findings: list[Finding] = []

    findings.extend(_check_dpc_configuration(emm_config, ownership))
    findings.extend(_check_zero_touch_security(emm_config))
    findings.extend(_check_attestation_requirements(emm_config))
    findings.extend(_check_byod_isolation(emm_config, ownership))
    findings.extend(_check_enrollment_restrictions(emm_config))

    duration = (datetime.utcnow() - start).total_seconds()

    # Deduplicate + sort
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in sorted(findings, key=lambda x: _severity_order(x.severity)):
        if f.finding_id not in seen:
            seen.add(f.finding_id)
            unique.append(f)

    auth_method = _infer_auth_method(emm_config)
    return EnrollmentReport(
        report_id=str(uuid.uuid4()),
        mdm_platform=MDMPlatform.ANDROID_ENTERPRISE,
        generated_at=datetime.utcnow(),
        findings=unique,
        enrollment_url=emm_config.get("enrollment_url", ""),
        requires_authentication=emm_config.get("requires_authentication", True),
        auth_method=auth_method,
        blocks_reenrollment=emm_config.get("blocks_reenrollment", True),
        scan_duration_seconds=duration,
    )


def check_enrollment_qr_security(qr_payload: dict) -> list[Finding]:
    """
    Analyse an Android Enterprise QR code provisioning payload for security issues.

    ``qr_payload`` is the JSON object encoded in the QR code, conforming to
    the Android provisioning extras schema.
    """
    findings: list[Finding] = []

    # Check if package checksum is present (prevents DPC substitution)
    checksum = qr_payload.get(
        "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM", ""
    )
    if not checksum:
        findings.append(Finding(
            finding_id="AE-HIGH-001",
            title="QR Enrollment Missing DPC Package Checksum",
            description=(
                "The enrollment QR code does not include "
                "PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM. Without this, a "
                "factory-reset device could be tricked into installing a malicious "
                "DPC (Device Policy Controller) that mimics your EMM, then "
                "enrolling as a legitimate corporate device."
            ),
            severity=FindingSeverity.HIGH,
            category="enrollment",
            evidence=["PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM: absent"],
            remediation=(
                "Add the SHA-256 checksum of your DPC APK to the QR provisioning "
                "extras. Regenerate QR codes whenever the DPC APK is updated."
            ),
            cwe_id="CWE-494",
            cvss_score=7.5,
        ))

    # Check if WiFi credentials are embedded (should use EAP-TLS, not PSK)
    wifi_ssid = qr_payload.get("android.app.extra.PROVISIONING_WIFI_SSID")
    wifi_security = qr_payload.get(
        "android.app.extra.PROVISIONING_WIFI_SECURITY_TYPE", "NONE"
    )
    wifi_pass = qr_payload.get("android.app.extra.PROVISIONING_WIFI_PASSWORD", "")

    if wifi_ssid and wifi_security == "WPA" and wifi_pass:
        findings.append(Finding(
            finding_id="AE-MED-001",
            title="Enrollment QR Contains Wi-Fi PSK in Plaintext",
            description=(
                "The enrollment QR code includes a Wi-Fi pre-shared key. Anyone "
                "who photographs or scans this QR code obtains permanent Wi-Fi "
                "access. The QR payload is stored in device logs during provisioning."
            ),
            severity=FindingSeverity.MEDIUM,
            category="enrollment",
            evidence=[
                f"SSID: {wifi_ssid}",
                f"Security: {wifi_security}",
                "Wi-Fi password present",
            ],
            remediation=(
                "Replace PSK Wi-Fi with 802.1X EAP-TLS certificate-based "
                "authentication for the enrollment SSID. This eliminates shared "
                "secrets and ties network access to device identity."
            ),
            cwe_id="CWE-312",
            cvss_score=5.5,
        ))

    # Check skip user consent
    skip_consent = qr_payload.get(
        "android.app.extra.PROVISIONING_SKIP_USER_CONSENT", False
    )
    if skip_consent is True:
        findings.append(Finding(
            finding_id="AE-INFO-001",
            title="QR Enrollment Skips User Consent Screen",
            description=(
                "PROVISIONING_SKIP_USER_CONSENT is set to true. This silently "
                "provisions the device without displaying the standard consent "
                "screen to the user. For COPE/BYOD scenarios this undermines "
                "transparency obligations (GDPR, local labour law)."
            ),
            severity=FindingSeverity.INFO,
            category="enrollment",
            evidence=["PROVISIONING_SKIP_USER_CONSENT: true"],
            remediation=(
                "For BYOD/COPE devices, do not skip the consent screen. "
                "For fully corporate-owned devices this may be acceptable, "
                "but review with your legal/HR team."
            ),
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _check_dpc_configuration(config: dict, ownership: DeviceOwnership) -> list[Finding]:
    findings: list[Finding] = []

    dpc = config.get("dpc_package_name", "")
    if dpc and dpc not in KNOWN_DPC_PACKAGES:
        findings.append(Finding(
            finding_id="AE-MED-002",
            title=f"Unrecognised DPC Package: {dpc}",
            description=(
                f"The configured Device Policy Controller package '{dpc}' is not "
                "in the list of known EMM vendor DPC packages. Verify this is your "
                "expected EMM agent and not a rogue or legacy application."
            ),
            severity=FindingSeverity.MEDIUM,
            category="enrollment",
            evidence=[f"DPC: {dpc}"],
            remediation=(
                "Confirm the DPC package name matches your EMM vendor's documented "
                "package ID. Enable Google Play Protect to verify APK integrity."
            ),
        ))

    return findings


def _check_zero_touch_security(config: dict) -> list[Finding]:
    findings: list[Finding] = []

    zt_enabled = config.get("zero_touch_enabled", False)
    zt_serial_locked = config.get("zero_touch_restrict_to_known_serials", False)

    if zt_enabled and not zt_serial_locked:
        findings.append(Finding(
            finding_id="AE-HIGH-002",
            title="Zero-Touch Enrollment Not Restricted to Known Serials",
            description=(
                "Zero-touch enrollment is enabled but not restricted to "
                "pre-registered device serials. An attacker who obtains your "
                "enrollment token could enroll an arbitrary Android device and "
                "receive corporate Wi-Fi, email, and VPN configurations."
            ),
            severity=FindingSeverity.HIGH,
            category="enrollment",
            evidence=["zero_touch_enabled: true", "zero_touch_restrict_to_known_serials: false"],
            remediation=(
                "In the Android Zero-Touch portal, pre-register all corporate "
                "device IMEIs/serials. Require hardware attestation (SafetyNet "
                "or Play Integrity API) before issuing credentials."
            ),
            cwe_id="CWE-284",
            cvss_score=7.5,
        ))

    return findings


def _check_attestation_requirements(config: dict) -> list[Finding]:
    findings: list[Finding] = []

    attestation_required = config.get("require_device_attestation", False)
    if not attestation_required:
        findings.append(Finding(
            finding_id="AE-MED-003",
            title="Device Attestation Not Required at Enrollment",
            description=(
                "The EMM configuration does not require Play Integrity API / "
                "SafetyNet attestation at enrollment time. Without attestation, "
                "rooted, emulated, or compromised devices can enroll and receive "
                "corporate credentials."
            ),
            severity=FindingSeverity.MEDIUM,
            category="enrollment",
            evidence=["require_device_attestation: false (or absent)"],
            remediation=(
                "Enable device attestation in your EMM enrollment policy. "
                "For high-security environments, require MEETS_DEVICE_INTEGRITY "
                "or MEETS_STRONG_INTEGRITY from the Play Integrity API before "
                "issuing credentials."
            ),
            cwe_id="CWE-346",
            cvss_score=5.9,
        ))

    return findings


def _check_byod_isolation(config: dict, ownership: DeviceOwnership) -> list[Finding]:
    findings: list[Finding] = []

    if ownership == DeviceOwnership.BYOD:
        work_profile_enforced = config.get("enforce_work_profile", True)
        if not work_profile_enforced:
            findings.append(Finding(
                finding_id="AE-CRIT-001",
                title="BYOD Enrollment Without Work Profile Isolation",
                description=(
                    "BYOD devices are enrolled without mandating a Work Profile. "
                    "Without profile isolation, corporate apps and data co-exist "
                    "with personal data in the same Android user context, enabling "
                    "personal apps to access corporate data stores."
                ),
                severity=FindingSeverity.CRITICAL,
                category="enrollment",
                evidence=["ownership: BYOD", "enforce_work_profile: false"],
                remediation=(
                    "Mandate Work Profile enrollment for all BYOD devices. "
                    "Configure a cross-profile data sharing policy that prevents "
                    "personal apps from accessing work profile data. "
                    "Use Android Enterprise BYOD mode (Profile Owner)."
                ),
                cwe_id="CWE-284",
                cvss_score=8.5,
            ))

        cross_profile_copy = config.get("allow_cross_profile_copy_paste", True)
        if cross_profile_copy:
            findings.append(Finding(
                finding_id="AE-HIGH-003",
                title="Cross-Profile Copy-Paste Allowed on BYOD",
                description=(
                    "Cross-profile clipboard sharing is enabled. Sensitive corporate "
                    "data (passwords, documents) can be copied from work apps and "
                    "pasted into personal apps, or vice versa."
                ),
                severity=FindingSeverity.HIGH,
                category="enrollment",
                evidence=["allow_cross_profile_copy_paste: true"],
                remediation=(
                    "Disable cross-profile clipboard sharing. Set "
                    "setCrossProfileCopyPasteDisabled(true) via the Device Policy "
                    "Controller. Consider DLP controls at the app level."
                ),
                cwe_id="CWE-200",
                cvss_score=6.5,
            ))

    return findings


def _check_enrollment_restrictions(config: dict) -> list[Finding]:
    findings: list[Finding] = []

    max_enroll_devices = config.get("max_devices_per_user")
    if max_enroll_devices is None:
        findings.append(Finding(
            finding_id="AE-LOW-001",
            title="No Per-User Device Enrollment Limit Configured",
            description=(
                "There is no limit on how many devices a single user can enroll. "
                "This makes it easier for an attacker with compromised credentials "
                "to enroll many devices and receive corporate profiles on each."
            ),
            severity=FindingSeverity.LOW,
            category="enrollment",
            evidence=["max_devices_per_user: not configured"],
            remediation=(
                "Set a per-user enrollment limit appropriate to your environment "
                "(typically 2–5 for most corporate roles). Require re-approval "
                "for additional devices beyond the limit."
            ),
        ))

    require_mfa_enrollment = config.get("require_mfa_for_enrollment", False)
    if not require_mfa_enrollment:
        findings.append(Finding(
            finding_id="AE-MED-004",
            title="MFA Not Required for Device Enrollment",
            description=(
                "Device enrollment can be completed with only a username and "
                "password. A compromised employee credential allows an attacker "
                "to enroll a device and receive corporate profiles without "
                "triggering a second-factor challenge."
            ),
            severity=FindingSeverity.MEDIUM,
            category="enrollment",
            evidence=["require_mfa_for_enrollment: false"],
            remediation=(
                "Require MFA (TOTP, push notification, or hardware key) for "
                "all device enrollment workflows. Integrate your EMM with "
                "your IdP (Azure AD, Okta) to enforce conditional access."
            ),
            cwe_id="CWE-308",
            cvss_score=6.5,
        ))

    return findings


def _infer_auth_method(config: dict) -> AuthMethod:
    method = config.get("auth_method", "")
    mapping = {
        "certificate": AuthMethod.CERTIFICATE,
        "oauth2": AuthMethod.OAUTH2,
        "saml": AuthMethod.SAML,
        "mfa": AuthMethod.MFA,
        "api_key": AuthMethod.API_KEY,
        "none": AuthMethod.NONE,
    }
    return mapping.get(method.lower(), AuthMethod.USERNAME_PASSWORD)


def _severity_order(s: FindingSeverity) -> int:
    return {FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4}[s]
