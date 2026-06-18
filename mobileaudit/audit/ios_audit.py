"""iOS configuration security audit — CIS iOS Benchmark & NIST SP 800-124."""

from __future__ import annotations

import logging
from typing import Any

from ..models import (
    ComplianceControl,
    ComplianceReport,
    ComplianceStatus,
    DeviceProfile,
    Platform,
    Severity,
)
from ..android.fingerprint import _adb  # reuse ADB helper for side-loading check if needed

logger = logging.getLogger(__name__)


def audit_ios_configuration(
    profile: DeviceProfile,
    lockdown: Any | None = None,
) -> ComplianceReport:
    """
    Audit iOS device configuration against CIS iOS Benchmark v8 and NIST SP 800-124 Rev 2.

    Parameters
    ----------
    profile:
        DeviceProfile built by fingerprint_ios_usb/mdm.
    lockdown:
        Optional live pymobiledevice3 LockdownClient for deeper checks.
        When None, audit is based on profile data only.
    """
    controls: list[ComplianceControl] = []

    # ------------------------------------------------------------------ #
    # 1. Passcode / Screen Lock                                            #
    # ------------------------------------------------------------------ #
    controls.append(_check_passcode(profile, lockdown))

    # ------------------------------------------------------------------ #
    # 2. Biometrics (Touch ID / Face ID)                                   #
    # ------------------------------------------------------------------ #
    controls.append(_check_biometrics(profile, lockdown))

    # ------------------------------------------------------------------ #
    # 3. Data encryption                                                   #
    # ------------------------------------------------------------------ #
    controls.append(ComplianceControl(
        control_id="CIS-iOS-2.1",
        framework="CIS",
        title="Data Protection (Encryption at Rest)",
        description="Device storage must be encrypted via iOS Data Protection.",
        status=ComplianceStatus.PASS if profile.encryption_enabled else ComplianceStatus.FAIL,
        current_value=profile.encryption_enabled,
        expected_value=True,
        remediation="Enable a device passcode to activate Data Protection.",
        severity=Severity.CRITICAL,
    ))

    # ------------------------------------------------------------------ #
    # 4. Automatic updates                                                 #
    # ------------------------------------------------------------------ #
    controls.append(_check_auto_updates(profile, lockdown))

    # ------------------------------------------------------------------ #
    # 5. Jailbreak status                                                  #
    # ------------------------------------------------------------------ #
    controls.append(ComplianceControl(
        control_id="CIS-iOS-3.1",
        framework="CIS",
        title="Jailbreak Detection",
        description="Device must not be jailbroken. Jailbreaking removes OS security controls.",
        status=ComplianceStatus.FAIL if profile.is_jailbroken else ComplianceStatus.PASS,
        current_value=f"Jailbroken ({profile.root_method})" if profile.is_jailbroken else False,
        expected_value=False,
        remediation=(
            "Factory reset the device and restore from a clean backup. "
            "Block device access to corporate resources."
        ),
        severity=Severity.CRITICAL,
    ))

    # ------------------------------------------------------------------ #
    # 6. MDM enrollment                                                    #
    # ------------------------------------------------------------------ #
    mdm_profiles = [
        p for p in profile.installed_profiles
        if "mdm" in p.get("name", "").lower()
        or "mdm" in p.get("identifier", "").lower()
        or "management" in p.get("name", "").lower()
    ]
    controls.append(ComplianceControl(
        control_id="NIST-SP800-124-4.1",
        framework="NIST",
        title="MDM Enrollment",
        description="Device must be enrolled in a corporate MDM solution.",
        status=ComplianceStatus.PASS if mdm_profiles else ComplianceStatus.FAIL,
        current_value=bool(mdm_profiles),
        expected_value=True,
        remediation="Enroll the device in the corporate MDM before granting access.",
        severity=Severity.HIGH,
    ))

    # ------------------------------------------------------------------ #
    # 7. VPN profile installed                                             #
    # ------------------------------------------------------------------ #
    vpn_profiles = [
        p for p in profile.installed_profiles
        if "vpn" in p.get("name", "").lower()
        or "vpn" in p.get("identifier", "").lower()
    ]
    controls.append(ComplianceControl(
        control_id="NIST-SP800-124-4.5",
        framework="NIST",
        title="VPN Profile Installed",
        description="A corporate VPN profile should be installed for secure remote access.",
        status=ComplianceStatus.PASS if vpn_profiles else ComplianceStatus.WARN,
        current_value=bool(vpn_profiles),
        expected_value=True,
        remediation="Push the corporate VPN profile via MDM.",
        severity=Severity.MEDIUM,
    ))

    # ------------------------------------------------------------------ #
    # 8. No unauthorised profiles (e.g. traffic interception certs)        #
    # ------------------------------------------------------------------ #
    controls.append(_check_unauthorized_profiles(profile))

    # ------------------------------------------------------------------ #
    # 9. Find My / iCloud Activation Lock                                  #
    # ------------------------------------------------------------------ #
    controls.append(_check_find_my(profile, lockdown))

    # ------------------------------------------------------------------ #
    # 10. Encrypted backups                                                #
    # ------------------------------------------------------------------ #
    controls.append(_check_encrypted_backup(profile, lockdown))

    # ------------------------------------------------------------------ #
    # 11. App with private API entitlements (suspicious)                   #
    # ------------------------------------------------------------------ #
    controls.append(_check_suspicious_entitlements(profile))

    report = ComplianceReport(
        device_udid=profile.udid,
        platform=Platform.IOS,
        generated_at=__import__("datetime").datetime.utcnow(),
        controls=controls,
    )
    report.overall_score = report.compute_score()
    report.risk_level = _derive_risk(report)
    return report


# ------------------------------------------------------------------ #
# Helper check functions                                               #
# ------------------------------------------------------------------ #

def _check_passcode(profile: DeviceProfile, lockdown: Any | None) -> ComplianceControl:
    passcode_enabled: bool | None = None

    if lockdown is not None:
        try:
            from pymobiledevice3.services.mobile_config import MobileConfigService
            svc = MobileConfigService(lockdown)
            restrictions = svc.get_restrictions()
            passcode_enabled = not restrictions.get("allowSimpleValue", True)
        except Exception:
            pass

    # Fall back to raw MDM DeviceInformation response
    if passcode_enabled is None:
        passcode_enabled = profile.raw_properties.get("PasscodePresent") == "1" or \
                           profile.raw_properties.get("PasscodePresent") is True

    if passcode_enabled is None:
        status = ComplianceStatus.UNKNOWN
        current_value = "unable to determine"
    elif passcode_enabled:
        status = ComplianceStatus.PASS
        current_value = True
    else:
        status = ComplianceStatus.FAIL
        current_value = False

    return ComplianceControl(
        control_id="CIS-iOS-1.1",
        framework="CIS",
        title="Passcode Enabled",
        description="A device passcode must be set and must meet minimum complexity requirements.",
        status=status,
        current_value=current_value,
        expected_value=True,
        remediation="Navigate to Settings > Face ID & Passcode and set a 6+ digit passcode.",
        severity=Severity.CRITICAL,
    )


def _check_biometrics(profile: DeviceProfile, lockdown: Any | None) -> ComplianceControl:
    biometrics_raw = profile.raw_properties.get("BiometricAvailable") or \
                     profile.raw_properties.get("BiometricEnrolled")
    biometrics_enabled = str(biometrics_raw).lower() in ("1", "true", "yes") \
                         if biometrics_raw is not None else None

    return ComplianceControl(
        control_id="CIS-iOS-1.2",
        framework="CIS",
        title="Touch ID / Face ID Enabled",
        description="Biometric authentication should be enabled for convenient secure access.",
        status=(ComplianceStatus.PASS if biometrics_enabled
                else ComplianceStatus.WARN if biometrics_enabled is False
                else ComplianceStatus.UNKNOWN),
        current_value=biometrics_enabled,
        expected_value=True,
        remediation="Enable Touch ID or Face ID in Settings > Face ID & Passcode.",
        severity=Severity.LOW,
    )


def _check_auto_updates(profile: DeviceProfile, lockdown: Any | None) -> ComplianceControl:
    auto_update = profile.raw_properties.get("AutoUpdate") or \
                  profile.raw_properties.get("OSUpdateSettings")
    enabled = str(auto_update).lower() in ("1", "true") if auto_update else None

    return ComplianceControl(
        control_id="CIS-iOS-1.5",
        framework="CIS",
        title="Automatic iOS Updates Enabled",
        description="Automatic updates ensure timely application of security patches.",
        status=(ComplianceStatus.PASS if enabled
                else ComplianceStatus.FAIL if enabled is False
                else ComplianceStatus.UNKNOWN),
        current_value=enabled,
        expected_value=True,
        remediation="Enable automatic updates in Settings > General > Software Update.",
        severity=Severity.HIGH,
    )


def _check_find_my(profile: DeviceProfile, lockdown: Any | None) -> ComplianceControl:
    find_my = profile.raw_properties.get("IsActivationLockEnabled") or \
              profile.raw_properties.get("FindMyDeviceEnabled")
    enabled = str(find_my).lower() in ("1", "true") if find_my is not None else None

    return ComplianceControl(
        control_id="CIS-iOS-2.3",
        framework="CIS",
        title="Find My / Activation Lock Enabled",
        description="Activation Lock prevents unauthorised use after loss or theft.",
        status=(ComplianceStatus.PASS if enabled
                else ComplianceStatus.FAIL if enabled is False
                else ComplianceStatus.UNKNOWN),
        current_value=enabled,
        expected_value=True,
        remediation="Sign in to iCloud and enable Find My iPhone.",
        severity=Severity.MEDIUM,
    )


def _check_encrypted_backup(profile: DeviceProfile, lockdown: Any | None) -> ComplianceControl:
    backup_encrypted = profile.raw_properties.get("IsEncrypted") or \
                       profile.raw_properties.get("BackupEncrypted")
    enabled = str(backup_encrypted).lower() in ("1", "true") \
               if backup_encrypted is not None else None

    return ComplianceControl(
        control_id="CIS-iOS-2.4",
        framework="CIS",
        title="iTunes / Local Backup Encryption",
        description="Local device backups must be encrypted to protect corporate data.",
        status=(ComplianceStatus.PASS if enabled
                else ComplianceStatus.WARN if enabled is False
                else ComplianceStatus.UNKNOWN),
        current_value=enabled,
        expected_value=True,
        remediation=(
            "In Finder/iTunes, check 'Encrypt local backup' when backing up the device, "
            "or enforce via MDM restriction."
        ),
        severity=Severity.MEDIUM,
    )


def _check_unauthorized_profiles(profile: DeviceProfile) -> ComplianceControl:
    """Flag any installed profile that could intercept TLS traffic."""
    suspicious: list[str] = []
    corp_keywords = ("corporate", "enterprise", "company", "mdm", "vpn", "wifi", "email")

    for p in profile.installed_profiles:
        name_lower = p.get("name", "").lower()
        ident_lower = p.get("identifier", "").lower()
        # Flag profiles not matching any corporate keyword
        if not any(kw in name_lower or kw in ident_lower for kw in corp_keywords):
            suspicious.append(p.get("name") or p.get("identifier") or "unnamed")

    return ComplianceControl(
        control_id="CIS-iOS-4.1",
        framework="CIS",
        title="No Unauthorised Configuration Profiles",
        description=(
            "Configuration profiles can install root CA certificates that enable "
            "TLS interception. Only MDM/corporate profiles should be present."
        ),
        status=ComplianceStatus.FAIL if suspicious else ComplianceStatus.PASS,
        current_value=suspicious or "none",
        expected_value="no suspicious profiles",
        remediation="Remove unrecognised profiles via Settings > General > VPN & Device Management.",
        severity=Severity.HIGH,
    )


def _check_suspicious_entitlements(profile: DeviceProfile) -> ComplianceControl:
    """Detect apps with entitlements typically used by spyware or privileged tools."""
    SUSPICIOUS_ENTITLEMENTS = {
        "com.apple.private.security.no-sandbox",
        "com.apple.private.memorystatus",
        "com.apple.private.cs.debugger",
        "com.apple.security.get-task-allow",
        "platform-application",
        "com.apple.private.icloud.account.access",
    }
    flagged: list[str] = []
    for app in profile.installed_apps:
        if app.is_system:
            continue
        found = SUSPICIOUS_ENTITLEMENTS.intersection(set(app.entitlements.keys()))
        if found:
            flagged.append(f"{app.bundle_id} ({', '.join(found)})")

    return ComplianceControl(
        control_id="CIS-iOS-5.2",
        framework="CIS",
        title="No User Apps with Private API Entitlements",
        description=(
            "Third-party apps should not hold private Apple entitlements. "
            "Their presence may indicate enterprise-signed spyware."
        ),
        status=ComplianceStatus.FAIL if flagged else ComplianceStatus.PASS,
        current_value=flagged or "none",
        expected_value="none",
        remediation="Remove the flagged applications and investigate how they were installed.",
        severity=Severity.HIGH,
    )


def _derive_risk(report: ComplianceReport) -> Severity:
    critical_fails = [
        c for c in report.failed()
        if c.severity == Severity.CRITICAL
    ]
    high_fails = [
        c for c in report.failed()
        if c.severity == Severity.HIGH
    ]
    if critical_fails:
        return Severity.CRITICAL
    if high_fails:
        return Severity.HIGH
    if report.failed():
        return Severity.MEDIUM
    if report.warnings():
        return Severity.LOW
    return Severity.INFO
