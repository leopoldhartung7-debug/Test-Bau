"""Android configuration security audit — CIS Android Benchmark & NIST SP 800-124."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from ..models import (
    ComplianceControl,
    ComplianceReport,
    ComplianceStatus,
    DeviceProfile,
    Platform,
    Severity,
)

logger = logging.getLogger(__name__)

# Minimum acceptable security patch age (days)
MAX_PATCH_AGE_DAYS = 90


def audit_android_configuration(
    profile: DeviceProfile,
    serial: str | None = None,
) -> ComplianceReport:
    """
    Audit Android device configuration against CIS Android Benchmark and NIST SP 800-124.

    Parameters
    ----------
    profile:
        DeviceProfile built by fingerprint_android.
    serial:
        ADB serial number for live checks. When None, audit uses profile data only.
    """
    from ..android.fingerprint import (
        check_developer_options,
        check_play_protect,
        check_screen_lock,
        check_unknown_sources,
        check_usb_debugging,
    )

    controls: list[ComplianceControl] = []

    # ------------------------------------------------------------------ #
    # 1. Screen lock / PIN                                                 #
    # ------------------------------------------------------------------ #
    if serial:
        try:
            lock_enabled, lock_type = check_screen_lock(serial)
        except Exception as exc:
            logger.warning("Screen lock check failed: %s", exc)
            lock_enabled, lock_type = None, "unknown"
    else:
        lock_enabled = None
        lock_type = profile.raw_properties.get("PasswordQuality", "unknown")

    controls.append(ComplianceControl(
        control_id="CIS-Android-1.1",
        framework="CIS",
        title="Screen Lock Enabled",
        description="A screen lock (PIN, password, or pattern) must be configured.",
        status=(ComplianceStatus.PASS if lock_enabled
                else ComplianceStatus.FAIL if lock_enabled is False
                else ComplianceStatus.UNKNOWN),
        current_value=f"enabled ({lock_type})" if lock_enabled else lock_enabled,
        expected_value=True,
        remediation="Go to Settings > Security > Screen Lock and set a PIN or password.",
        severity=Severity.CRITICAL,
    ))

    # ------------------------------------------------------------------ #
    # 2. Full-disk / file-based encryption                                 #
    # ------------------------------------------------------------------ #
    controls.append(ComplianceControl(
        control_id="CIS-Android-1.2",
        framework="CIS",
        title="Device Encryption Enabled",
        description="Device storage must be encrypted (FBE or FDE).",
        status=(ComplianceStatus.PASS if profile.encryption_enabled
                else ComplianceStatus.FAIL if profile.encryption_enabled is False
                else ComplianceStatus.UNKNOWN),
        current_value=profile.encryption_enabled,
        expected_value=True,
        remediation="Go to Settings > Security > Encryption & Credentials and encrypt device.",
        severity=Severity.CRITICAL,
    ))

    # ------------------------------------------------------------------ #
    # 3. Bootloader lock status                                            #
    # ------------------------------------------------------------------ #
    controls.append(ComplianceControl(
        control_id="CIS-Android-2.1",
        framework="CIS",
        title="Bootloader Locked",
        description="The bootloader must be locked to prevent unauthorised OS modifications.",
        status=(ComplianceStatus.PASS if profile.bootloader_locked
                else ComplianceStatus.FAIL if profile.bootloader_locked is False
                else ComplianceStatus.UNKNOWN),
        current_value=profile.bootloader_locked,
        expected_value=True,
        remediation=(
            "Re-lock the bootloader and perform a factory reset. "
            "Block device access if bootloader is unlocked."
        ),
        severity=Severity.CRITICAL,
    ))

    # ------------------------------------------------------------------ #
    # 4. Root detection                                                    #
    # ------------------------------------------------------------------ #
    controls.append(ComplianceControl(
        control_id="CIS-Android-2.2",
        framework="CIS",
        title="Device Not Rooted",
        description="Rooted devices bypass Android security model and must not access corporate resources.",
        status=ComplianceStatus.FAIL if profile.is_rooted else ComplianceStatus.PASS,
        current_value=f"Rooted ({profile.root_method})" if profile.is_rooted else False,
        expected_value=False,
        remediation="Factory reset the device. Enforce root detection via MDM policy.",
        severity=Severity.CRITICAL,
    ))

    # ------------------------------------------------------------------ #
    # 5. Security patch level recency                                      #
    # ------------------------------------------------------------------ #
    controls.append(_check_patch_level(profile))

    # ------------------------------------------------------------------ #
    # 6. Google Play Protect                                               #
    # ------------------------------------------------------------------ #
    if serial:
        try:
            play_protect = check_play_protect(serial)
        except Exception as exc:
            logger.warning("Play Protect check failed: %s", exc)
            play_protect = None
    else:
        play_protect = None

    controls.append(ComplianceControl(
        control_id="CIS-Android-3.1",
        framework="CIS",
        title="Google Play Protect Enabled",
        description="Play Protect scans apps for malware and should always be enabled.",
        status=(ComplianceStatus.PASS if play_protect
                else ComplianceStatus.FAIL if play_protect is False
                else ComplianceStatus.UNKNOWN),
        current_value=play_protect,
        expected_value=True,
        remediation="Open Play Store > Profile > Play Protect and enable it.",
        severity=Severity.HIGH,
    ))

    # ------------------------------------------------------------------ #
    # 7. Unknown sources / sideloading                                     #
    # ------------------------------------------------------------------ #
    if serial:
        try:
            unknown_sources = check_unknown_sources(serial)
        except Exception as exc:
            logger.warning("Unknown sources check failed: %s", exc)
            unknown_sources = None
    else:
        unknown_sources = None

    controls.append(ComplianceControl(
        control_id="CIS-Android-3.2",
        framework="CIS",
        title="Install from Unknown Sources Disabled",
        description="Sideloading allows installation of unvetted APKs, increasing malware risk.",
        status=(ComplianceStatus.FAIL if unknown_sources
                else ComplianceStatus.PASS if unknown_sources is False
                else ComplianceStatus.UNKNOWN),
        current_value=unknown_sources,
        expected_value=False,
        remediation="Disable 'Install unknown apps' in Settings > Apps > Special App Access.",
        severity=Severity.HIGH,
    ))

    # ------------------------------------------------------------------ #
    # 8. USB debugging                                                     #
    # ------------------------------------------------------------------ #
    if serial:
        try:
            usb_debug = check_usb_debugging(serial)
        except Exception as exc:
            logger.warning("USB debugging check failed: %s", exc)
            usb_debug = None
    else:
        usb_debug = None

    controls.append(ComplianceControl(
        control_id="CIS-Android-4.1",
        framework="CIS",
        title="USB Debugging Disabled",
        description=(
            "USB debugging grants ADB shell access to the device. "
            "It must be disabled on production BYOD devices."
        ),
        status=(ComplianceStatus.FAIL if usb_debug
                else ComplianceStatus.PASS if usb_debug is False
                else ComplianceStatus.UNKNOWN),
        current_value=usb_debug,
        expected_value=False,
        remediation="Disable USB debugging in Settings > Developer Options.",
        severity=Severity.HIGH,
    ))

    # ------------------------------------------------------------------ #
    # 9. Developer options                                                 #
    # ------------------------------------------------------------------ #
    if serial:
        try:
            dev_opts = check_developer_options(serial)
        except Exception as exc:
            logger.warning("Developer options check failed: %s", exc)
            dev_opts = None
    else:
        dev_opts = None

    controls.append(ComplianceControl(
        control_id="CIS-Android-4.2",
        framework="CIS",
        title="Developer Options Disabled",
        description="Developer options expose sensitive debugging and override capabilities.",
        status=(ComplianceStatus.WARN if dev_opts
                else ComplianceStatus.PASS if dev_opts is False
                else ComplianceStatus.UNKNOWN),
        current_value=dev_opts,
        expected_value=False,
        remediation="Disable developer options in Settings > System > Developer Options.",
        severity=Severity.MEDIUM,
    ))

    # ------------------------------------------------------------------ #
    # 10. Excessive permission apps (accessibility abuse)                  #
    # ------------------------------------------------------------------ #
    controls.append(_check_accessibility_abuse(profile))

    # ------------------------------------------------------------------ #
    # 11. Non-MDM device admin apps                                        #
    # ------------------------------------------------------------------ #
    controls.append(_check_device_admins(profile, serial))

    report = ComplianceReport(
        device_udid=profile.udid,
        platform=Platform.ANDROID,
        generated_at=datetime.utcnow(),
        controls=controls,
    )
    report.overall_score = report.compute_score()
    report.risk_level = _derive_risk(report)
    return report


def _check_patch_level(profile: DeviceProfile) -> ComplianceControl:
    patch_str = profile.security_patch_level  # format: "YYYY-MM-DD" or "YYYY-MM-05"
    if not patch_str:
        return ComplianceControl(
            control_id="CIS-Android-1.3",
            framework="CIS",
            title="Security Patch Level Current",
            description=f"Security patch must be within the last {MAX_PATCH_AGE_DAYS} days.",
            status=ComplianceStatus.UNKNOWN,
            current_value="unavailable",
            expected_value=f"within {MAX_PATCH_AGE_DAYS} days",
            remediation="Install the latest security patch via Settings > System > System Update.",
            severity=Severity.HIGH,
        )

    try:
        # Patches come as "YYYY-MM-DD" or "YYYY-MM-01/05"
        patch_date = datetime.strptime(patch_str[:10], "%Y-%m-%d")
        age = (datetime.utcnow() - patch_date).days
        is_current = age <= MAX_PATCH_AGE_DAYS
        return ComplianceControl(
            control_id="CIS-Android-1.3",
            framework="CIS",
            title="Security Patch Level Current",
            description=f"Security patch must be within the last {MAX_PATCH_AGE_DAYS} days.",
            status=ComplianceStatus.PASS if is_current else ComplianceStatus.FAIL,
            current_value=f"{patch_str} ({age} days ago)",
            expected_value=f"within {MAX_PATCH_AGE_DAYS} days",
            remediation="Install the latest security patch via Settings > System > System Update.",
            severity=Severity.HIGH,
        )
    except ValueError:
        return ComplianceControl(
            control_id="CIS-Android-1.3",
            framework="CIS",
            title="Security Patch Level Current",
            description=f"Security patch must be within the last {MAX_PATCH_AGE_DAYS} days.",
            status=ComplianceStatus.UNKNOWN,
            current_value=patch_str,
            expected_value=f"within {MAX_PATCH_AGE_DAYS} days",
            remediation="Install the latest security patch via Settings > System > System Update.",
            severity=Severity.HIGH,
        )


def _check_accessibility_abuse(profile: DeviceProfile) -> ComplianceControl:
    """Flag non-system apps that have the BIND_ACCESSIBILITY_SERVICE permission."""
    flagged: list[str] = []
    for app in profile.installed_apps:
        if app.is_system:
            continue
        if "android.permission.BIND_ACCESSIBILITY_SERVICE" in app.permissions:
            flagged.append(app.bundle_id)

    return ComplianceControl(
        control_id="CIS-Android-5.1",
        framework="CIS",
        title="No Suspicious Accessibility Service Apps",
        description=(
            "Accessibility services can read screen content and inject input events. "
            "Banking trojans and spyware commonly abuse this permission."
        ),
        status=ComplianceStatus.FAIL if flagged else ComplianceStatus.PASS,
        current_value=flagged or "none",
        expected_value="none",
        remediation="Disable and uninstall flagged accessibility apps via Settings > Accessibility.",
        severity=Severity.HIGH,
    )


def _check_device_admins(
    profile: DeviceProfile,
    serial: str | None,
) -> ComplianceControl:
    """Detect non-corporate device admin apps (potential stalkerware)."""
    if not serial:
        return ComplianceControl(
            control_id="CIS-Android-5.2",
            framework="CIS",
            title="No Rogue Device Admin Apps",
            description="Only corporate MDM apps should have Device Administrator privileges.",
            status=ComplianceStatus.UNKNOWN,
            current_value="live check unavailable",
            expected_value="only corporate MDM",
            remediation="Run a live ADB scan to list device admin apps.",
            severity=Severity.HIGH,
        )

    from ..android.fingerprint import _adb

    try:
        out = _adb(
            ["shell", "dumpsys device_policy | grep -A1 'Device Owner'"],
            serial=serial,
        )
        active_admins_out = _adb(
            ["shell", "dumpsys device_policy | grep 'Active admin'"],
            serial=serial,
        )
    except RuntimeError as exc:
        return ComplianceControl(
            control_id="CIS-Android-5.2",
            framework="CIS",
            title="No Rogue Device Admin Apps",
            description="Only corporate MDM apps should have Device Administrator privileges.",
            status=ComplianceStatus.UNKNOWN,
            current_value=f"ADB unavailable: {exc}",
            expected_value="only corporate MDM",
            remediation="Run a live ADB scan to list device admin apps.",
            severity=Severity.HIGH,
        )

    # Known legitimate corporate MDM package prefixes
    CORP_MDM_PREFIXES = (
        "com.microsoft.intune",
        "com.vmware.horizon",
        "com.airwatch",
        "com.mobileiron",
        "com.jamf",
        "com.blackberry",
        "com.google.android.apps.work",
    )

    flagged: list[str] = []
    import re
    for line in active_admins_out.splitlines():
        m = re.search(r"ComponentInfo\{([^/}]+)/", line)
        if m:
            pkg = m.group(1)
            if not any(pkg.startswith(prefix) for prefix in CORP_MDM_PREFIXES):
                flagged.append(pkg)

    return ComplianceControl(
        control_id="CIS-Android-5.2",
        framework="CIS",
        title="No Rogue Device Admin Apps",
        description="Only corporate MDM apps should have Device Administrator privileges.",
        status=ComplianceStatus.FAIL if flagged else ComplianceStatus.PASS,
        current_value=flagged or "none",
        expected_value="only corporate MDM",
        remediation=(
            "Go to Settings > Security > Device Admin Apps and revoke unknown admins, "
            "then uninstall them."
        ),
        severity=Severity.CRITICAL,
    )


def _derive_risk(report: ComplianceReport) -> Severity:
    critical_fails = [c for c in report.failed() if c.severity == Severity.CRITICAL]
    high_fails = [c for c in report.failed() if c.severity == Severity.HIGH]
    if critical_fails:
        return Severity.CRITICAL
    if high_fails:
        return Severity.HIGH
    if report.failed():
        return Severity.MEDIUM
    if report.warnings():
        return Severity.LOW
    return Severity.INFO
