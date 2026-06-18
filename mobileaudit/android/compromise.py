"""Android Indicator of Compromise (IOC) detection."""

from __future__ import annotations

import logging
import re
from typing import Any

from ..models import IOC, DeviceProfile, Severity

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Pegasus / NSO Group Android indicators
# ------------------------------------------------------------------
PEGASUS_ANDROID_PACKAGES = {
    "com.network.android",
    "com.updates.android",
    "com.system.update.service",
    "com.android.system.update",
}

# Cerberus banking trojan package patterns
CERBERUS_PACKAGE_PATTERNS = [
    r"com\.mmt\.\w+",
    r"com\.android\.protect\.\w+",
]

# FlexiSpy and commercial stalkerware packages
STALKERWARE_PACKAGES = {
    "com.flexispy.android",
    "com.mspy.android",
    "com.spyzie.android",
    "com.thetruthspy.android",
    "com.hoverwatch.android",
    "com.iKeyMonitor.android",
    "com.phonesheriff.android",
    "com.highster.android",
    "com.kidguard.android",
    "net.msafely.android",
}

# Permissions that are commonly abused by spyware and banking trojans
HIGH_RISK_PERMISSION_COMBOS: list[set[str]] = [
    # Combination that allows full device monitoring
    {
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CALL_LOG",
    },
    # Banking overlay attack combo
    {
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.READ_SMS",
    },
]

# Suspicious app name patterns (Pegasus disguises itself as system apps)
PEGASUS_ANDROID_PROCESS_PATTERNS = [
    r"com\.android\.system\.",
    r"com\.google\.android\.gms\.persistent",
    r"com\.qualcomm\.qcrilmsgtunnel",
]

# Known MITM certificate fingerprints (partial SHA1 — never real in production,
# these are illustrative placeholders)
KNOWN_MITM_CA_SUBJECTS = [
    "burpsuite",
    "charles proxy ca",
    "mitmproxy",
    "fiddler root certificate",
    "ssl kill switch",
]


def detect_android_iocs(
    profile: DeviceProfile,
    serial: str | None = None,
) -> list[IOC]:
    """
    Scan an Android device profile for indicators of compromise.

    Parameters
    ----------
    profile:
        DeviceProfile from fingerprint_android.
    serial:
        ADB serial for live checks (network connections, certificates).
    """
    iocs: list[IOC] = []

    iocs.extend(_check_known_spyware_packages(profile))
    iocs.extend(_check_permission_abuse(profile))
    iocs.extend(_check_root_with_hidden_su(profile))
    iocs.extend(_check_sideloaded_system_mimics(profile))

    if serial:
        iocs.extend(_check_mitm_certificates(serial))
        iocs.extend(_check_suspicious_network_connections(serial))
        iocs.extend(_check_suspicious_device_admins(serial))

    return iocs


def _check_known_spyware_packages(profile: DeviceProfile) -> list[IOC]:
    iocs: list[IOC] = []
    installed_ids = {app.bundle_id for app in profile.installed_apps}

    # Direct match: known stalkerware
    for pkg in STALKERWARE_PACKAGES:
        if pkg in installed_ids:
            iocs.append(IOC(
                ioc_id=f"android-stalkerware-{pkg}",
                name=f"Known stalkerware installed: {pkg}",
                description=(
                    f"Package '{pkg}' is a commercial stalkerware or spyware product. "
                    "It covertly monitors calls, messages, location, and media."
                ),
                severity=Severity.CRITICAL,
                indicator_type="app",
                value=pkg,
                threat_family="Commercial Spyware",
                confidence=1.0,
            ))

    # Pegasus-specific packages
    for pkg in PEGASUS_ANDROID_PACKAGES:
        if pkg in installed_ids:
            iocs.append(IOC(
                ioc_id=f"android-pegasus-pkg-{pkg}",
                name=f"Pegasus-associated package detected: {pkg}",
                description=(
                    f"Package '{pkg}' is associated with the Pegasus spyware (NSO Group). "
                    "The device may be compromised via a zero-click exploit."
                ),
                severity=Severity.CRITICAL,
                indicator_type="app",
                value=pkg,
                threat_family="Pegasus",
                confidence=0.9,
                reference="https://github.com/mvt-project/mvt",
            ))

    # Pattern-based: Cerberus
    for app in profile.installed_apps:
        for pattern in CERBERUS_PACKAGE_PATTERNS:
            if re.match(pattern, app.bundle_id):
                iocs.append(IOC(
                    ioc_id=f"android-cerberus-pattern-{app.bundle_id}",
                    name=f"Cerberus-pattern package: {app.bundle_id}",
                    description=(
                        f"Package '{app.bundle_id}' matches a Cerberus banking trojan "
                        "naming pattern. Cerberus uses accessibility services to steal "
                        "credentials and intercept 2FA SMS."
                    ),
                    severity=Severity.HIGH,
                    indicator_type="app",
                    value=app.bundle_id,
                    threat_family="Cerberus",
                    confidence=0.7,
                    reference="https://www.threatfabric.com/blogs/cerberus-a-new-banking-trojan-for-rent",
                ))
                break

    return iocs


def _check_permission_abuse(profile: DeviceProfile) -> list[IOC]:
    """Flag non-system apps holding dangerous permission combinations."""
    iocs: list[IOC] = []
    for app in profile.installed_apps:
        if app.is_system:
            continue
        app_perms = set(app.permissions)
        for i, combo in enumerate(HIGH_RISK_PERMISSION_COMBOS):
            if combo.issubset(app_perms):
                iocs.append(IOC(
                    ioc_id=f"android-permission-combo-{app.bundle_id}-{i}",
                    name=f"App holds high-risk permission combination: {app.bundle_id}",
                    description=(
                        f"App '{app.bundle_id}' holds the permission combination: "
                        f"{sorted(combo)}. This combination is commonly abused by "
                        "spyware and banking trojans to perform full device surveillance "
                        "or credential theft."
                    ),
                    severity=Severity.HIGH,
                    indicator_type="permission",
                    value=f"{app.bundle_id}: {sorted(combo)}",
                    threat_family="Generic Spyware / Banking Trojan",
                    confidence=0.65,
                ))
    return iocs


def _check_root_with_hidden_su(profile: DeviceProfile) -> list[IOC]:
    """
    If the device is rooted but Magisk/su wasn't found via standard paths,
    raise a low-confidence IOC — it may indicate a stealthy root hide.
    """
    iocs: list[IOC] = []
    if profile.is_rooted and not profile.root_method:
        iocs.append(IOC(
            ioc_id="android-hidden-root",
            name="Device appears rooted with hidden root management",
            description=(
                "The device shows signs of being rooted, but no standard root "
                "binary or Magisk installation was found. This may indicate "
                "the use of a root-hiding tool (e.g. Magisk Hide, Zygisk Deny List, "
                "or a kernel-level patch) to evade detection."
            ),
            severity=Severity.HIGH,
            indicator_type="process",
            value="hidden_root",
            threat_family="Root / Privilege Escalation",
            confidence=0.6,
        ))
    return iocs


def _check_sideloaded_system_mimics(profile: DeviceProfile) -> list[IOC]:
    """
    Detect non-system apps that mimic Android system package names.
    Spyware often uses com.android.* or com.google.* bundle IDs.
    """
    LEGITIMATE_SYSTEM_PREFIXES = {
        "com.android.",
        "com.google.android.",
        "com.samsung.android.",
        "android.",
    }
    iocs: list[IOC] = []
    for app in profile.installed_apps:
        if app.is_system:
            continue
        if any(app.bundle_id.startswith(prefix) for prefix in LEGITIMATE_SYSTEM_PREFIXES):
            iocs.append(IOC(
                ioc_id=f"android-system-mimic-{app.bundle_id}",
                name=f"Non-system app mimics system package name: {app.bundle_id}",
                description=(
                    f"User-installed app '{app.bundle_id}' uses a system-like package "
                    "name prefix. Spyware commonly disguises itself as a system service "
                    "to avoid user suspicion."
                ),
                severity=Severity.HIGH,
                indicator_type="app",
                value=app.bundle_id,
                threat_family="System Mimic / Spyware",
                confidence=0.75,
            ))
    return iocs


def _check_mitm_certificates(serial: str) -> list[IOC]:
    """Detect user-installed CA certificates (MITM enablers) via ADB."""
    from ..android.fingerprint import _adb

    iocs: list[IOC] = []
    try:
        out = _adb(
            ["shell", "ls /data/misc/user/0/cacerts-added/ 2>/dev/null"],
            serial=serial,
        )
    except RuntimeError:
        return iocs

    if out and "No such file" not in out:
        cert_files = [f.strip() for f in out.splitlines() if f.strip()]
        for cert_file in cert_files:
            try:
                cert_info = _adb(
                    ["shell",
                     f"openssl x509 -in /data/misc/user/0/cacerts-added/{cert_file} "
                     "-noout -subject -issuer 2>/dev/null"],
                    serial=serial,
                )
            except RuntimeError:
                continue
            cert_lower = cert_info.lower()
            for pattern in KNOWN_MITM_CA_SUBJECTS:
                if pattern in cert_lower:
                    iocs.append(IOC(
                        ioc_id=f"android-mitm-ca-{cert_file}",
                        name=f"MITM CA certificate installed: {cert_file}",
                        description=(
                            f"A user-installed CA certificate matching '{pattern}' was found. "
                            "This certificate can be used to intercept TLS traffic via a "
                            "man-in-the-middle proxy."
                        ),
                        severity=Severity.CRITICAL,
                        indicator_type="certificate",
                        value=cert_info[:200],
                        threat_family="MITM / Traffic Interception",
                        confidence=0.9,
                    ))
                    break
            else:
                iocs.append(IOC(
                    ioc_id=f"android-user-ca-{cert_file}",
                    name=f"User-installed CA certificate: {cert_file}",
                    description=(
                        f"A user-installed CA certificate '{cert_file}' was found. "
                        "User CAs can enable TLS interception on network traffic."
                    ),
                    severity=Severity.MEDIUM,
                    indicator_type="certificate",
                    value=cert_info[:200],
                    threat_family="Potential MITM",
                    confidence=0.5,
                ))
    return iocs


def _check_suspicious_network_connections(serial: str) -> list[IOC]:
    """Check active network connections for Pegasus/C2 infrastructure."""
    from ..android.fingerprint import _adb

    iocs: list[IOC] = []
    try:
        out = _adb(["shell", "ss -tnp 2>/dev/null || netstat -tn 2>/dev/null"], serial=serial)
    except RuntimeError:
        return iocs

    # Known C2/Pegasus infrastructure IP ranges (illustrative — production should
    # load from a threat intel feed or MVT IOC database)
    SUSPICIOUS_IP_PATTERNS = [
        r"\b198\.199\.\d+\.\d+\b",   # Example suspicious range
    ]

    for pattern in SUSPICIOUS_IP_PATTERNS:
        matches = re.findall(pattern, out)
        for ip in set(matches):
            iocs.append(IOC(
                ioc_id=f"android-suspicious-conn-{ip}",
                name=f"Active connection to suspicious IP: {ip}",
                description=(
                    f"An active network connection to IP '{ip}' was detected. "
                    "This IP matches a range associated with C2 infrastructure."
                ),
                severity=Severity.HIGH,
                indicator_type="network",
                value=ip,
                threat_family="C2 Infrastructure",
                confidence=0.55,
            ))
    return iocs


def _check_suspicious_device_admins(serial: str) -> list[IOC]:
    """Flag non-MDM device admin apps — common persistence mechanism for spyware."""
    from ..android.fingerprint import _adb

    KNOWN_CORP_MDM = {
        "com.microsoft.intune",
        "com.vmware.horizon",
        "com.airwatch.agent",
        "com.mobileiron",
        "com.jamf.management",
        "com.blackberry.protect",
    }

    iocs: list[IOC] = []
    try:
        out = _adb(
            ["shell", "dumpsys device_policy | grep 'Active admin:'"], serial=serial
        )
    except RuntimeError:
        return iocs
    for line in out.splitlines():
        m = re.search(r"Active admin:\s+ComponentInfo\{([^/}]+)/", line)
        if m:
            pkg = m.group(1)
            if pkg not in KNOWN_CORP_MDM:
                iocs.append(IOC(
                    ioc_id=f"android-rogue-device-admin-{pkg}",
                    name=f"Unauthorised device admin app: {pkg}",
                    description=(
                        f"Package '{pkg}' has Device Administrator privileges but is not "
                        "a recognised corporate MDM app. Spyware and ransomware commonly "
                        "acquire device admin rights to prevent removal."
                    ),
                    severity=Severity.CRITICAL,
                    indicator_type="app",
                    value=pkg,
                    threat_family="Spyware / Ransomware Persistence",
                    confidence=0.8,
                ))
    return iocs
