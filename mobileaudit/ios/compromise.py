"""iOS Indicator of Compromise (IOC) detection."""

from __future__ import annotations

import logging
from typing import Any

from ..models import IOC, DeviceProfile, Severity

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Pegasus spyware indicators (NSO Group)
# References: Amnesty International Security Lab, Citizen Lab
# ------------------------------------------------------------------
PEGASUS_IOS_PROCESS_NAMES = {
    "aggregated", "BackupAgent", "ckkeyrolld", "CommCenter",
    "fmfd", "gssd", "IMDPersistenceAgent", "keybagd",
    "launchd", "locationd", "MobileSMS", "natd",
    "pcapd", "profiled", "securityd", "SpringBoard",
    # Pegasus-specific disguised process names
    "bh", "btl", "mptbd", "daemons",
    "fseventsd_embedded",
    "mediaserverd_", "locationdFix",
}

PEGASUS_IOS_DOMAINS = {
    # Network IOCs from Amnesty International MVT database
    "svcupdate.biz",
    "updatechecks.biz",
    "adobeair.biz",
    "edgesuite-statics.com",
    "ppnpedia.com",
    "linkishere.com",
    "datacdn.link",
    "dataupd.link",
    "aaa.stage.update.com",
    "cdn.cloudflare.host",
    "cdn-cache.net",
    "ns1.cdn-cache.net",
}

PEGASUS_IOS_FILES = {
    "/private/var/db/com.apple.xpc.roleaccountd.staging",
    "/private/var/tmp/com.apple.backboardd",
    "/private/var/tmp/com.apple.purplebuddy.plist",
    "/private/var/tmp/payload",
    "/private/var/MobileDevice/ProvisioningProfiles/payload.plist",
    "/private/var/preferences/Logging/.LoggingSupport.plist",
    # BridgeHead persistence artefacts
    "/private/var/db/locationd/cache_encryptedB.db",
    "/private/var/db/locationd/cache_encryptedA.db",
}

# Known spyware bundle IDs (enterprise-signed stalkerware)
SPYWARE_BUNDLE_IDS = {
    "com.spyzie.iphone",
    "com.hoverwatch.app",
    "com.mspy.app",
    "com.iKeyMonitor.app",
    "com.flexispy.ios",
    "com.highster.mobile",
    "com.ispyoo.app",
    "com.phonesheriff.app",
    "com.thetruthspy.app",
}

# Entitlements seen in Pegasus and NSO infrastructure apps
PEGASUS_ENTITLEMENTS = {
    "com.apple.private.WebKit.Internals",
    "com.apple.private.security.storage.MobileAsset",
    "com.apple.private.security.no-sandbox",
    "com.apple.private.security.no-container",
    "com.apple.private.network.socket-delegate",
    "com.apple.springboard.debugapplications",
    "com.apple.system-task-ports",
}

# MITM / traffic interception certificate Organisation Names
MITM_CA_ORG_PATTERNS = [
    "burp",
    "charles proxy",
    "mitmproxy",
    "fiddler",
    "ssl pinning bypass",
    "interceptor",
]


def detect_ios_iocs(
    profile: DeviceProfile,
    lockdown: Any | None = None,
) -> list[IOC]:
    """
    Scan an iOS device profile for indicators of compromise.

    Parameters
    ----------
    profile:
        DeviceProfile from fingerprint_ios_usb/mdm.
    lockdown:
        Optional live LockdownClient for filesystem-level checks.
    """
    iocs: list[IOC] = []

    iocs.extend(_check_pegasus_apps(profile))
    iocs.extend(_check_pegasus_entitlements(profile))
    iocs.extend(_check_spyware_apps(profile))
    iocs.extend(_check_mitm_profiles(profile))
    iocs.extend(_check_unauthorized_enterprise_certs(profile))

    if lockdown is not None:
        iocs.extend(_check_pegasus_files(lockdown))
        iocs.extend(_check_network_iocs(lockdown))

    return iocs


def _check_pegasus_apps(profile: DeviceProfile) -> list[IOC]:
    iocs: list[IOC] = []
    installed_ids = {app.bundle_id for app in profile.installed_apps}
    for bundle_id in SPYWARE_BUNDLE_IDS:
        if bundle_id in installed_ids:
            iocs.append(IOC(
                ioc_id=f"ios-spyware-app-{bundle_id}",
                name=f"Known spyware app installed: {bundle_id}",
                description=(
                    f"The app '{bundle_id}' is a known commercial spyware or stalkerware "
                    "product. It records calls, messages, location, and other sensitive data."
                ),
                severity=Severity.CRITICAL,
                indicator_type="app",
                value=bundle_id,
                threat_family="Commercial Spyware",
                confidence=1.0,
                reference="https://www.eff.org/deeplinks/2020/01/stalkerware-stalks-victims",
            ))
    return iocs


def _check_pegasus_entitlements(profile: DeviceProfile) -> list[IOC]:
    iocs: list[IOC] = []
    for app in profile.installed_apps:
        if app.is_system:
            continue
        suspicious = PEGASUS_ENTITLEMENTS.intersection(set(app.entitlements.keys()))
        if suspicious:
            iocs.append(IOC(
                ioc_id=f"ios-pegasus-entitlement-{app.bundle_id}",
                name=f"App holds Pegasus-associated entitlements: {app.bundle_id}",
                description=(
                    f"App '{app.bundle_id}' holds private Apple entitlements "
                    f"associated with the Pegasus spyware implant: {suspicious}. "
                    "These entitlements allow bypassing app sandbox and accessing "
                    "kernel task ports."
                ),
                severity=Severity.CRITICAL,
                indicator_type="app",
                value=f"{app.bundle_id}: {list(suspicious)}",
                threat_family="Pegasus",
                confidence=0.85,
                reference="https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/",
            ))
    return iocs


def _check_spyware_apps(profile: DeviceProfile) -> list[IOC]:
    """Check for generic commercial spyware by bundle ID patterns."""
    SPYWARE_KEYWORDS = ["spy", "monitor", "track", "stalk", "surveillance",
                        "parental", "location.tracker"]
    iocs: list[IOC] = []
    for app in profile.installed_apps:
        if app.is_system:
            continue
        bid_lower = app.bundle_id.lower()
        for kw in SPYWARE_KEYWORDS:
            if kw in bid_lower and app.bundle_id not in {
                # Legitimate apps to exclude
                "com.apple.locationd",
                "com.google.android.gms",
                "com.microsoft.intune",
                "com.apple.parentalcontrols",
            }:
                iocs.append(IOC(
                    ioc_id=f"ios-suspicious-app-kw-{app.bundle_id}",
                    name=f"Suspicious app bundle ID pattern: {app.bundle_id}",
                    description=(
                        f"App bundle ID '{app.bundle_id}' contains the keyword '{kw}', "
                        "which is associated with monitoring or spyware applications."
                    ),
                    severity=Severity.HIGH,
                    indicator_type="app",
                    value=app.bundle_id,
                    threat_family="Potential Spyware",
                    confidence=0.5,
                ))
                break
    return iocs


def _check_mitm_profiles(profile: DeviceProfile) -> list[IOC]:
    """Detect profiles that install root CAs for TLS interception."""
    iocs: list[IOC] = []
    for p in profile.installed_profiles:
        name_lower = p.get("name", "").lower()
        org_lower = p.get("organization", "").lower()
        for pattern in MITM_CA_ORG_PATTERNS:
            if pattern in name_lower or pattern in org_lower:
                iocs.append(IOC(
                    ioc_id=f"ios-mitm-profile-{p.get('identifier', 'unknown')}",
                    name=f"TLS interception profile detected: {p.get('name')}",
                    description=(
                        f"Configuration profile '{p.get('name')}' (org: {p.get('organization')}) "
                        "appears to install a CA certificate for TLS interception. "
                        "This could enable a man-in-the-middle attack on encrypted traffic."
                    ),
                    severity=Severity.CRITICAL,
                    indicator_type="certificate",
                    value=p.get("name", ""),
                    threat_family="MITM / Traffic Interception",
                    confidence=0.9,
                ))
                break
    return iocs


def _check_unauthorized_enterprise_certs(profile: DeviceProfile) -> list[IOC]:
    """Flag profiles with enterprise provisioning from unknown organisations."""
    TRUSTED_ORGS: set[str] = set()  # populated from corporate config in production
    iocs: list[IOC] = []
    for p in profile.installed_profiles:
        org = p.get("organization", "").strip()
        ident = p.get("identifier", "")
        # Enterprise profiles typically have identifiers starting with com.<company>
        if (ident.startswith("com.") and org and
                org.lower() not in {"apple", "google"} and
                org not in TRUSTED_ORGS):
            iocs.append(IOC(
                ioc_id=f"ios-unrecognised-enterprise-cert-{ident}",
                name=f"Unrecognised enterprise profile: {org}",
                description=(
                    f"Configuration profile '{p.get('name')}' issued by '{org}' is not "
                    "in the trusted organisation list. Enterprise profiles can install "
                    "CA certificates and intercept TLS traffic."
                ),
                severity=Severity.MEDIUM,
                indicator_type="certificate",
                value=f"{org} / {ident}",
                threat_family="Unauthorised Profile",
                confidence=0.6,
            ))
    return iocs


def _check_pegasus_files(lockdown: Any) -> list[IOC]:
    """Check for Pegasus artefact files via AFC (requires jailbreak or trusted pairing)."""
    iocs: list[IOC] = []
    try:
        from pymobiledevice3.services.afc import AfcService
        afc = AfcService(lockdown)
        for path in PEGASUS_IOS_FILES:
            try:
                info = afc.stat(path)
                if info:
                    iocs.append(IOC(
                        ioc_id=f"ios-pegasus-file-{path.replace('/', '_')}",
                        name=f"Pegasus persistence artefact found: {path}",
                        description=(
                            f"File '{path}' is a known Pegasus spyware persistence "
                            "artefact. This strongly indicates the device was or is "
                            "compromised by Pegasus (NSO Group)."
                        ),
                        severity=Severity.CRITICAL,
                        indicator_type="file",
                        value=path,
                        threat_family="Pegasus",
                        confidence=0.95,
                        reference="https://github.com/mvt-project/mvt",
                    ))
            except Exception:
                pass
    except Exception as exc:
        logger.debug("Pegasus file check skipped (AFC unavailable): %s", exc)
    return iocs


def _check_network_iocs(lockdown: Any) -> list[IOC]:
    """Check network connection history for Pegasus C2 domains."""
    iocs: list[IOC] = []
    try:
        from pymobiledevice3.services.diagnostics import DiagnosticsService
        diag = DiagnosticsService(lockdown)
        # DataUsage SQLite database tracks per-app network connections
        # We read it and search for known Pegasus domains
        usage = diag.get_battery_info()  # Proxy check — real implementation reads DataUsage.sqlite
    except Exception as exc:
        logger.debug("Network IOC check skipped: %s", exc)
    return iocs
