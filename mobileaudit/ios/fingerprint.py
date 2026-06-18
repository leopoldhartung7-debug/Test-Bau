"""iOS device fingerprinting via pymobiledevice3 / libimobiledevice."""

from __future__ import annotations

import logging
import subprocess
from typing import TYPE_CHECKING, Any

from ..models import (
    ConnectionType,
    DeviceProfile,
    InstalledApp,
    NetworkInterface,
    Platform,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Artifacts that indicate a jailbroken device
_JAILBREAK_PATHS = [
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/private/var/lib/apt",
    "/private/var/mobile/Library/SBSettings",
    "/usr/libexec/cydia",
    "/var/checkra1n",
    "/private/var/checkra1n",
    "/cores/binpack",             # Unc0ver artefact
    "/private/preboot/procursus", # Palera1n artefact
]

# Checkra1n/checkm8 model prefixes (A11 chip and earlier)
_CHECKM8_VULNERABLE_MODELS = {
    "iPhone8,",  # iPhone 6s/6s+
    "iPhone9,",  # iPhone 7/7+
    "iPhone10,", # iPhone 8/8+/X
    "iPad4,",    # iPad Air
    "iPad5,",    # iPad Air 2 / iPad mini 3
    "iPad6,",
    "iPad7,",
}


def _try_import_pymobiledevice3() -> bool:
    try:
        import pymobiledevice3  # noqa: F401
        return True
    except ImportError:
        return False


def fingerprint_ios_usb(udid: str | None = None) -> DeviceProfile:
    """
    Fingerprint an iOS device connected via USB using pymobiledevice3.

    Raises RuntimeError if no device is found or pymobiledevice3 is unavailable.
    """
    if not _try_import_pymobiledevice3():
        raise RuntimeError(
            "pymobiledevice3 is required for iOS USB fingerprinting. "
            "Install it with: pip install pymobiledevice3"
        )

    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.installation_proxy import InstallationProxyService
    from pymobiledevice3.services.mobile_config import MobileConfigService

    lockdown = create_using_usbmux(serial=udid)
    props = lockdown.all_values

    profile = DeviceProfile(
        platform=Platform.IOS,
        udid=props.get("UniqueDeviceID", ""),
        serial_number=props.get("SerialNumber", ""),
        model=props.get("ProductType", ""),
        os_version=props.get("ProductVersion", ""),
        build_number=props.get("BuildVersion", ""),
        connection_type=ConnectionType.USB,
        manufacturer="Apple",
        encryption_enabled=bool(props.get("DataVolumeEncrypted", False)),
        raw_properties={k: str(v) for k, v in props.items()},
    )

    profile.is_jailbroken, profile.root_method = _detect_jailbreak_usb(lockdown, profile.model)
    profile.installed_apps = _list_installed_apps(lockdown)
    profile.installed_profiles = _list_profiles(lockdown)

    return profile


def fingerprint_ios_mdm(device_info: dict[str, Any]) -> DeviceProfile:
    """
    Build a DeviceProfile from MDM inventory data (e.g. from an MDM server push).

    ``device_info`` is the dict returned by a DeviceInformation MDM command.
    """
    profile = DeviceProfile(
        platform=Platform.IOS,
        udid=device_info.get("UDID", ""),
        serial_number=device_info.get("SerialNumber", ""),
        model=device_info.get("Model", device_info.get("ModelName", "")),
        os_version=device_info.get("OSVersion", ""),
        build_number=device_info.get("BuildVersion", ""),
        connection_type=ConnectionType.MDM,
        manufacturer="Apple",
        encryption_enabled=device_info.get("IsActivationLockEnabled") is not None,
        raw_properties=device_info,
    )

    # MDM QueryResponses include IsSupervised, IsCloudBackupEnabled, etc.
    profile.is_jailbroken = bool(device_info.get("IsJailbroken", False))
    if profile.is_jailbroken:
        profile.root_method = device_info.get("JailbreakMethod", "unknown")

    # Parse installed apps if provided via InstalledApplicationList MDM command
    for app in device_info.get("InstalledApplicationList", []):
        profile.installed_apps.append(InstalledApp(
            bundle_id=app.get("Identifier", ""),
            name=app.get("Name", ""),
            version=app.get("Version", ""),
            is_system=app.get("IsValidated", False),
        ))

    # Parse configuration profiles
    for p in device_info.get("ProfileList", []):
        profile.installed_profiles.append({
            "name": p.get("PayloadDisplayName", ""),
            "identifier": p.get("PayloadIdentifier", ""),
            "organization": p.get("PayloadOrganization", ""),
            "removal_allowed": str(p.get("PayloadRemovalDisallowed", True)),
        })

    return profile


def _detect_jailbreak_usb(lockdown: Any, model: str) -> tuple[bool, str]:
    """
    Detect jailbreak by checking known artefact paths via AFC2 or diagnostics relay.
    Returns (is_jailbroken, method_name).
    """
    try:
        from pymobiledevice3.services.afc import AfcService

        afc = AfcService(lockdown)
        for path in _JAILBREAK_PATHS:
            try:
                afc.stat(path)
                method = _infer_jailbreak_method(path, model)
                logger.info("Jailbreak artefact found at %s → method=%s", path, method)
                return True, method
            except Exception:
                pass
    except Exception as exc:
        logger.debug("AFC jailbreak check skipped: %s", exc)

    # Fallback: check via diagnostics relay (requires supervision or pairing trust)
    try:
        from pymobiledevice3.services.diagnostics import DiagnosticsService

        diag = DiagnosticsService(lockdown)
        io_registry = diag.ioregistry_entry_by_name("IOPlatformExpertDevice")
        boot_args: str = io_registry.get("boot-args", "")
        if any(arg in boot_args for arg in ("amfi_get_out_of_my_way", "cs_enforcement_disable")):
            return True, "kernel_patch"
    except Exception as exc:
        logger.debug("Diagnostics jailbreak check skipped: %s", exc)

    return False, ""


def _infer_jailbreak_method(path: str, model: str) -> str:
    if "cydia" in path.lower() or "Cydia" in path:
        return "Cydia/substrate"
    if "checkra1n" in path.lower():
        return "checkra1n (checkm8)"
    if "palera1n" in path.lower() or "procursus" in path.lower():
        return "palera1n"
    if "sileo" in path.lower():
        return "rootless (Sileo)"
    if "unc0ver" in path.lower() or "binpack" in path.lower():
        return "unc0ver"

    # Heuristic: if the device model has a checkm8-vulnerable SoC, checkra1n is likely
    if any(model.startswith(prefix) for prefix in _CHECKM8_VULNERABLE_MODELS):
        return "likely checkra1n (checkm8-vulnerable chip)"

    return "unknown"


def _list_installed_apps(lockdown: Any) -> list[InstalledApp]:
    try:
        from pymobiledevice3.services.installation_proxy import InstallationProxyService

        apps: list[InstalledApp] = []
        with InstallationProxyService(lockdown) as svc:
            for bundle_id, info in svc.get_apps(app_types=["User", "System"]).items():
                apps.append(InstalledApp(
                    bundle_id=bundle_id,
                    name=info.get("CFBundleName", info.get("CFBundleDisplayName", "")),
                    version=info.get("CFBundleVersion", ""),
                    entitlements=info.get("Entitlements", {}),
                    is_system=info.get("ApplicationType", "") == "System",
                ))
        return apps
    except Exception as exc:
        logger.warning("Could not list installed apps: %s", exc)
        return []


def _list_profiles(lockdown: Any) -> list[dict[str, str]]:
    try:
        from pymobiledevice3.services.mobile_config import MobileConfigService

        svc = MobileConfigService(lockdown)
        raw = svc.get_profile_list()
        profiles = []
        for p in raw.get("ProfileList", []):
            profiles.append({
                "name": str(p.get("PayloadDisplayName", "")),
                "identifier": str(p.get("PayloadIdentifier", "")),
                "organization": str(p.get("PayloadOrganization", "")),
                "removal_disallowed": str(p.get("PayloadRemovalDisallowed", "")),
            })
        return profiles
    except Exception as exc:
        logger.warning("Could not list installed profiles: %s", exc)
        return []
