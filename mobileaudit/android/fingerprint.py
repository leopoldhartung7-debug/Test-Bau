"""Android device fingerprinting via ADB."""

from __future__ import annotations

import logging
import re
import subprocess
from typing import Any

from ..models import (
    ConnectionType,
    DeviceProfile,
    InstalledApp,
    NetworkInterface,
    Platform,
)

logger = logging.getLogger(__name__)

# ADB properties we read for fingerprinting
_PROPS = [
    "ro.product.model",
    "ro.product.manufacturer",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.id",
    "ro.build.version.security_patch",
    "ro.boot.verifiedbootstate",      # "green" = locked, "orange" = unlocked
    "ro.boot.flash.locked",           # "1" = locked
    "ro.crypto.state",                # "encrypted" | "unencrypted"
    "ro.crypto.type",                 # "file" (FBE) | "block"
    "ro.serialno",
]

# Paths / binaries that indicate a rooted device
_ROOT_INDICATORS = [
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/system/xbin/su",
    "/system/bin/su",
    "/sbin/su",
    "/data/local/xbin/su",
    "/data/local/bin/su",
    "/data/local/su",
    "/system/sd/xbin/su",
]

_MAGISK_INDICATORS = [
    "/sbin/.magisk",
    "/data/adb/magisk",
    "/data/adb/modules",
    "/cache/.magisk",
]


def _adb(args: list[str], serial: str | None = None, timeout: int = 30) -> str:
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return result.stdout.strip()
    except FileNotFoundError:
        raise RuntimeError("adb not found. Install Android SDK Platform Tools.")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"ADB command timed out: {' '.join(args)}")


def list_connected_devices() -> list[str]:
    """Return serial numbers of USB-connected ADB devices."""
    output = _adb(["devices"])
    serials = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2 and parts[1] == "device":
            serials.append(parts[0])
    return serials


def fingerprint_android(serial: str | None = None) -> DeviceProfile:
    """
    Fingerprint an Android device via ADB.

    If *serial* is None, uses the single connected device (errors if multiple).
    """
    if not serial:
        devices = list_connected_devices()
        if not devices:
            raise RuntimeError("No ADB devices found. Ensure USB debugging is enabled.")
        if len(devices) > 1:
            raise RuntimeError(
                f"Multiple ADB devices found: {devices}. Specify a serial number."
            )
        serial = devices[0]

    props = _get_all_props(serial)

    udid = serial
    model = props.get("ro.product.model", "")
    manufacturer = props.get("ro.product.manufacturer", "")
    os_version = props.get("ro.build.version.release", "")
    build_number = props.get("ro.build.id", "")
    security_patch = props.get("ro.build.version.security_patch", "")
    serial_number = props.get("ro.serialno", serial)

    # Bootloader lock: verifiedbootstate == "green" → locked
    vbs = props.get("ro.boot.verifiedbootstate", "").lower()
    flash_locked = props.get("ro.boot.flash.locked", "")
    bootloader_locked: bool | None = None
    if vbs == "green" or flash_locked == "1":
        bootloader_locked = True
    elif vbs in ("orange", "red", "yellow") or flash_locked == "0":
        bootloader_locked = False

    crypto_state = props.get("ro.crypto.state", "")
    encryption_enabled = crypto_state == "encrypted"

    profile = DeviceProfile(
        platform=Platform.ANDROID,
        udid=udid,
        serial_number=serial_number,
        model=model,
        os_version=os_version,
        build_number=build_number,
        connection_type=ConnectionType.USB,
        manufacturer=manufacturer,
        security_patch_level=security_patch,
        bootloader_locked=bootloader_locked,
        encryption_enabled=encryption_enabled,
        raw_properties=props,
    )

    profile.is_rooted, profile.root_method = _detect_root(serial)
    profile.installed_apps = _list_packages(serial)
    profile.network_interfaces = _get_network_interfaces(serial)

    return profile


def _get_all_props(serial: str) -> dict[str, str]:
    """Read all system properties from the device."""
    raw = _adb(["shell", "getprop"], serial=serial)
    props: dict[str, str] = {}
    pattern = re.compile(r"\[(.+?)\]:\s*\[(.*)?\]")
    for line in raw.splitlines():
        m = pattern.match(line.strip())
        if m:
            props[m.group(1)] = m.group(2)
    return props


def _detect_root(serial: str) -> tuple[bool, str]:
    """Check for su binary, Magisk, and root via 'id' command."""
    # Check well-known root paths
    for path in _ROOT_INDICATORS:
        out = _adb(["shell", f"ls {path} 2>/dev/null"], serial=serial)
        if path in out:
            return True, "su_binary"

    # Check Magisk artefacts
    for path in _MAGISK_INDICATORS:
        out = _adb(["shell", f"ls {path} 2>/dev/null"], serial=serial)
        if path in out or out.strip():
            return True, "Magisk"

    # Try running su directly (won't work on properly hardened shells, but worth trying)
    out = _adb(["shell", "su -c id 2>/dev/null"], serial=serial)
    if "uid=0" in out:
        return True, "su_binary"

    # Check for Magisk via package name
    packages = _adb(["shell", "pm list packages"], serial=serial)
    if "io.github.huskydg.magisk" in packages or "com.topjohnwu.magisk" in packages:
        return True, "Magisk"

    return False, ""


def _list_packages(serial: str) -> list[InstalledApp]:
    """List all installed packages with basic metadata."""
    output = _adb(["shell", "pm list packages -f"], serial=serial)
    apps: list[InstalledApp] = []
    for line in output.splitlines():
        # format: package:/data/app/com.example-xxx/base.apk=com.example
        m = re.match(r"package:(.+?)=(\S+)", line.strip())
        if not m:
            continue
        apk_path, bundle_id = m.group(1), m.group(2)
        is_system = apk_path.startswith("/system/") or apk_path.startswith("/product/")

        permissions = _get_app_permissions(serial, bundle_id)
        apps.append(InstalledApp(
            bundle_id=bundle_id,
            name=bundle_id.rsplit(".", 1)[-1],  # approximate name from bundle ID
            version=_get_app_version(serial, bundle_id),
            permissions=permissions,
            is_system=is_system,
        ))
    return apps


def _get_app_version(serial: str, package: str) -> str:
    out = _adb(["shell", f"dumpsys package {package} | grep versionName"], serial=serial)
    m = re.search(r"versionName=(\S+)", out)
    return m.group(1) if m else ""


def _get_app_permissions(serial: str, package: str) -> list[str]:
    out = _adb(
        ["shell", f"dumpsys package {package} | grep 'granted=true'"], serial=serial
    )
    perms = []
    for line in out.splitlines():
        m = re.search(r"(android\.permission\.\S+):", line.strip())
        if m:
            perms.append(m.group(1))
    return perms


def _get_network_interfaces(serial: str) -> list[NetworkInterface]:
    out = _adb(["shell", "ip addr show"], serial=serial)
    interfaces: list[NetworkInterface] = []
    current_name = ""
    for line in out.splitlines():
        iface_match = re.match(r"\d+:\s+(\S+):", line)
        if iface_match:
            current_name = iface_match.group(1).rstrip("@").split("@")[0]
        ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/\d+", line)
        if ip_match and current_name and current_name != "lo":
            interfaces.append(NetworkInterface(
                name=current_name,
                ip_address=ip_match.group(1),
                mac_address="",
            ))
    return interfaces


def check_usb_debugging(serial: str) -> bool:
    """Return True if USB debugging is enabled (adb_enabled = 1)."""
    out = _adb(["shell", "settings get global adb_enabled"], serial=serial)
    return out.strip() == "1"


def check_unknown_sources(serial: str) -> bool:
    """Return True if sideloading from unknown sources is allowed."""
    # Android 8+: secure setting per-package; older: global install_non_market_apps
    out = _adb(
        ["shell", "settings get secure install_non_market_apps"], serial=serial
    )
    if out.strip() == "1":
        return True
    # Android 8+: check package verifier setting as proxy
    out2 = _adb(
        ["shell", "settings get global package_verifier_enable"], serial=serial
    )
    return out2.strip() == "0"


def check_developer_options(serial: str) -> bool:
    """Return True if developer options are enabled."""
    out = _adb(
        ["shell", "settings get global development_settings_enabled"], serial=serial
    )
    return out.strip() == "1"


def check_play_protect(serial: str) -> bool:
    """Return True if Google Play Protect is enabled."""
    out = _adb(["shell", "settings get global package_verifier_enable"], serial=serial)
    return out.strip() == "1"


def check_screen_lock(serial: str) -> tuple[bool, str]:
    """Return (enabled, lock_type) where lock_type is 'pin'|'password'|'pattern'|'none'."""
    out = _adb(["shell", "dumpsys deviceidle | grep mScreenLocked"], serial=serial)
    # Fall back to locksettings
    ls_out = _adb(["shell", "locksettings get-disabled 2>/dev/null"], serial=serial)
    if "true" in ls_out.lower():
        return False, "none"

    # Check password quality via dpm
    dpm_out = _adb(
        ["shell", "dumpsys device_policy | grep passwordQuality"], serial=serial
    )
    if "PASSWORD_QUALITY_SOMETHING" in dpm_out or "PASSWORD_QUALITY_NUMERIC" in dpm_out:
        return True, "pin"
    if "PASSWORD_QUALITY_ALPHABETIC" in dpm_out or "PASSWORD_QUALITY_ALPHANUMERIC" in dpm_out:
        return True, "password"
    if "PASSWORD_QUALITY_UNSPECIFIED" in dpm_out:
        return False, "none"

    return True, "unknown"
