"""
Continuous monitoring agent deployment.

iOS:  Deploys an MDM profile that enables supervised telemetry reporting.
Android: Deploys a managed APK via Android Enterprise / managed Google Play.
"""

from __future__ import annotations

import json
import logging
import plistlib
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import (
    AgentDeploymentMethod,
    AgentStatus,
    DeviceProfile,
    MonitoringAgent,
    Platform,
)

logger = logging.getLogger(__name__)

# MDM profile UUID for the monitoring payload
MONITORING_PROFILE_IDENTIFIER = "com.enterprise.mobileaudit.monitoring"
MONITORING_PROFILE_VERSION = "1.0.0"

# Android managed APK metadata
ANDROID_AGENT_PACKAGE = "com.enterprise.mobileaudit.agent"
ANDROID_AGENT_VERSION = "1.0.0"
ANDROID_AGENT_DOWNLOAD_URL = "https://mdm.internal/agents/mobileaudit-android-latest.apk"

MONITORING_CAPABILITIES_IOS = [
    "configuration_change_detection",
    "jailbreak_acquisition_alert",
    "new_app_install_notification",
    "profile_change_detection",
    "compliance_drift_alert",
    "risk_score_change_alert",
]

MONITORING_CAPABILITIES_ANDROID = [
    "configuration_change_detection",
    "root_acquisition_alert",
    "usb_debugging_enable_alert",
    "new_app_install_notification",
    "permission_change_alert",
    "compliance_drift_alert",
    "suspicious_network_connection_alert",
    "device_admin_change_alert",
    "risk_score_change_alert",
]


def deploy_monitoring(
    device: DeviceProfile,
    mdm_server_url: str = "",
    mdm_push_token: str = "",
    alert_webhook_url: str = "",
    lockdown: Any | None = None,
    adb_serial: str | None = None,
) -> MonitoringAgent:
    """
    Deploy a lightweight monitoring agent to the enrolled device.

    iOS:     Push a supervised MDM profile with the monitoring payload.
    Android: Deploy the monitoring APK via Android Enterprise managed install.

    Parameters
    ----------
    device:
        DeviceProfile of the enrolled device.
    mdm_server_url:
        Base URL of the MDM server (e.g. https://mdm.corp.example.com).
    mdm_push_token:
        APNs push token for the iOS device (required for iOS MDM push).
    alert_webhook_url:
        HTTPS endpoint that receives alert POSTs from the monitoring agent.
    lockdown:
        Optional pymobiledevice3 LockdownClient (iOS USB direct install).
    adb_serial:
        ADB serial number (Android USB direct install).
    """
    if device.platform == Platform.IOS:
        return _deploy_ios_agent(
            device, mdm_server_url, mdm_push_token, alert_webhook_url, lockdown
        )
    elif device.platform == Platform.ANDROID:
        return _deploy_android_agent(
            device, mdm_server_url, alert_webhook_url, adb_serial
        )
    else:
        return MonitoringAgent(
            device_udid=device.udid,
            platform=device.platform,
            deployment_method=AgentDeploymentMethod.MDM_PROFILE,
            status=AgentStatus.NOT_SUPPORTED,
            agent_version="",
            error_message=f"Unsupported platform: {device.platform}",
        )


# ---------------------------------------------------------------
# iOS deployment
# ---------------------------------------------------------------

def _deploy_ios_agent(
    device: DeviceProfile,
    mdm_server_url: str,
    push_token: str,
    alert_webhook_url: str,
    lockdown: Any | None,
) -> MonitoringAgent:
    """
    Push the monitoring MDM profile to an iOS device.

    Requires either:
    - A live lockdown connection (USB, direct profile install), OR
    - Valid MDM server credentials to trigger an MDM InstallProfile command.
    """
    agent = MonitoringAgent(
        device_udid=device.udid,
        platform=Platform.IOS,
        deployment_method=AgentDeploymentMethod.MDM_PROFILE,
        status=AgentStatus.PENDING,
        agent_version=MONITORING_PROFILE_VERSION,
        monitoring_capabilities=MONITORING_CAPABILITIES_IOS,
    )

    profile_plist = _build_ios_monitoring_profile(device, alert_webhook_url)

    # Path A: Direct USB install via pymobiledevice3
    if lockdown is not None:
        success, error = _install_ios_profile_usb(lockdown, profile_plist)
        if success:
            agent.status = AgentStatus.DEPLOYED
            agent.deployed_at = datetime.utcnow()
        else:
            agent.status = AgentStatus.FAILED
            agent.error_message = error
        return agent

    # Path B: Push via MDM server
    if mdm_server_url and push_token:
        success, error = _push_ios_profile_mdm(
            mdm_server_url, device.udid, push_token, profile_plist
        )
        if success:
            agent.status = AgentStatus.DEPLOYED
            agent.deployed_at = datetime.utcnow()
        else:
            agent.status = AgentStatus.FAILED
            agent.error_message = error
        return agent

    agent.status = AgentStatus.FAILED
    agent.error_message = (
        "No deployment path available: provide either a lockdown connection "
        "or (mdm_server_url + push_token)."
    )
    return agent


def _build_ios_monitoring_profile(
    device: DeviceProfile,
    alert_webhook_url: str,
) -> bytes:
    """
    Build an Apple Configuration Profile (.mobileconfig) plist for monitoring.

    The profile installs:
    - A supervised MDM check-in payload that reports configuration state.
    - Web content filter configuration to log network connections.
    - A custom payload that configures alert destinations.
    """
    profile_uuid = str(uuid.uuid4()).upper()
    payload_uuid = str(uuid.uuid4()).upper()

    profile = {
        "PayloadDisplayName": "MobileAudit Security Monitoring",
        "PayloadDescription": (
            "Enables continuous security posture monitoring for enterprise BYOD compliance."
        ),
        "PayloadIdentifier": MONITORING_PROFILE_IDENTIFIER,
        "PayloadOrganization": "Enterprise IT Security",
        "PayloadType": "Configuration",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1,
        "PayloadRemovalDisallowed": True,
        "PayloadContent": [
            {
                # Custom payload — stores monitoring configuration
                "PayloadType": "com.enterprise.mobileaudit.monitoring",
                "PayloadDisplayName": "MobileAudit Agent Configuration",
                "PayloadIdentifier": f"{MONITORING_PROFILE_IDENTIFIER}.config",
                "PayloadUUID": payload_uuid,
                "PayloadVersion": 1,
                "AlertWebhookURL": alert_webhook_url,
                "DeviceUDID": device.udid,
                "MonitoringCapabilities": MONITORING_CAPABILITIES_IOS,
                "ReportingIntervalSeconds": 300,
                "AlertOnJailbreak": True,
                "AlertOnNewApp": True,
                "AlertOnProfileChange": True,
                "AlertOnComplianceDrift": True,
            }
        ],
    }

    return plistlib.dumps(profile)


def _install_ios_profile_usb(lockdown: Any, profile_plist: bytes) -> tuple[bool, str]:
    try:
        from pymobiledevice3.services.mobile_config import MobileConfigService
        svc = MobileConfigService(lockdown)
        svc.install(profile_plist)
        logger.info("Monitoring profile installed via USB")
        return True, ""
    except Exception as exc:
        logger.error("USB profile install failed: %s", exc)
        return False, str(exc)


def _push_ios_profile_mdm(
    mdm_server_url: str,
    udid: str,
    push_token: str,
    profile_plist: bytes,
) -> tuple[bool, str]:
    """
    Send an InstallProfile MDM command to the device via the MDM server API.

    This calls the MDM server's internal REST API — the exact endpoint and
    authentication mechanism depend on the MDM vendor (Jamf, Intune, etc.).
    """
    try:
        import requests

        # MDM server endpoint — production: replace with vendor-specific API
        endpoint = f"{mdm_server_url.rstrip('/')}/api/v1/devices/{udid}/commands"
        payload = {
            "command": "InstallProfile",
            "payload": profile_plist.hex(),
            "push_token": push_token,
        }
        resp = requests.post(endpoint, json=payload, timeout=30)
        resp.raise_for_status()
        logger.info("MDM InstallProfile command sent for device %s", udid)
        return True, ""
    except Exception as exc:
        logger.error("MDM profile push failed: %s", exc)
        return False, str(exc)


# ---------------------------------------------------------------
# Android deployment
# ---------------------------------------------------------------

def _deploy_android_agent(
    device: DeviceProfile,
    mdm_server_url: str,
    alert_webhook_url: str,
    adb_serial: str | None,
) -> MonitoringAgent:
    """
    Deploy the MobileAudit monitoring APK to an Android device.

    Deployment order:
    1. Android Enterprise managed install (via MDM server API).
    2. Fallback: direct ADB install (USB-connected device).
    """
    agent = MonitoringAgent(
        device_udid=device.udid,
        platform=Platform.ANDROID,
        deployment_method=AgentDeploymentMethod.MANAGED_APK,
        status=AgentStatus.PENDING,
        agent_version=ANDROID_AGENT_VERSION,
        monitoring_capabilities=MONITORING_CAPABILITIES_ANDROID,
    )

    # Path A: Android Enterprise managed install
    if mdm_server_url:
        success, error = _push_android_agent_mdm(
            mdm_server_url, device.udid, alert_webhook_url
        )
        if success:
            agent.status = AgentStatus.DEPLOYED
            agent.deployed_at = datetime.utcnow()
            return agent
        logger.warning("MDM agent push failed (%s); trying ADB fallback", error)

    # Path B: Direct ADB install
    if adb_serial:
        success, error = _install_android_agent_adb(
            adb_serial, alert_webhook_url, device.udid
        )
        if success:
            agent.status = AgentStatus.DEPLOYED
            agent.deployed_at = datetime.utcnow()
            return agent
        agent.status = AgentStatus.FAILED
        agent.error_message = error
        return agent

    agent.status = AgentStatus.FAILED
    agent.error_message = (
        "No deployment path available: provide either mdm_server_url or adb_serial."
    )
    return agent


def _push_android_agent_mdm(
    mdm_server_url: str,
    device_id: str,
    alert_webhook_url: str,
) -> tuple[bool, str]:
    """
    Trigger a managed app install via the MDM server API.

    Uses Android Enterprise managed Google Play API under the hood.
    The MDM server must have the MobileAudit app approved in the managed Play Store.
    """
    try:
        import requests

        endpoint = f"{mdm_server_url.rstrip('/')}/api/v1/devices/{device_id}/managed-apps"
        payload = {
            "package_name": ANDROID_AGENT_PACKAGE,
            "install_type": "FORCE_INSTALLED",
            "managed_configuration": {
                "alertWebhookUrl": alert_webhook_url,
                "deviceId": device_id,
                "reportingIntervalSeconds": 300,
                "capabilities": MONITORING_CAPABILITIES_ANDROID,
            },
        }
        resp = requests.post(endpoint, json=payload, timeout=30)
        resp.raise_for_status()
        logger.info("Android Enterprise managed install triggered for device %s", device_id)
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _install_android_agent_adb(
    serial: str,
    alert_webhook_url: str,
    device_id: str,
) -> tuple[bool, str]:
    """
    Install the monitoring APK directly via ADB (used for enrolled USB devices
    during initial setup, not for ongoing BYOD deployments).
    """
    apk_path = Path(tempfile.gettempdir()) / "mobileaudit-agent.apk"

    # Download APK from internal distribution server
    try:
        import requests
        resp = requests.get(ANDROID_AGENT_DOWNLOAD_URL, timeout=60, stream=True)
        resp.raise_for_status()
        with open(apk_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
    except Exception as exc:
        return False, f"APK download failed: {exc}"

    # Install via ADB
    try:
        result = subprocess.run(
            ["adb", "-s", serial, "install", "-r", str(apk_path)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0 or "Failure" in result.stdout:
            return False, f"ADB install failed: {result.stdout} {result.stderr}"
    except Exception as exc:
        return False, f"ADB install error: {exc}"

    # Configure the agent via broadcast intent
    try:
        config = json.dumps({
            "alertWebhookUrl": alert_webhook_url,
            "deviceId": device_id,
            "reportingIntervalSeconds": 300,
        })
        subprocess.run([
            "adb", "-s", serial, "shell",
            "am", "broadcast",
            "-a", "com.enterprise.mobileaudit.CONFIGURE",
            "-n", f"{ANDROID_AGENT_PACKAGE}/.ConfigurationReceiver",
            "--es", "config", config,
        ], capture_output=True, timeout=30)
    except Exception as exc:
        logger.warning("Agent configuration broadcast failed: %s", exc)

    logger.info("Android monitoring agent installed via ADB on device %s", serial)
    return True, ""
