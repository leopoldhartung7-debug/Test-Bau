"""
MobileReconScanner — central entry point for MobileAudit device assessment.

Orchestrates fingerprinting, vulnerability assessment, configuration auditing,
IOC detection, and monitoring agent deployment for iOS and Android devices.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .models import (
    AgentStatus,
    ComplianceReport,
    ConnectionType,
    DeviceProfile,
    IOC,
    MonitoringAgent,
    Platform,
    Severity,
    Vulnerability,
)

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Aggregated result of a full device security assessment."""

    profile: DeviceProfile
    vulnerabilities: list[Vulnerability]
    compliance_report: ComplianceReport
    iocs: list[IOC]
    risk_score: float = 0.0        # 0 (clean) – 100 (critical risk)
    risk_level: Severity = Severity.INFO
    scan_duration_seconds: float = 0.0

    @property
    def critical_vuln_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def exploitable_vuln_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.exploit_available)

    @property
    def high_confidence_ioc_count(self) -> int:
        return sum(1 for i in self.iocs if i.confidence >= 0.8)

    def summary(self) -> str:
        lines = [
            f"Device:         {self.profile.model} ({self.profile.platform.value.upper()}) "
            f"{self.profile.os_version}",
            f"UDID:           {self.profile.udid}",
            f"Jailbroken/Root: {'YES — ' + self.profile.root_method if (self.profile.is_jailbroken or self.profile.is_rooted) else 'No'}",
            f"Risk Score:     {self.risk_score:.1f}/100 ({self.risk_level.value.upper()})",
            f"Vulnerabilities: {len(self.vulnerabilities)} total, "
            f"{self.critical_vuln_count} critical, "
            f"{self.exploitable_vuln_count} with public exploit",
            f"Compliance:     {self.compliance_report.overall_score:.1f}% "
            f"({len(self.compliance_report.failed())} controls failed)",
            f"IOCs detected:  {len(self.iocs)} "
            f"({self.high_confidence_ioc_count} high-confidence)",
        ]
        return "\n".join(lines)


class DeviceConnection:
    """
    Thin wrapper that carries a physical/logical connection to a device.

    Attributes
    ----------
    platform:
        Platform.IOS or Platform.ANDROID.
    connection_type:
        USB | MDM | WIFI.
    serial:
        ADB serial (Android) or UDID (iOS/USB).
    mdm_device_info:
        Raw MDM inventory dict (iOS MDM or Android EMM query response).
    lockdown:
        pymobiledevice3 LockdownClient instance (iOS USB only).
    adb_serial:
        ADB device serial override (Android USB only).
    """

    def __init__(
        self,
        platform: Platform,
        connection_type: ConnectionType = ConnectionType.USB,
        serial: str | None = None,
        mdm_device_info: dict[str, Any] | None = None,
        lockdown: Any | None = None,
        adb_serial: str | None = None,
    ):
        self.platform = platform
        self.connection_type = connection_type
        self.serial = serial
        self.mdm_device_info = mdm_device_info or {}
        self.lockdown = lockdown
        self.adb_serial = adb_serial


class MobileReconScanner:
    """
    Enterprise mobile device security assessment tool.

    Performs:
    - Device fingerprinting (iOS via pymobiledevice3, Android via ADB)
    - Vulnerability assessment against NVD CVE database + built-in signatures
    - Configuration security audit (CIS / NIST baselines)
    - Compromise indicator detection (Pegasus, Cerberus, FlexiSpy, etc.)
    - Continuous monitoring agent deployment
    """

    def __init__(
        self,
        nvd_api_key: str | None = None,
        mdm_server_url: str = "",
        alert_webhook_url: str = "",
        fetch_nvd: bool = True,
    ):
        """
        Parameters
        ----------
        nvd_api_key:
            Optional NVD API key for higher rate limits (50 req/s vs 5 req/s).
        mdm_server_url:
            Base URL of the corporate MDM server for profile push and managed
            app deployment.
        alert_webhook_url:
            HTTPS endpoint that monitoring agents use to POST security alerts.
        fetch_nvd:
            If False, skip live NVD queries and use only built-in signatures.
            Useful for offline environments or testing.
        """
        self.mdm_server_url = mdm_server_url
        self.alert_webhook_url = alert_webhook_url
        self.fetch_nvd = fetch_nvd

        if fetch_nvd:
            from .vuln.cve import NVDClient
            self._nvd = NVDClient(api_key=nvd_api_key)
        else:
            self._nvd = None

    # ---------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------

    def fingerprint_device(self, connection: DeviceConnection) -> DeviceProfile:
        """
        Identify the target device completely.

        iOS:     Query via pymobiledevice3 (USB) or parse MDM inventory response.
        Android: Query via ADB shell getprop + pm list packages + ADB fingerprint.

        Returns
        -------
        DeviceProfile
            Complete device profile including OS version, model, serial number,
            jailbreak/root status, installed apps, and MDM profiles.
        """
        logger.info(
            "Fingerprinting %s device (%s)",
            connection.platform.value, connection.connection_type.value,
        )

        if connection.platform == Platform.IOS:
            return self._fingerprint_ios(connection)
        elif connection.platform == Platform.ANDROID:
            return self._fingerprint_android(connection)
        else:
            raise ValueError(f"Unsupported platform: {connection.platform}")

    def assess_vulnerabilities(self, profile: DeviceProfile) -> list[Vulnerability]:
        """
        Check device against known vulnerabilities.

        Queries:
        - NIST NVD API v2 for CVEs matching the device OS version CPE.
        - Built-in high-value vulnerability signatures (checkm8, BLASTPASS,
          Operation Triangulation, Exynos baseband RCE, etc.).

        Each returned Vulnerability includes CVSS score, severity, exploit
        availability flag, and relevant reference URLs.

        Returns
        -------
        list[Vulnerability]
            Sorted by CVSS score descending (highest severity first).
        """
        logger.info(
            "Assessing vulnerabilities for %s %s",
            profile.platform.value, profile.os_version,
        )

        from .vuln.cve import get_builtin_vulnerabilities, parse_nvd_item

        vulns: list[Vulnerability] = []

        # 1. Built-in curated signatures (always available, even offline)
        vulns.extend(get_builtin_vulnerabilities(
            platform=profile.platform,
            os_version=profile.os_version,
            model=profile.model,
            manufacturer=profile.manufacturer,
        ))
        logger.info("Built-in signatures: %d vulnerabilities", len(vulns))

        # 2. Live NVD query
        if self._nvd is not None:
            try:
                nvd_items = self._nvd.search_by_cpe(
                    platform=profile.platform,
                    os_version=profile.os_version,
                )
                existing_ids = {v.cve_id for v in vulns}
                for item in nvd_items:
                    parsed = parse_nvd_item(item, profile.platform, profile.os_version)
                    if parsed.cve_id not in existing_ids:
                        vulns.append(parsed)
                        existing_ids.add(parsed.cve_id)
                logger.info("NVD query added %d additional vulnerabilities", len(nvd_items))
            except Exception as exc:
                logger.warning("NVD query failed (continuing with built-in only): %s", exc)

        # Sort: exploitable first, then by CVSS score
        vulns.sort(key=lambda v: (not v.exploit_available, -v.cvss_score))
        return vulns

    def audit_configuration(self, profile: DeviceProfile) -> ComplianceReport:
        """
        Audit security configurations against CIS Benchmarks and NIST SP 800-124.

        iOS checks:
            passcode enabled, Touch ID/Face ID, Find My, encrypted backup,
            automatic updates, VPN profiles, unauthorised profiles, private
            API entitlements in user apps, MDM enrollment.

        Android checks:
            screen lock type, device encryption, bootloader lock, root status,
            security patch recency, Google Play Protect, unknown sources,
            USB debugging, developer options, accessibility abuse, device admins.

        Returns
        -------
        ComplianceReport
            Contains individual control results, overall compliance score (0–100),
            and overall risk level. Frameworks: CIS and NIST.
        """
        logger.info("Auditing configuration for %s", profile.udid)

        if profile.platform == Platform.IOS:
            from .audit.ios_audit import audit_ios_configuration
            return audit_ios_configuration(profile)
        elif profile.platform == Platform.ANDROID:
            from .audit.android_audit import audit_android_configuration
            serial = profile.udid if profile.connection_type == ConnectionType.USB else None
            return audit_android_configuration(profile, serial=serial)
        else:
            raise ValueError(f"Unsupported platform: {profile.platform}")

    def detect_compromise_indicators(self, profile: DeviceProfile) -> list[IOC]:
        """
        Scan for signs of existing device compromise.

        iOS scans for:
            - Pegasus spyware artefacts (files, processes, network IOCs)
            - TLS interception / MITM configuration profiles
            - Apps with private API entitlements (enterprise-signed implants)
            - Known stalkerware bundle IDs

        Android scans for:
            - Pegasus, Cerberus, FlexiSpy package signatures
            - Apps with accessibility service abuse (common banking trojan tactic)
            - Rogue device admin apps (persistence mechanism)
            - User-installed MITM CA certificates
            - Active connections to known C2 IP ranges
            - Non-system apps mimicking Android system package names

        Returns
        -------
        list[IOC]
            Sorted by confidence descending, then severity.
        """
        logger.info("Detecting compromise indicators for %s", profile.udid)

        if profile.platform == Platform.IOS:
            from .ios.compromise import detect_ios_iocs
            iocs = detect_ios_iocs(profile)
        elif profile.platform == Platform.ANDROID:
            from .android.compromise import detect_android_iocs
            serial = profile.udid if profile.connection_type == ConnectionType.USB else None
            iocs = detect_android_iocs(profile, serial=serial)
        else:
            raise ValueError(f"Unsupported platform: {profile.platform}")

        iocs.sort(key=lambda i: (-i.confidence, list(Severity).index(i.severity)))
        return iocs

    def deploy_monitoring(self, device: DeviceProfile) -> MonitoringAgent:
        """
        Deploy a lightweight continuous monitoring agent to an enrolled device.

        iOS:     Pushes an MDM supervisory profile that reports configuration
                 changes, new app installs, and compliance drift.
        Android: Deploys a managed APK via Android Enterprise managed Google
                 Play that monitors root acquisition, USB debug enable, new
                 app installs, suspicious network connections, and device
                 admin changes.

        Both agents POST alerts to the configured ``alert_webhook_url`` and
        report periodic compliance snapshots to the MDM server.

        Returns
        -------
        MonitoringAgent
            Deployment status, method, and list of active monitoring capabilities.

        Raises
        ------
        ValueError
            If neither ``mdm_server_url`` nor a direct connection is available.
        """
        logger.info("Deploying monitoring agent to %s (%s)", device.udid, device.platform.value)

        from .monitor.agent import deploy_monitoring as _deploy

        agent = _deploy(
            device=device,
            mdm_server_url=self.mdm_server_url,
            alert_webhook_url=self.alert_webhook_url,
        )

        if agent.status == AgentStatus.DEPLOYED:
            logger.info("Monitoring agent deployed successfully to %s", device.udid)
        else:
            logger.warning(
                "Monitoring agent deployment failed for %s: %s",
                device.udid, agent.error_message,
            )
        return agent

    def full_scan(
        self,
        connection: DeviceConnection,
        deploy_agent: bool = False,
    ) -> ScanResult:
        """
        Run a complete security assessment: fingerprint → vuln assess →
        config audit → IOC detection, with optional monitoring agent deployment.

        Parameters
        ----------
        connection:
            DeviceConnection describing how to reach the device.
        deploy_agent:
            If True, attempt to deploy the monitoring agent after the scan.

        Returns
        -------
        ScanResult
            Aggregated assessment including risk score and summary.
        """
        import time
        start = time.monotonic()

        profile = self.fingerprint_device(connection)
        vulns = self.assess_vulnerabilities(profile)
        report = self.audit_configuration(profile)
        iocs = self.detect_compromise_indicators(profile)

        risk_score, risk_level = _compute_risk_score(profile, vulns, report, iocs)

        duration = time.monotonic() - start

        result = ScanResult(
            profile=profile,
            vulnerabilities=vulns,
            compliance_report=report,
            iocs=iocs,
            risk_score=risk_score,
            risk_level=risk_level,
            scan_duration_seconds=round(duration, 2),
        )

        if deploy_agent:
            self.deploy_monitoring(profile)

        return result

    # ---------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------

    def _fingerprint_ios(self, conn: DeviceConnection) -> DeviceProfile:
        if conn.connection_type == ConnectionType.USB:
            if conn.lockdown is not None:
                from .ios.fingerprint import fingerprint_ios_usb
                # Use the existing lockdown session if provided
                from .ios.fingerprint import (
                    _detect_jailbreak_usb,
                    _list_installed_apps,
                    _list_profiles,
                )
                props = conn.lockdown.all_values
                from .models import DeviceProfile as DP
                profile = DP(
                    platform=Platform.IOS,
                    udid=props.get("UniqueDeviceID", conn.serial or ""),
                    serial_number=props.get("SerialNumber", ""),
                    model=props.get("ProductType", ""),
                    os_version=props.get("ProductVersion", ""),
                    build_number=props.get("BuildVersion", ""),
                    connection_type=ConnectionType.USB,
                    manufacturer="Apple",
                    encryption_enabled=bool(props.get("DataVolumeEncrypted", False)),
                    raw_properties={k: str(v) for k, v in props.items()},
                )
                profile.is_jailbroken, profile.root_method = _detect_jailbreak_usb(
                    conn.lockdown, profile.model
                )
                profile.installed_apps = _list_installed_apps(conn.lockdown)
                profile.installed_profiles = _list_profiles(conn.lockdown)
                return profile
            else:
                from .ios.fingerprint import fingerprint_ios_usb
                return fingerprint_ios_usb(udid=conn.serial)

        elif conn.connection_type == ConnectionType.MDM:
            if not conn.mdm_device_info:
                raise ValueError("mdm_device_info must be provided for MDM connections")
            from .ios.fingerprint import fingerprint_ios_mdm
            return fingerprint_ios_mdm(conn.mdm_device_info)

        else:
            raise ValueError(f"Unsupported iOS connection type: {conn.connection_type}")

    def _fingerprint_android(self, conn: DeviceConnection) -> DeviceProfile:
        if conn.connection_type == ConnectionType.USB:
            from .android.fingerprint import fingerprint_android
            return fingerprint_android(serial=conn.adb_serial or conn.serial)
        elif conn.connection_type == ConnectionType.MDM:
            return _android_profile_from_mdm(conn.mdm_device_info)
        else:
            raise ValueError(f"Unsupported Android connection type: {conn.connection_type}")


def _android_profile_from_mdm(info: dict[str, Any]) -> DeviceProfile:
    """Build an Android DeviceProfile from an Android Enterprise EMM inventory dict."""
    from .android.fingerprint import _CHECKM8_VULNERABLE_MODELS  # reuse for SoC check
    from .models import DeviceProfile as DP, InstalledApp

    profile = DP(
        platform=Platform.ANDROID,
        udid=info.get("deviceId", info.get("serialNumber", "")),
        serial_number=info.get("serialNumber", ""),
        model=info.get("hardwareInfo", {}).get("model", info.get("model", "")),
        os_version=info.get("softwareInfo", {}).get("androidVersion",
                   info.get("osVersion", "")),
        build_number=info.get("softwareInfo", {}).get("androidBuildNumber",
                     info.get("buildNumber", "")),
        connection_type=ConnectionType.MDM,
        manufacturer=info.get("hardwareInfo", {}).get("manufacturer",
                     info.get("manufacturer", "")),
        security_patch_level=info.get("softwareInfo", {}).get(
            "deviceKernelVersion",
            info.get("securityPatchLevel", "")
        ),
        bootloader_locked=not info.get("bootloaderUnlocked", False),
        encryption_enabled=info.get("encryptionStatus") in (
            "ENCRYPTION_STATE_ACTIVE_PER_USER",
            "ENCRYPTION_STATE_ACTIVE",
            "encrypted",
            True,
        ),
        raw_properties=info,
    )

    # Root indicators from MDM compliance reports
    profile.is_rooted = info.get("isRooted", False) or info.get("rootDetected", False)
    if profile.is_rooted:
        profile.root_method = info.get("rootMethod", "unknown")

    # Installed applications from Android Enterprise AppReport
    for app in info.get("applications", []):
        profile.installed_apps.append(InstalledApp(
            bundle_id=app.get("packageName", ""),
            name=app.get("displayName", ""),
            version=app.get("versionName", ""),
            permissions=app.get("permissions", []),
        ))

    return profile


def _compute_risk_score(
    profile: DeviceProfile,
    vulns: list[Vulnerability],
    report: ComplianceReport,
    iocs: list[IOC],
) -> tuple[float, Severity]:
    """
    Compute an overall device risk score (0–100) from all assessment dimensions.

    Weighting:
    - Jailbreak/root:         +30
    - Critical exploitable CVE: +25 each (cap 50)
    - High CVE (no exploit):    +10 each (cap 20)
    - Critical compliance fail: +15 each (cap 30)
    - High-confidence IOC:      +20 each (cap 40)
    """
    score = 0.0

    # Jailbreak / root is a significant signal
    if profile.is_jailbroken or profile.is_rooted:
        score += 30

    # Vulnerabilities
    crit_exploit = [v for v in vulns if v.severity == Severity.CRITICAL and v.exploit_available]
    score += min(len(crit_exploit) * 25, 50)

    high_no_exploit = [
        v for v in vulns
        if v.severity == Severity.HIGH and not v.exploit_available
    ]
    score += min(len(high_no_exploit) * 10, 20)

    # Compliance failures
    crit_fails = [c for c in report.failed() if c.severity == Severity.CRITICAL]
    score += min(len(crit_fails) * 15, 30)

    # IOCs
    high_conf_iocs = [i for i in iocs if i.confidence >= 0.8]
    score += min(len(high_conf_iocs) * 20, 40)

    score = min(score, 100.0)

    if score >= 75:
        level = Severity.CRITICAL
    elif score >= 50:
        level = Severity.HIGH
    elif score >= 25:
        level = Severity.MEDIUM
    elif score > 0:
        level = Severity.LOW
    else:
        level = Severity.INFO

    return round(score, 1), level
