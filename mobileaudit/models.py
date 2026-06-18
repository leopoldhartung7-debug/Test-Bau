"""Data models for MobileAudit security assessment results."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


class Platform(str, enum.Enum):
    IOS = "ios"
    ANDROID = "android"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConnectionType(str, enum.Enum):
    USB = "usb"
    MDM = "mdm"
    WIFI = "wifi"


class ComplianceStatus(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    UNKNOWN = "unknown"


@dataclass
class InstalledApp:
    bundle_id: str
    name: str
    version: str
    permissions: list[str] = field(default_factory=list)
    entitlements: dict[str, Any] = field(default_factory=dict)
    is_system: bool = False


@dataclass
class NetworkInterface:
    name: str
    ip_address: str
    mac_address: str


@dataclass
class DeviceProfile:
    platform: Platform
    udid: str
    serial_number: str
    model: str
    os_version: str
    build_number: str
    connection_type: ConnectionType

    # Populated by platform-specific fingerprinting
    manufacturer: str = ""
    security_patch_level: str = ""        # Android-specific
    bootloader_locked: bool | None = None # Android-specific
    is_rooted: bool = False
    is_jailbroken: bool = False
    root_method: str = ""                 # e.g. "Magisk", "checkra1n"
    encryption_enabled: bool | None = None
    installed_apps: list[InstalledApp] = field(default_factory=list)
    installed_profiles: list[dict[str, str]] = field(default_factory=list)  # iOS MDM/cert profiles
    network_interfaces: list[NetworkInterface] = field(default_factory=list)
    raw_properties: dict[str, Any] = field(default_factory=dict)
    scanned_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Vulnerability:
    cve_id: str
    title: str
    description: str
    severity: Severity
    cvss_score: float
    affected_versions: list[str]
    platform: Platform
    exploit_available: bool = False
    exploit_type: str = ""   # e.g. "jailbreak", "remote_code_execution", "privilege_escalation"
    patch_version: str = ""
    reference_urls: list[str] = field(default_factory=list)


@dataclass
class ComplianceControl:
    control_id: str          # e.g. "CIS-iOS-1.1"
    framework: str           # "CIS" | "NIST"
    title: str
    description: str
    status: ComplianceStatus
    current_value: Any = None
    expected_value: Any = None
    remediation: str = ""
    severity: Severity = Severity.MEDIUM


@dataclass
class ComplianceReport:
    device_udid: str
    platform: Platform
    generated_at: datetime
    controls: list[ComplianceControl]
    overall_score: float = 0.0   # 0–100
    risk_level: Severity = Severity.INFO

    def passed(self) -> list[ComplianceControl]:
        return [c for c in self.controls if c.status == ComplianceStatus.PASS]

    def failed(self) -> list[ComplianceControl]:
        return [c for c in self.controls if c.status == ComplianceStatus.FAIL]

    def warnings(self) -> list[ComplianceControl]:
        return [c for c in self.controls if c.status == ComplianceStatus.WARN]

    def compute_score(self) -> float:
        if not self.controls:
            return 0.0
        weight = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
                  Severity.LOW: 1, Severity.INFO: 0}
        total_weight = sum(weight[c.severity] for c in self.controls)
        pass_weight = sum(weight[c.severity] for c in self.controls
                         if c.status == ComplianceStatus.PASS)
        return round((pass_weight / total_weight * 100) if total_weight else 0.0, 1)


@dataclass
class IOC:
    ioc_id: str
    name: str
    description: str
    severity: Severity
    indicator_type: str   # "process", "file", "network", "certificate", "app", "permission"
    value: str            # the artifact found
    threat_family: str    # e.g. "Pegasus", "Cerberus", "FlexiSpy"
    confidence: float     # 0.0 – 1.0
    reference: str = ""


class AgentDeploymentMethod(str, enum.Enum):
    MDM_PROFILE = "mdm_profile"   # iOS
    MANAGED_APK = "managed_apk"   # Android via managed Google Play


class AgentStatus(str, enum.Enum):
    DEPLOYED = "deployed"
    PENDING = "pending"
    FAILED = "failed"
    NOT_SUPPORTED = "not_supported"


@dataclass
class MonitoringAgent:
    device_udid: str
    platform: Platform
    deployment_method: AgentDeploymentMethod
    status: AgentStatus
    agent_version: str
    deployed_at: datetime | None = None
    last_heartbeat: datetime | None = None
    monitoring_capabilities: list[str] = field(default_factory=list)
    error_message: str = ""
