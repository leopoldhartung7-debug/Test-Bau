"""
Core data models for MDMAudit — MDM security assessment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class MDMPlatform(Enum):
    JAMF = "jamf"
    INTUNE = "intune"
    WORKSPACE_ONE = "workspace_one"
    KANDJI = "kandji"
    MOSYLE = "mosyle"
    GENERIC_APPLE = "generic_apple"
    ANDROID_ENTERPRISE = "android_enterprise"


class DevicePlatform(Enum):
    IOS = "ios"
    IPADOS = "ipados"
    MACOS = "macos"
    ANDROID = "android"


class DeviceOwnership(Enum):
    CORPORATE = "corporate"
    BYOD = "byod"
    COPE = "cope"  # Corporate Owned, Personally Enabled


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ProfileType(Enum):
    MDM = "mdm"
    CERTIFICATE = "certificate"
    VPN = "vpn"
    WIFI = "wifi"
    RESTRICTION = "restriction"
    EMAIL = "email"
    SCEP = "scep"
    OTHER = "other"


class AuthMethod(Enum):
    NONE = "none"
    USERNAME_PASSWORD = "username_password"
    CERTIFICATE = "certificate"
    OAUTH2 = "oauth2"
    SAML = "saml"
    MFA = "mfa"
    API_KEY = "api_key"


# ─────────────────────────────────────────────────────────────────────────────
# Base finding
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    finding_id: str
    title: str
    description: str
    severity: FindingSeverity
    category: str
    evidence: list[str]
    remediation: str
    cwe_id: str = ""
    cvss_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": self.cwe_id,
            "cvss": self.cvss_score,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Enrollment report
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EnrollmentReport:
    report_id: str
    mdm_platform: MDMPlatform
    generated_at: datetime
    findings: list[Finding]
    enrollment_url: str = ""
    requires_authentication: bool = True
    auth_method: AuthMethod = AuthMethod.USERNAME_PASSWORD
    supports_zero_touch: bool = False
    blocks_reenrollment: bool = True
    scan_duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)

    def by_severity(self, severity: FindingSeverity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def summary(self) -> str:
        counts = {s: sum(1 for f in self.findings if f.severity == s)
                  for s in FindingSeverity}
        lines = [
            f"MDM Enrollment Assessment — {self.mdm_platform.value.upper()}",
            f"Generated: {self.generated_at.isoformat()}",
            f"Auth required: {self.requires_authentication}  "
            f"Auth method: {self.auth_method.value}",
            f"",
            f"Findings: {len(self.findings)} total",
            f"  Critical: {counts[FindingSeverity.CRITICAL]}",
            f"  High:     {counts[FindingSeverity.HIGH]}",
            f"  Medium:   {counts[FindingSeverity.MEDIUM]}",
            f"  Low:      {counts[FindingSeverity.LOW]}",
            f"  Info:     {counts[FindingSeverity.INFO]}",
        ]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Profile report
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProfileFinding(Finding):
    profile_identifier: str = ""
    profile_type: ProfileType = ProfileType.OTHER
    payload_uuid: str = ""


@dataclass
class ProfileReport:
    report_id: str
    device_identifier: str
    device_platform: DevicePlatform
    generated_at: datetime
    profiles_analyzed: int
    findings: list[ProfileFinding]
    scan_duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)

    def by_severity(self, severity: FindingSeverity) -> list[ProfileFinding]:
        return [f for f in self.findings if f.severity == severity]

    def by_profile(self, identifier: str) -> list[ProfileFinding]:
        return [f for f in self.findings if f.profile_identifier == identifier]

    def summary(self) -> str:
        counts = {s: sum(1 for f in self.findings if f.severity == s)
                  for s in FindingSeverity}
        return (
            f"Profile Security Analysis — {self.device_platform.value.upper()} "
            f"[{self.device_identifier}]\n"
            f"Profiles analysed: {self.profiles_analyzed} | "
            f"Critical: {counts[FindingSeverity.CRITICAL]} | "
            f"High: {counts[FindingSeverity.HIGH]} | "
            f"Medium: {counts[FindingSeverity.MEDIUM]}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# API security report
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class APIFinding(Finding):
    endpoint: str = ""
    http_method: str = ""
    parameter: str = ""
    request_sample: str = ""


@dataclass
class APISecurityReport:
    report_id: str
    endpoint: str
    generated_at: datetime
    tls_version: str
    tls_ciphers: list[str]
    supports_certificate_pinning: bool
    has_rate_limiting: bool
    auth_method: AuthMethod
    findings: list[APIFinding]
    scan_duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)

    def by_severity(self, severity: FindingSeverity) -> list[APIFinding]:
        return [f for f in self.findings if f.severity == severity]

    def summary(self) -> str:
        counts = {s: sum(1 for f in self.findings if f.severity == s)
                  for s in FindingSeverity}
        return (
            f"MDM API Security — {self.endpoint}\n"
            f"TLS: {self.tls_version} | Pinning: {self.supports_certificate_pinning} | "
            f"Rate-limiting: {self.has_rate_limiting}\n"
            f"Critical: {counts[FindingSeverity.CRITICAL]} | "
            f"High: {counts[FindingSeverity.HIGH]} | "
            f"Medium: {counts[FindingSeverity.MEDIUM]}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Attack graph
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackNode:
    node_id: str
    # "device" | "user" | "service" | "credential" | "network" | "data_store"
    node_type: str
    name: str
    platform: str
    privileges: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class AttackEdge:
    edge_id: str
    source_id: str
    target_id: str
    technique: str
    mitre_id: str
    description: str
    difficulty: str   # "low" | "medium" | "high"
    impact: str
    prerequisites: list[str] = field(default_factory=list)


@dataclass
class AttackPath:
    path_id: str
    name: str
    node_ids: list[str]
    edge_ids: list[str]
    severity: FindingSeverity
    description: str
    remediation: str
    mitre_techniques: list[str] = field(default_factory=list)


@dataclass
class AttackGraph:
    graph_id: str
    generated_at: datetime
    nodes: list[AttackNode]
    edges: list[AttackEdge]
    attack_paths: list[AttackPath]
    scan_duration_seconds: float = 0.0

    @property
    def critical_paths(self) -> list[AttackPath]:
        return [p for p in self.attack_paths if p.severity == FindingSeverity.CRITICAL]

    @property
    def high_impact_paths(self) -> list[AttackPath]:
        return [p for p in self.attack_paths
                if p.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)]

    def node_by_id(self, node_id: str) -> Optional[AttackNode]:
        return next((n for n in self.nodes if n.node_id == node_id), None)

    def edges_from(self, node_id: str) -> list[AttackEdge]:
        return [e for e in self.edges if e.source_id == node_id]

    def edges_to(self, node_id: str) -> list[AttackEdge]:
        return [e for e in self.edges if e.target_id == node_id]

    def summary(self) -> str:
        return (
            f"MDM Attack Graph\n"
            f"Nodes: {len(self.nodes)} | Edges: {len(self.edges)}\n"
            f"Attack paths: {len(self.attack_paths)} | "
            f"Critical: {len(self.critical_paths)} | "
            f"High: {len([p for p in self.attack_paths if p.severity == FindingSeverity.HIGH])}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Rogue MDM
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RogueProfile:
    profile_id: str
    display_name: str
    organization: str
    server_url: str
    installed_at: Optional[datetime]
    profile_type: ProfileType
    severity: FindingSeverity
    reason: str
    indicators: list[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)

    @property
    def is_suspicious(self) -> bool:
        return self.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)

    def to_dict(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "display_name": self.display_name,
            "organization": self.organization,
            "server_url": self.server_url,
            "installed_at": self.installed_at.isoformat() if self.installed_at else None,
            "type": self.profile_type.value,
            "severity": self.severity.value,
            "reason": self.reason,
            "indicators": self.indicators,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Deployment descriptor (input to attack path analysis)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MDMDeployment:
    deployment_id: str
    platform: MDMPlatform
    server_url: str
    organization: str
    device_count: int = 0
    ownership: DeviceOwnership = DeviceOwnership.CORPORATE
    managed_platforms: list[DevicePlatform] = field(default_factory=list)
    ldap_integrated: bool = False
    pki_integrated: bool = False
    siem_integrated: bool = False
    mfa_required: bool = False
    # Credentials or service accounts the MDM uses
    linked_services: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
