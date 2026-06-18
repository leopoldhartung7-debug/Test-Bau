"""
MDM privilege escalation and lateral movement path analysis.

Models the MDM deployment as a directed graph and identifies attack paths
that an adversary could follow to escalate privileges or move laterally
from a compromised device to MDM administration or connected infrastructure.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from ..models import (
    AttackEdge,
    AttackGraph,
    AttackNode,
    AttackPath,
    FindingSeverity,
    MDMDeployment,
    MDMPlatform,
)


def map_attack_paths(deployment: MDMDeployment) -> AttackGraph:
    """
    Analyse an MDM deployment and construct an attack graph with prioritised
    escalation paths.

    The graph models:
    - Device → MDM server (credential/token abuse)
    - MDM → LDAP/AD (directory service escalation)
    - MDM → PKI (certificate authority abuse)
    - MDM → connected services (lateral movement)
    - Device → Device (shared credential/profile abuse)
    """
    nodes: list[AttackNode] = []
    edges: list[AttackEdge] = []

    # ── Seed nodes ────────────────────────────────────────────────────────────
    device_node = AttackNode(
        node_id="node-device",
        node_type="device",
        name="Compromised Enrolled Device",
        platform=str(deployment.managed_platforms[0].value)
        if deployment.managed_platforms else "unknown",
        privileges=["device-token", "mdm-client"],
    )
    nodes.append(device_node)

    mdm_node = AttackNode(
        node_id="node-mdm",
        node_type="service",
        name=f"MDM Server ({deployment.platform.value})",
        platform="server",
        privileges=["device-management", "profile-push", "remote-wipe"],
        metadata={"url": deployment.server_url},
    )
    nodes.append(mdm_node)

    mdm_admin_node = AttackNode(
        node_id="node-mdm-admin",
        node_type="user",
        name="MDM Administrator Account",
        platform="server",
        privileges=["mdm-admin", "push-payload", "enroll-device", "wipe-device"],
    )
    nodes.append(mdm_admin_node)

    # ── Build platform-specific graph ─────────────────────────────────────────
    _add_device_to_mdm_edges(edges, device_node, mdm_node, deployment)
    _add_mdm_admin_escalation(nodes, edges, mdm_node, mdm_admin_node, deployment)

    if deployment.ldap_integrated:
        ldap_node = _add_ldap_paths(nodes, edges, mdm_node)
    if deployment.pki_integrated:
        pki_node = _add_pki_paths(nodes, edges, mdm_node)
    if deployment.linked_services:
        _add_service_paths(nodes, edges, mdm_admin_node, deployment.linked_services)

    if deployment.device_count > 1:
        _add_device_to_device_paths(nodes, edges, device_node, deployment)

    # ── Enumerate high-impact paths ───────────────────────────────────────────
    paths = _enumerate_paths(nodes, edges, deployment)

    return AttackGraph(
        graph_id=str(uuid.uuid4()),
        generated_at=datetime.utcnow(),
        nodes=nodes,
        edges=edges,
        attack_paths=sorted(paths, key=lambda p: _severity_order(p.severity)),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Edge builders
# ─────────────────────────────────────────────────────────────────────────────

def _add_device_to_mdm_edges(
    edges: list[AttackEdge],
    device: AttackNode,
    mdm: AttackNode,
    deployment: MDMDeployment,
) -> None:
    # Device token abuse — replay device's MDM token to query inventory
    edges.append(AttackEdge(
        edge_id="edge-dev-mdm-token",
        source_id=device.node_id,
        target_id=mdm.node_id,
        technique="MDM Device Token Replay",
        mitre_id="T1550.001",
        description=(
            "Use the device's MDM authentication token (extracted from device "
            "keychain or network traffic) to authenticate to the MDM management "
            "API as if the request came from the device."
        ),
        difficulty="medium",
        impact=(
            "Read inventory, configuration profiles, and installed app lists "
            "for all devices if the API has IDOR vulnerabilities."
        ),
        prerequisites=["device-token", "mdm-api-accessible"],
    ))

    # Profile SSID/PSK extraction
    edges.append(AttackEdge(
        edge_id="edge-dev-mdm-profile",
        source_id=device.node_id,
        target_id=mdm.node_id,
        technique="MDM Profile Credential Extraction",
        mitre_id="T1552.001",
        description=(
            "Extract Wi-Fi PSKs, VPN credentials, or email passwords from "
            "MDM-pushed configuration profiles stored on the compromised device."
        ),
        difficulty="low",
        impact=(
            "Obtain VPN pre-shared keys or Wi-Fi passwords that provide access "
            "to corporate networks from any device."
        ),
        prerequisites=["device-filesystem-access"],
    ))

    if not deployment.mfa_required:
        edges.append(AttackEdge(
            edge_id="edge-dev-mdm-creds",
            source_id=device.node_id,
            target_id=mdm.node_id,
            technique="MDM Admin Credential Theft (No MFA)",
            mitre_id="T1078",
            description=(
                "Capture MDM administrator credentials from device memory, "
                "keychain, or cached browser sessions. Without MFA, stolen "
                "credentials immediately grant MDM administrator access."
            ),
            difficulty="medium",
            impact="Full MDM administrator access — push payloads to all managed devices.",
            prerequisites=["credential-access", "no-mfa"],
        ))


def _add_mdm_admin_escalation(
    nodes: list[AttackNode],
    edges: list[AttackEdge],
    mdm: AttackNode,
    mdm_admin: AttackNode,
    deployment: MDMDeployment,
) -> None:
    # Misconfigured RBAC — regular MDM user → admin
    edges.append(AttackEdge(
        edge_id="edge-mdm-rbac",
        source_id=mdm.node_id,
        target_id=mdm_admin.node_id,
        technique="MDM RBAC Misconfiguration",
        mitre_id="T1078.003",
        description=(
            "Exploit overly permissive role-based access control in the MDM "
            "to access administrative functions from a regular user or device "
            "management account."
        ),
        difficulty="low" if deployment.device_count > 50 else "medium",
        impact="Escalate from device-level access to full MDM administrator.",
        prerequisites=["mdm-low-priv-account"],
    ))

    # API key exposure
    edges.append(AttackEdge(
        edge_id="edge-mdm-apikey",
        source_id=mdm.node_id,
        target_id=mdm_admin.node_id,
        technique="MDM API Key Exposure",
        mitre_id="T1552.004",
        description=(
            "Extract MDM API keys from device applications, mobile management "
            "profiles, or server-side configuration files. Static API keys with "
            "admin scope provide persistent privileged access."
        ),
        difficulty="medium",
        impact="Persistent MDM admin access independent of user credentials.",
        prerequisites=["mdm-api-key-in-app"],
    ))


def _add_ldap_paths(
    nodes: list[AttackNode],
    edges: list[AttackEdge],
    mdm: AttackNode,
) -> AttackNode:
    ldap_node = AttackNode(
        node_id="node-ldap",
        node_type="service",
        name="LDAP / Active Directory",
        platform="server",
        privileges=["directory-read", "user-auth"],
    )
    nodes.append(ldap_node)

    edges.append(AttackEdge(
        edge_id="edge-mdm-ldap-creds",
        source_id=mdm.node_id,
        target_id=ldap_node.node_id,
        technique="MDM LDAP Bind Credential Extraction",
        mitre_id="T1003",
        description=(
            "The MDM server uses a service account to bind to LDAP for "
            "authentication lookups. Extracting the MDM server's LDAP bind "
            "credentials (from server config files or memory) provides a "
            "service account with directory read — often a path to DCSync "
            "or user enumeration."
        ),
        difficulty="medium",
        impact=(
            "Directory service access: user enumeration, password policy "
            "discovery, and potential path to domain escalation."
        ),
        prerequisites=["mdm-server-access", "ldap-bind-account"],
    ))

    edges.append(AttackEdge(
        edge_id="edge-ldap-dc",
        source_id=ldap_node.node_id,
        target_id="node-domain-controller",
        technique="LDAP Service Account → Domain Escalation",
        mitre_id="T1078.002",
        description=(
            "Leverage LDAP bind credentials to enumerate privileged accounts, "
            "Kerberoastable service accounts, or to perform DCSync if the "
            "bind account has replication rights."
        ),
        difficulty="high",
        impact="Domain Controller compromise.",
        prerequisites=["ldap-bind-account", "ad-misconfiguration"],
    ))

    dc_node = AttackNode(
        node_id="node-domain-controller",
        node_type="service",
        name="Active Directory Domain Controller",
        platform="server",
        privileges=["domain-admin", "all-accounts"],
    )
    nodes.append(dc_node)

    return ldap_node


def _add_pki_paths(
    nodes: list[AttackNode],
    edges: list[AttackEdge],
    mdm: AttackNode,
) -> AttackNode:
    pki_node = AttackNode(
        node_id="node-pki",
        node_type="service",
        name="Enterprise PKI / Certificate Authority",
        platform="server",
        privileges=["issue-certificate", "revoke-certificate"],
    )
    nodes.append(pki_node)

    edges.append(AttackEdge(
        edge_id="edge-mdm-pki-scep",
        source_id=mdm.node_id,
        target_id=pki_node.node_id,
        technique="MDM SCEP Challenge Extraction",
        mitre_id="T1552",
        description=(
            "The MDM server embeds a SCEP challenge password in configuration "
            "profiles pushed to devices. Extracting this challenge from a "
            "device profile or from the MDM configuration allows an attacker "
            "to request arbitrary device certificates from the enterprise CA."
        ),
        difficulty="medium",
        impact=(
            "Issue valid enterprise certificates for attacker-controlled "
            "identities. These certificates may grant VPN, Wi-Fi, or "
            "internal service access."
        ),
        prerequisites=["mdm-profile-access", "scep-challenge-static"],
    ))

    return pki_node


def _add_service_paths(
    nodes: list[AttackNode],
    edges: list[AttackEdge],
    mdm_admin: AttackNode,
    services: list[str],
) -> None:
    for svc in services:
        svc_node = AttackNode(
            node_id=f"node-svc-{svc[:20]}",
            node_type="service",
            name=svc,
            platform="server",
            privileges=["service-user"],
        )
        nodes.append(svc_node)
        edges.append(AttackEdge(
            edge_id=f"edge-mdm-svc-{svc[:20]}",
            source_id=mdm_admin.node_id,
            target_id=svc_node.node_id,
            technique="MDM-to-Service Credential Reuse",
            mitre_id="T1078",
            description=(
                f"MDM administrator credentials or service accounts may be "
                f"reused for '{svc}'. Credential reuse exposes all linked services "
                "when any one credential is compromised."
            ),
            difficulty="low",
            impact=f"Access to {svc} with MDM admin-level credentials.",
            prerequisites=["mdm-admin-creds", "credential-reuse"],
        ))


def _add_device_to_device_paths(
    nodes: list[AttackNode],
    edges: list[AttackEdge],
    device: AttackNode,
    deployment: MDMDeployment,
) -> None:
    target_device = AttackNode(
        node_id="node-target-device",
        node_type="device",
        name="Other Enrolled Device",
        platform="any",
        privileges=["enrolled-device"],
    )
    nodes.append(target_device)

    # Shared Wi-Fi PSK
    edges.append(AttackEdge(
        edge_id="edge-dev-dev-wifi",
        source_id=device.node_id,
        target_id=target_device.node_id,
        technique="Shared Wi-Fi Credential Lateral Movement",
        mitre_id="T1021",
        description=(
            "Wi-Fi PSKs pushed to all devices via MDM are shared secrets — "
            "compromise of one device reveals credentials that provide "
            "network-layer access to segment any enrolled device is on."
        ),
        difficulty="low",
        impact="Network adjacency to all devices on the corporate Wi-Fi segment.",
        prerequisites=["device-filesystem-access", "shared-wifi-psk"],
    ))

    # MDM payload push after admin escalation
    edges.append(AttackEdge(
        edge_id="edge-dev-dev-payload",
        source_id=device.node_id,
        target_id=target_device.node_id,
        technique="MDM Payload Push to All Devices (Post-Admin-Escalation)",
        mitre_id="T1072",
        description=(
            "After escalating to MDM administrator (via any path), push a "
            "malicious configuration profile or managed app to all enrolled "
            "devices. This is the highest-impact MDM attack path."
        ),
        difficulty="low",
        impact=(
            f"Compromise all {deployment.device_count} enrolled devices: "
            "install malware, extract credentials, remote wipe."
        ),
        prerequisites=["mdm-admin-access"],
    ))


# ─────────────────────────────────────────────────────────────────────────────
# Path enumeration
# ─────────────────────────────────────────────────────────────────────────────

def _enumerate_paths(
    nodes: list[AttackNode],
    edges: list[AttackEdge],
    deployment: MDMDeployment,
) -> list[AttackPath]:
    paths: list[AttackPath] = []

    # Path 1: Device token → IDOR → all device inventory
    paths.append(AttackPath(
        path_id="path-idor-inventory",
        name="Device Token → IDOR → Full Device Inventory",
        node_ids=["node-device", "node-mdm"],
        edge_ids=["edge-dev-mdm-token"],
        severity=FindingSeverity.HIGH,
        description=(
            "A compromised enrolled device's authentication token is replayed "
            "to query the MDM management API. If the API has IDOR vulnerabilities "
            "(CWE-639), the attacker can read inventory data, certificates, and "
            "configuration profiles for all enrolled devices."
        ),
        remediation=(
            "Implement per-resource authorization checks. Verify the requesting "
            "device/user identity against the requested resource on every API call. "
            "Rotate device tokens regularly and bind them to device attestation."
        ),
        mitre_techniques=["T1550.001", "T1530"],
    ))

    # Path 2: Profile extraction → VPN/Wi-Fi access
    paths.append(AttackPath(
        path_id="path-profile-cred-extract",
        name="Device Compromise → Profile Credential Extraction → Network Access",
        node_ids=["node-device", "node-mdm"],
        edge_ids=["edge-dev-mdm-profile"],
        severity=FindingSeverity.HIGH,
        description=(
            "MDM-pushed profiles on a compromised device contain VPN pre-shared "
            "keys, Wi-Fi passwords, or email credentials. These are readable "
            "from the device file system or keychain. They provide persistent "
            "network access that survives device replacement."
        ),
        remediation=(
            "Use certificate-based authentication (EAP-TLS, IKEv2) instead of "
            "shared secrets. Issue per-device certificates via SCEP so the "
            "private key is generated on-device and never leaves it. "
            "Rotate PSKs immediately when a device is reported compromised."
        ),
        mitre_techniques=["T1552.001"],
    ))

    # Path 3: Full MDM admin takeover (critical)
    paths.append(AttackPath(
        path_id="path-mdm-admin-takeover",
        name="Credential Theft → MDM Admin → Push Payload to All Devices",
        node_ids=["node-device", "node-mdm", "node-mdm-admin"],
        edge_ids=["edge-dev-mdm-creds", "edge-mdm-rbac"],
        severity=FindingSeverity.CRITICAL,
        description=(
            "Stolen MDM administrator credentials (from device memory, cached "
            "browser sessions, or phishing) provide immediate admin access to "
            "the MDM server. The attacker can push a malicious configuration "
            "profile or managed app to all enrolled devices simultaneously. "
            "Without MFA, this is a one-step path to full fleet compromise."
        ),
        remediation=(
            "Require MFA for all MDM administrator accounts. "
            "Restrict MDM admin access to known IP addresses (corporate network "
            "or VPN). Implement session recording for admin actions. "
            "Apply least-privilege: create separate accounts for read-only "
            "inventory vs. destructive operations (wipe, payload push). "
            "Alert on first-time-seen logins and off-hours admin activity."
        ),
        mitre_techniques=["T1078", "T1072", "T1565.001"],
    ))

    # Path 4 (conditional): MDM → LDAP → DC
    if deployment.ldap_integrated:
        paths.append(AttackPath(
            path_id="path-mdm-ldap-dc",
            name="MDM Server Compromise → LDAP Bind Credential → Domain Controller",
            node_ids=["node-device", "node-mdm", "node-ldap", "node-domain-controller"],
            edge_ids=["edge-dev-mdm-creds", "edge-mdm-ldap-creds", "edge-ldap-dc"],
            severity=FindingSeverity.CRITICAL,
            description=(
                "The MDM server is integrated with Active Directory for user "
                "authentication. The LDAP bind service account credentials are "
                "stored on the MDM server. Compromise of the MDM server or its "
                "configuration exposes the bind account, which (if over-privileged) "
                "provides a path to DCSync or Kerberoasting against the domain."
            ),
            remediation=(
                "Grant the MDM LDAP bind account only the minimum permissions "
                "required (read-only, scoped to the OU containing device users). "
                "Store bind credentials in a secrets vault (HashiCorp Vault, "
                "Azure Key Vault) rather than plaintext config files. "
                "Use a dedicated service account that cannot interactively log in. "
                "Rotate the bind account password on a regular schedule."
            ),
            mitre_techniques=["T1003", "T1558.003", "T1078.002"],
        ))

    # Path 5 (conditional): SCEP challenge extraction
    if deployment.pki_integrated:
        paths.append(AttackPath(
            path_id="path-scep-challenge",
            name="SCEP Challenge Extraction → Arbitrary Certificate Issuance",
            node_ids=["node-device", "node-mdm", "node-pki"],
            edge_ids=["edge-dev-mdm-profile", "edge-mdm-pki-scep"],
            severity=FindingSeverity.HIGH,
            description=(
                "If the MDM uses a static SCEP challenge password (rather than "
                "one-time per-device challenges), extracting it from any enrolled "
                "device's configuration profile allows the attacker to request "
                "certificates for arbitrary identities from the enterprise CA."
            ),
            remediation=(
                "Use one-time, per-device SCEP challenge passwords generated by "
                "the MDM and validated by the RA. Alternatively, use ACME with "
                "device attestation for certificate issuance. Audit the CA's "
                "certificate templates to prevent privilege escalation via "
                "certificate attribute manipulation (ESC1–ESC8 attack classes)."
            ),
            mitre_techniques=["T1552", "T1649"],
        ))

    return paths


def _severity_order(s: FindingSeverity) -> int:
    return {FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4}[s]
