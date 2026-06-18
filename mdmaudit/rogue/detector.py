"""
Rogue MDM profile detection.

Analyses installed configuration profiles and MDM enrollments to identify:
- Profiles from unrecognised MDM servers
- Consumer stalkerware masquerading as MDM
- Profiles granting excessive permissions on BYOD devices
- CA certificates enabling traffic interception
- MDM servers with anomalous certificate characteristics
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime
from typing import Optional, Union
from urllib.parse import urlparse

from ..models import FindingSeverity, ProfileType, RogueProfile

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Known-bad / suspicious MDM server indicators
# These are documented by Amnesty International MVT, Citizen Lab, and
# commercial mobile threat intelligence feeds.
# ─────────────────────────────────────────────────────────────────────────────

# Organisation names used by known commercial stalkerware MDM enrollments
# (documented by researchers; not used to build anything harmful)
KNOWN_STALKERWARE_ORGS: set[str] = {
    "FlexiSpy", "flexispy", "Retina-X Studios",
    "mSpy", "iKeyMonitor", "Hoverwatch",
    "Spyic", "SpyBubble", "CocoSpy",
    "TheTruthSpy", "iSpyoo", "Copy9",
    "Highster Mobile", "PhoneSpector",
}

# Domain patterns associated with known stalkerware infrastructure
STALKERWARE_DOMAIN_PATTERNS: list[re.Pattern] = [
    re.compile(r"flexispy\.com", re.IGNORECASE),
    re.compile(r"mspy\.com", re.IGNORECASE),
    re.compile(r"ikeymonitor\.com", re.IGNORECASE),
    re.compile(r"hoverwatch\.com", re.IGNORECASE),
    re.compile(r"spyic\.com", re.IGNORECASE),
    re.compile(r"cocospy\.com", re.IGNORECASE),
    re.compile(r"spybubble\.com", re.IGNORECASE),
    re.compile(r"thetruthspy\.com", re.IGNORECASE),
    re.compile(r"copy9\.com", re.IGNORECASE),
    re.compile(r"highstermobile\.com", re.IGNORECASE),
    re.compile(r"xnspy\.com", re.IGNORECASE),
    re.compile(r"mobilespy\.", re.IGNORECASE),
]

# MDM payload types that grant full device management (vs. limited profile)
FULL_MDM_PAYLOAD_TYPES = {
    "com.apple.mdm",
    "com.android.enterprise.device.owner",
}

# Organisation name patterns that suggest deceptive / misleading profile identity
DECEPTIVE_ORG_PATTERNS: list[re.Pattern] = [
    re.compile(r"apple\s+inc", re.IGNORECASE),   # impersonating Apple
    re.compile(r"google\s+llc", re.IGNORECASE),  # impersonating Google
    re.compile(r"microsoft\s+corp", re.IGNORECASE),
    re.compile(r"system\s+service", re.IGNORECASE),
    re.compile(r"ios\s+update", re.IGNORECASE),
    re.compile(r"android\s+system", re.IGNORECASE),
]


def detect_rogue_mdm(
    profiles: list[dict],
    trusted_mdm_domains: Optional[list[str]] = None,
    device_ownership: str = "corporate",
) -> list[RogueProfile]:
    """
    Scan a list of installed profile records for rogue or suspicious MDM enrollments.

    Args:
        profiles: List of installed profile dicts. Each dict should contain at
                  minimum: ``PayloadIdentifier``, ``PayloadDisplayName``,
                  ``PayloadOrganization``, ``PayloadContent`` (list of payloads),
                  and optionally ``ServerURL`` / ``InstallDate``.
        trusted_mdm_domains: Domains that are pre-approved as legitimate MDM
                             servers for this organisation. Profiles from other
                             domains are flagged as unrecognised.
        device_ownership: "corporate" or "byod" — affects severity of
                          full-device-management findings.

    Returns:
        List of RogueProfile objects, sorted by severity descending.
    """
    rogue: list[RogueProfile] = []
    trusted = set(trusted_mdm_domains or [])

    for raw in profiles:
        rogue.extend(_analyse_profile(raw, trusted, device_ownership))

    # Sort: CRITICAL → INFO
    _order = {FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1,
               FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 3,
               FindingSeverity.INFO: 4}
    rogue.sort(key=lambda r: _order[r.severity])
    return rogue


def check_ca_certificates(profiles: list[dict]) -> list[RogueProfile]:
    """
    Extract and flag all CA certificates installed via MDM profile, regardless
    of the profile source. This is a standalone check for MITM risk.
    """
    rogue: list[RogueProfile] = []
    for profile in profiles:
        payloads = profile.get("PayloadContent", [])
        for payload in payloads:
            ptype = str(payload.get("PayloadType", ""))
            if ptype in ("com.apple.security.root", "com.apple.security.pkcs1"):
                org = str(profile.get("PayloadOrganization", "Unknown"))
                ca_name = str(payload.get("PayloadDisplayName", "Unknown CA"))
                rogue.append(RogueProfile(
                    profile_id=str(payload.get("PayloadUUID", "unknown")),
                    display_name=ca_name,
                    organization=org,
                    server_url=str(profile.get("ServerURL", "")),
                    installed_at=_parse_date(profile.get("InstallDate")),
                    profile_type=ProfileType.CERTIFICATE,
                    severity=FindingSeverity.MEDIUM,
                    reason=(
                        f"Root CA certificate '{ca_name}' from '{org}' installed. "
                        "Devices trust all TLS certificates signed by this CA, "
                        "enabling HTTPS traffic interception if the CA key is "
                        "held by an unauthorised party."
                    ),
                    indicators=[
                        f"PayloadType: {ptype}",
                        f"Organization: {org}",
                    ],
                    raw_data=payload,
                ))
    return rogue


def verify_mdm_server_certificate(server_url: str, timeout: int = 10) -> list[RogueProfile]:
    """
    Connect to the MDM server and verify its TLS certificate.
    Returns RogueProfile entries for certificate anomalies.
    """
    rogue: list[RogueProfile] = []
    parsed = urlparse(server_url)
    if parsed.scheme != "https":
        rogue.append(RogueProfile(
            profile_id="cert-check-http",
            display_name="MDM Server (HTTP)",
            organization="Unknown",
            server_url=server_url,
            installed_at=None,
            profile_type=ProfileType.MDM,
            severity=FindingSeverity.CRITICAL,
            reason="MDM server URL uses plaintext HTTP — no TLS certificate to verify.",
            indicators=["scheme: http"],
        ))
        return rogue

    hostname = parsed.hostname or ""
    port = parsed.port or 443

    try:
        import ssl, socket

        ctx = ssl.create_default_context()
        try:
            with ctx.wrap_socket(
                socket.create_connection((hostname, port), timeout=timeout),
                server_hostname=hostname,
            ) as conn:
                cert = conn.getpeercert()
                _check_cert_anomalies(cert, server_url, rogue)
        except ssl.SSLCertVerificationError as exc:
            rogue.append(RogueProfile(
                profile_id="cert-invalid",
                display_name="MDM Server",
                organization="Unknown",
                server_url=server_url,
                installed_at=None,
                profile_type=ProfileType.MDM,
                severity=FindingSeverity.CRITICAL,
                reason=f"MDM server TLS certificate failed validation: {exc}",
                indicators=[str(exc)],
            ))
    except Exception as exc:
        logger.debug("Certificate verification failed for %s: %s", server_url, exc)

    return rogue


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _analyse_profile(
    profile: dict,
    trusted_domains: set[str],
    device_ownership: str,
) -> list[RogueProfile]:
    rogue: list[RogueProfile] = []

    profile_id = str(profile.get("PayloadIdentifier", "unknown"))
    display_name = str(profile.get("PayloadDisplayName", "Unknown Profile"))
    organization = str(profile.get("PayloadOrganization", ""))
    server_url = str(profile.get("ServerURL", ""))
    install_date = _parse_date(profile.get("InstallDate"))
    payloads: list[dict] = profile.get("PayloadContent", [])

    # ── Stalkerware organisation check ────────────────────────────────────────
    for bad_org in KNOWN_STALKERWARE_ORGS:
        if bad_org.lower() in organization.lower():
            rogue.append(RogueProfile(
                profile_id=profile_id,
                display_name=display_name,
                organization=organization,
                server_url=server_url,
                installed_at=install_date,
                profile_type=ProfileType.MDM,
                severity=FindingSeverity.CRITICAL,
                reason=(
                    f"Profile organisation '{organization}' matches known "
                    f"commercial stalkerware vendor '{bad_org}'. "
                    "This profile provides covert device surveillance capabilities "
                    "and should be removed immediately."
                ),
                indicators=[
                    f"Organization match: {bad_org}",
                    f"Server URL: {server_url}",
                ],
                raw_data=profile,
            ))
            return rogue  # No need to continue checking this profile

    # ── Stalkerware server URL check ──────────────────────────────────────────
    for pattern in STALKERWARE_DOMAIN_PATTERNS:
        if pattern.search(server_url):
            rogue.append(RogueProfile(
                profile_id=profile_id,
                display_name=display_name,
                organization=organization,
                server_url=server_url,
                installed_at=install_date,
                profile_type=ProfileType.MDM,
                severity=FindingSeverity.CRITICAL,
                reason=(
                    f"MDM server URL '{server_url}' matches a known stalkerware "
                    "infrastructure domain. This profile was likely installed "
                    "without the device owner's knowledge."
                ),
                indicators=[
                    f"Domain match: {pattern.pattern}",
                    f"Server URL: {server_url}",
                ],
                raw_data=profile,
            ))
            return rogue

    # ── Deceptive organisation name ───────────────────────────────────────────
    for pattern in DECEPTIVE_ORG_PATTERNS:
        if pattern.search(organization):
            rogue.append(RogueProfile(
                profile_id=profile_id,
                display_name=display_name,
                organization=organization,
                server_url=server_url,
                installed_at=install_date,
                profile_type=ProfileType.MDM,
                severity=FindingSeverity.HIGH,
                reason=(
                    f"Profile organisation name '{organization}' appears to "
                    "impersonate a major technology vendor. Legitimate MDM profiles "
                    "use the deploying organisation's actual name."
                ),
                indicators=[f"Deceptive org name: {organization}"],
                raw_data=profile,
            ))

    # ── Unrecognised MDM server ───────────────────────────────────────────────
    if server_url and trusted_domains:
        parsed = urlparse(server_url)
        host = parsed.hostname or ""
        domain_recognised = any(
            host == d or host.endswith("." + d)
            for d in trusted_domains
        )
        if not domain_recognised:
            # Check for IP address (unusual for legitimate MDM)
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False

            severity = FindingSeverity.HIGH if is_ip else FindingSeverity.MEDIUM
            rogue.append(RogueProfile(
                profile_id=profile_id,
                display_name=display_name,
                organization=organization,
                server_url=server_url,
                installed_at=install_date,
                profile_type=ProfileType.MDM,
                severity=severity,
                reason=(
                    f"MDM server '{server_url}' is not in the list of "
                    "approved MDM domains for this organisation. "
                    + ("IP addresses as MDM server URLs are unusual for legitimate deployments. " if is_ip else "")
                    + "Verify this profile was intentionally installed."
                ),
                indicators=[
                    f"Server URL: {server_url}",
                    f"Trusted domains: {', '.join(trusted_domains)}",
                ],
                raw_data=profile,
            ))

    # ── Full device management on BYOD ────────────────────────────────────────
    for payload in payloads:
        ptype = str(payload.get("PayloadType", ""))
        if ptype in FULL_MDM_PAYLOAD_TYPES and device_ownership == "byod":
            rogue.append(RogueProfile(
                profile_id=profile_id,
                display_name=display_name,
                organization=organization,
                server_url=server_url,
                installed_at=install_date,
                profile_type=ProfileType.MDM,
                severity=FindingSeverity.HIGH,
                reason=(
                    f"Profile contains a full device management payload "
                    f"({ptype}) installed on a BYOD device. Full management "
                    "grants the MDM server control over the entire device, "
                    "not just a work profile or managed apps. This may exceed "
                    "the consent provided by the employee."
                ),
                indicators=[
                    f"PayloadType: {ptype}",
                    "device_ownership: byod",
                ],
                raw_data=payload,
            ))

        # Root CA in any profile → flag for review
        if ptype in ("com.apple.security.root", "com.apple.security.pkcs1"):
            ca_name = str(payload.get("PayloadDisplayName", "Unknown CA"))
            rogue.append(RogueProfile(
                profile_id=f"{profile_id}-ca-{payload.get('PayloadUUID', '')[:8]}",
                display_name=ca_name,
                organization=organization,
                server_url=server_url,
                installed_at=install_date,
                profile_type=ProfileType.CERTIFICATE,
                severity=FindingSeverity.MEDIUM,
                reason=(
                    f"Root CA certificate '{ca_name}' installed by profile "
                    f"'{display_name}' from '{organization}'. This CA can sign "
                    "certificates for any domain. Verify this is your organisation's "
                    "internal PKI root, not a rogue intercept CA."
                ),
                indicators=[
                    f"CA name: {ca_name}",
                    f"Source profile: {profile_id}",
                ],
                raw_data=payload,
            ))

    return rogue


def _check_cert_anomalies(cert: dict, server_url: str, rogue: list[RogueProfile]) -> None:
    """Check TLS certificate for characteristics typical of rogue/stalkerware MDMs."""
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    org = subject.get("organizationName", "")
    common_name = subject.get("commonName", "")
    issuer_org = issuer.get("organizationName", "")

    # Self-signed (issuer == subject)
    if subject == issuer:
        rogue.append(RogueProfile(
            profile_id="cert-self-signed",
            display_name=f"MDM Server: {common_name}",
            organization=org,
            server_url=server_url,
            installed_at=None,
            profile_type=ProfileType.MDM,
            severity=FindingSeverity.HIGH,
            reason=(
                f"MDM server '{server_url}' presents a self-signed TLS certificate. "
                "Self-signed certificates cannot be verified by devices without "
                "installing a custom CA root. This is unusual for legitimate "
                "enterprise MDM deployments."
            ),
            indicators=[
                f"Subject: {subject}",
                f"Issuer (same as subject): {issuer}",
            ],
        ))

    # Certificate issued to an IP address
    parsed = urlparse(server_url)
    host = parsed.hostname or ""
    try:
        ipaddress.ip_address(host)
        rogue.append(RogueProfile(
            profile_id="cert-ip-address",
            display_name=f"MDM Server: {common_name}",
            organization=org,
            server_url=server_url,
            installed_at=None,
            profile_type=ProfileType.MDM,
            severity=FindingSeverity.MEDIUM,
            reason=(
                f"MDM server uses an IP address ({host}) rather than a hostname. "
                "Legitimate enterprise MDM servers use FQDNs with DNS-validated certificates."
            ),
            indicators=[f"Server IP: {host}", f"Certificate CN: {common_name}"],
        ))
    except ValueError:
        pass


def _parse_date(raw) -> Optional[datetime]:
    if isinstance(raw, datetime):
        return raw
    if isinstance(raw, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(raw, fmt)
            except ValueError:
                continue
    return None
