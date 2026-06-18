"""
iOS .mobileconfig profile security analysis.

Parses Apple configuration profile XML (plist format) and reports
misconfigurations across certificate, VPN, Wi-Fi, MDM, and restriction payloads.
"""

from __future__ import annotations

import logging
import plistlib
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Union

from ..models import (
    DevicePlatform,
    Finding,
    FindingSeverity,
    ProfileFinding,
    ProfileReport,
    ProfileType,
)

logger = logging.getLogger(__name__)

# EAP type IDs — RFC 3748 / IANA
_EAP_TYPES = {
    13: "EAP-TLS",
    17: "LEAP",
    18: "EAP-SIM",
    21: "EAP-TTLS",
    23: "EAP-AKA",
    25: "PEAP",
    43: "EAP-FAST",
}

# EAP types that should not be used alone (weak inner auth or no mutual auth)
_WEAK_EAP_ALONE = {17, 21, 25}  # LEAP, TTLS/PAP, PEAP/MSCHAPv2 without TLS

# VPN auth methods that transmit credentials in cleartext-equivalent form
_WEAK_VPN_AUTH = {"Password", "RSASecurID", "CHAP"}

# Restriction keys that control high-risk device capabilities
_KEY_RESTRICTIONS = {
    "allowCamera": (FindingSeverity.MEDIUM, "Camera access not restricted"),
    "allowScreenShot": (FindingSeverity.LOW, "Screenshot capture not restricted"),
    "allowCloudBackup": (FindingSeverity.MEDIUM, "iCloud backup not disabled"),
    "forceEncryptedBackup": (FindingSeverity.HIGH, "Encrypted backup not enforced"),
    "allowManagedAppsCloudSync": (FindingSeverity.MEDIUM, "Managed app iCloud sync not restricted"),
    "allowAirDrop": (FindingSeverity.MEDIUM, "AirDrop not disabled"),
    "allowUSBRestrictedMode": (FindingSeverity.HIGH, "USB Restricted Mode not enforced"),
    "allowDiagnosticSubmission": (FindingSeverity.LOW, "Diagnostic submission to Apple not disabled"),
}

# Payload type → ProfileType mapping
_PAYLOAD_TYPE_MAP = {
    "com.apple.mdm": ProfileType.MDM,
    "com.apple.security.pkcs12": ProfileType.CERTIFICATE,
    "com.apple.security.root": ProfileType.CERTIFICATE,
    "com.apple.security.pkcs1": ProfileType.CERTIFICATE,
    "com.apple.vpn.managed": ProfileType.VPN,
    "com.apple.vpn.managed.appmapper": ProfileType.VPN,
    "com.apple.wifi.managed": ProfileType.WIFI,
    "com.apple.applicationaccess": ProfileType.RESTRICTION,
    "com.apple.applicationaccess.new": ProfileType.RESTRICTION,
    "com.apple.mail.managed": ProfileType.EMAIL,
    "com.apple.exchActiveSync": ProfileType.EMAIL,
}


def analyze_ios_profiles(
    profiles: Union[list[dict], list[bytes], list[Path], dict, bytes, Path],
    device_identifier: str = "unknown",
) -> ProfileReport:
    """
    Analyse one or more iOS configuration profiles for security issues.

    ``profiles`` may be:
    - A single dict (already-parsed plist)
    - A single bytes blob (raw .mobileconfig)
    - A pathlib.Path to a .mobileconfig file
    - A list of any of the above
    """
    start = datetime.utcnow()

    if not isinstance(profiles, list):
        profiles = [profiles]

    all_findings: list[ProfileFinding] = []
    profile_count = 0

    for raw in profiles:
        parsed = _load_profile(raw)
        if parsed is None:
            continue
        profile_count += 1
        all_findings.extend(_analyze_single_profile(parsed))

    # Sort: CRITICAL → INFO, then by title
    _order = {FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1,
               FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 3,
               FindingSeverity.INFO: 4}
    all_findings.sort(key=lambda f: (_order[f.severity], f.title))

    return ProfileReport(
        report_id=str(uuid.uuid4()),
        device_identifier=device_identifier,
        device_platform=DevicePlatform.IOS,
        generated_at=datetime.utcnow(),
        profiles_analyzed=profile_count,
        findings=all_findings,
        scan_duration_seconds=(datetime.utcnow() - start).total_seconds(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Per-profile analysis
# ─────────────────────────────────────────────────────────────────────────────

def _analyze_single_profile(profile: dict) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []
    profile_id = str(profile.get("PayloadIdentifier", "unknown"))

    payloads: list[dict] = profile.get("PayloadContent", [])
    for payload in payloads:
        ptype_str = str(payload.get("PayloadType", ""))
        profile_type = _PAYLOAD_TYPE_MAP.get(ptype_str, ProfileType.OTHER)
        payload_uuid = str(payload.get("PayloadUUID", ""))

        if profile_type == ProfileType.CERTIFICATE:
            findings.extend(_check_certificate_payload(payload, profile_id, payload_uuid))
        elif profile_type == ProfileType.VPN:
            findings.extend(_check_vpn_payload(payload, profile_id, payload_uuid))
        elif profile_type == ProfileType.WIFI:
            findings.extend(_check_wifi_payload(payload, profile_id, payload_uuid))
        elif profile_type == ProfileType.RESTRICTION:
            findings.extend(_check_restriction_payload(payload, profile_id, payload_uuid))
        elif profile_type == ProfileType.MDM:
            findings.extend(_check_mdm_payload(payload, profile_id, payload_uuid))

    # Profile-level checks
    findings.extend(_check_profile_signing(profile, profile_id))

    return findings


def _check_certificate_payload(payload: dict, profile_id: str, puuid: str) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []
    name = str(payload.get("PayloadDisplayName", "Certificate"))
    ptype_str = str(payload.get("PayloadType", ""))

    # Check expiry — stored in DER/PEM content; parse if possible
    cert_data = payload.get("PayloadContent")
    if cert_data and isinstance(cert_data, bytes):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import Encoding
            import io
            cert = x509.load_der_x509_certificate(bytes(cert_data))
            now = datetime.now(timezone.utc)
            not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") \
                else cert.not_valid_after.replace(tzinfo=timezone.utc)
            if not_after < now:
                findings.append(ProfileFinding(
                    finding_id=f"IOS-CERT-001-{puuid[:8]}",
                    title=f"Expired Certificate in Profile: {name}",
                    description=(
                        f"Certificate '{name}' expired on "
                        f"{not_after.strftime('%Y-%m-%d')}. "
                        "Expired certificates prevent authentication and may cause "
                        "service outages. Device connectivity depending on this "
                        "certificate (VPN, Wi-Fi, email) will fail."
                    ),
                    severity=FindingSeverity.HIGH,
                    category="profile-certificate",
                    evidence=[
                        f"Profile: {profile_id}",
                        f"Certificate: {name}",
                        f"Expired: {not_after.isoformat()}",
                    ],
                    remediation=(
                        "Renew the certificate and push an updated profile. "
                        "Enable certificate expiry monitoring in your MDM so "
                        "alerts fire ≥30 days before expiry."
                    ),
                    cwe_id="CWE-298",
                    profile_identifier=profile_id,
                    profile_type=ProfileType.CERTIFICATE,
                    payload_uuid=puuid,
                ))
        except Exception:
            pass

    # Root CA installed — flag for review
    if ptype_str in ("com.apple.security.root", "com.apple.security.pkcs1"):
        findings.append(ProfileFinding(
            finding_id=f"IOS-CERT-002-{puuid[:8]}",
            title=f"Root CA Certificate Installed: {name}",
            description=(
                f"A root certificate authority ('{name}') is being installed "
                "as a trusted root. Devices will trust any certificate signed "
                "by this CA, including for HTTPS traffic. This is appropriate "
                "for internal PKI but creates a MITM risk if the CA is "
                "controlled by an unauthorised party."
            ),
            severity=FindingSeverity.MEDIUM,
            category="profile-certificate",
            evidence=[
                f"Profile: {profile_id}",
                f"CA name: {name}",
                f"Payload type: {ptype_str}",
            ],
            remediation=(
                "Verify this CA is your organisation's internal PKI root and "
                "that the private key is stored in an HSM. Document which "
                "services require this CA. Review periodically to ensure "
                "no unauthorised CAs are deployed."
            ),
            cwe_id="CWE-295",
            profile_identifier=profile_id,
            profile_type=ProfileType.CERTIFICATE,
            payload_uuid=puuid,
        ))

    return findings


def _check_vpn_payload(payload: dict, profile_id: str, puuid: str) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []
    name = str(payload.get("PayloadDisplayName", "VPN"))

    vpn_dict = payload.get("VPNType", payload.get("IPSec", {}))
    auth_method = ""
    if isinstance(payload.get("IKEv2"), dict):
        auth_method = payload["IKEv2"].get("AuthenticationMethod", "")
    elif isinstance(payload.get("IPSec"), dict):
        auth_method = payload["IPSec"].get("AuthenticationMethod", "")

    # Shared secret in profile
    psk = (
        payload.get("IPSec", {}).get("SharedSecret", "") or
        payload.get("IKEv2", {}).get("SharedSecret", "") or
        payload.get("PPP", {}).get("AuthPassword", "")
    )
    if psk:
        findings.append(ProfileFinding(
            finding_id=f"IOS-VPN-001-{puuid[:8]}",
            title=f"VPN Pre-Shared Key Stored in Profile: {name}",
            description=(
                f"The VPN profile '{name}' contains a pre-shared key or "
                "password in plaintext. If this profile is exported or the "
                "device is examined, the VPN credential is exposed."
            ),
            severity=FindingSeverity.HIGH,
            category="profile-vpn",
            evidence=[
                f"Profile: {profile_id}",
                f"VPN name: {name}",
                "Pre-shared key / password present in profile XML",
            ],
            remediation=(
                "Use certificate-based VPN authentication (EAP-TLS / IKEv2 RSA). "
                "Distribute certificates via SCEP so the private key is generated "
                "on-device and never exported. Remove PSK-based VPN profiles."
            ),
            cwe_id="CWE-312",
            cvss_score=7.5,
            profile_identifier=profile_id,
            profile_type=ProfileType.VPN,
            payload_uuid=puuid,
        ))

    if auth_method in _WEAK_VPN_AUTH:
        findings.append(ProfileFinding(
            finding_id=f"IOS-VPN-002-{puuid[:8]}",
            title=f"VPN Uses Weak Authentication Method: {auth_method}",
            description=(
                f"VPN profile '{name}' uses '{auth_method}' authentication. "
                "Password-based VPN authentication is susceptible to credential "
                "theft and replay attacks."
            ),
            severity=FindingSeverity.MEDIUM,
            category="profile-vpn",
            evidence=[f"AuthenticationMethod: {auth_method}"],
            remediation=(
                "Migrate to certificate-based VPN authentication (IKEv2 with "
                "EAP-TLS or RSA). Use device certificates issued via SCEP/ACME "
                "for mutual authentication."
            ),
            cwe_id="CWE-522",
            profile_identifier=profile_id,
            profile_type=ProfileType.VPN,
            payload_uuid=puuid,
        ))

    # Check for on-demand VPN — best practice for data protection
    on_demand = payload.get("OnDemandEnabled", 0)
    if not on_demand:
        findings.append(ProfileFinding(
            finding_id=f"IOS-VPN-003-{puuid[:8]}",
            title=f"VPN Not Configured as Always-On / On-Demand: {name}",
            description=(
                f"VPN profile '{name}' does not enable On-Demand. Users must "
                "manually activate the VPN, which is rarely done consistently. "
                "Sensitive corporate traffic may traverse untrusted networks unprotected."
            ),
            severity=FindingSeverity.LOW,
            category="profile-vpn",
            evidence=["OnDemandEnabled: 0 or absent"],
            remediation=(
                "Enable On-Demand VPN for corporate DNS domains and internal IP "
                "ranges. For high-security environments, configure Always-On VPN "
                "via supervised MDM (requires Device Enrollment, not BYOD)."
            ),
            profile_identifier=profile_id,
            profile_type=ProfileType.VPN,
            payload_uuid=puuid,
        ))

    return findings


def _check_wifi_payload(payload: dict, profile_id: str, puuid: str) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []
    ssid = str(payload.get("SSID_STR", "unknown"))

    eap_config: dict = payload.get("EAPClientConfiguration", {})
    eap_types: list[int] = eap_config.get("AcceptEAPTypes", [])

    if eap_config and eap_types:
        # EAP-TLS (13) is the strongest — no issues
        if eap_types == [13]:
            pass
        elif set(eap_types) & _WEAK_EAP_ALONE and 13 not in eap_types:
            eap_names = [_EAP_TYPES.get(t, str(t)) for t in eap_types]
            findings.append(ProfileFinding(
                finding_id=f"IOS-WIFI-001-{puuid[:8]}",
                title=f"Enterprise Wi-Fi Uses Weak EAP Method: {', '.join(eap_names)}",
                description=(
                    f"Wi-Fi profile for SSID '{ssid}' accepts EAP types "
                    f"{eap_names} without EAP-TLS (type 13). "
                    "PEAP/MSCHAPv2 and EAP-TTLS/PAP transmit hashed credentials "
                    "that are crackable offline. Without server certificate "
                    "validation, rogue AP attacks can harvest credentials."
                ),
                severity=FindingSeverity.HIGH,
                category="profile-wifi",
                evidence=[
                    f"SSID: {ssid}",
                    f"AcceptEAPTypes: {eap_types}",
                ],
                remediation=(
                    "Migrate to EAP-TLS with device certificates issued via SCEP. "
                    "If PEAP is required, enforce server certificate validation by "
                    "pinning the RADIUS server certificate in the profile."
                ),
                cwe_id="CWE-522",
                cvss_score=7.1,
                profile_identifier=profile_id,
                profile_type=ProfileType.WIFI,
                payload_uuid=puuid,
            ))

        # Check server certificate validation
        trusted_certs = eap_config.get("TLSTrustedServerNames", [])
        trusted_cas = eap_config.get("PayloadCertificateAnchorUUID", [])
        if not trusted_certs and not trusted_cas:
            findings.append(ProfileFinding(
                finding_id=f"IOS-WIFI-002-{puuid[:8]}",
                title=f"Wi-Fi Profile Does Not Pin RADIUS Server Certificate: {ssid}",
                description=(
                    f"Enterprise Wi-Fi profile for SSID '{ssid}' does not specify "
                    "trusted server names or CA certificates for the RADIUS server. "
                    "Devices will connect to any RADIUS server presenting a trusted "
                    "certificate, enabling rogue access point credential harvesting."
                ),
                severity=FindingSeverity.HIGH,
                category="profile-wifi",
                evidence=[
                    f"SSID: {ssid}",
                    "TLSTrustedServerNames: absent",
                    "PayloadCertificateAnchorUUID: absent",
                ],
                remediation=(
                    "Set TLSTrustedServerNames to the exact FQDN(s) of your "
                    "RADIUS servers, or set PayloadCertificateAnchorUUID to the "
                    "UUID of the CA certificate payload in this profile."
                ),
                cwe_id="CWE-295",
                cvss_score=7.4,
                profile_identifier=profile_id,
                profile_type=ProfileType.WIFI,
                payload_uuid=puuid,
            ))

    elif not eap_config:
        # Open or PSK Wi-Fi
        encryption = payload.get("EncryptionType", "None")
        if encryption.upper() in ("NONE", ""):
            findings.append(ProfileFinding(
                finding_id=f"IOS-WIFI-003-{puuid[:8]}",
                title=f"Open (Unencrypted) Wi-Fi Network Configured: {ssid}",
                description=(
                    f"The Wi-Fi profile configures an open network ('{ssid}') with "
                    "no encryption. All traffic on this network is visible to "
                    "adjacent wireless devices."
                ),
                severity=FindingSeverity.MEDIUM,
                category="profile-wifi",
                evidence=[f"SSID: {ssid}", f"EncryptionType: {encryption}"],
                remediation=(
                    "Remove open Wi-Fi profiles unless required for a captive "
                    "portal. Route all sensitive traffic through VPN when connecting "
                    "to unencrypted networks."
                ),
                cwe_id="CWE-311",
                profile_identifier=profile_id,
                profile_type=ProfileType.WIFI,
                payload_uuid=puuid,
            ))

    return findings


def _check_restriction_payload(payload: dict, profile_id: str, puuid: str) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []

    # forceEncryptedBackup: should be true
    if payload.get("forceEncryptedBackup") is False:
        findings.append(ProfileFinding(
            finding_id=f"IOS-RESTR-001-{puuid[:8]}",
            title="Encrypted iTunes Backup Not Enforced",
            description=(
                "The restriction profile does not enforce encrypted iTunes/Finder "
                "backups (forceEncryptedBackup = false). Unencrypted backups expose "
                "all app data, keychain items accessible to device backups, and "
                "corporate documents to anyone with access to the backup destination."
            ),
            severity=FindingSeverity.HIGH,
            category="profile-restriction",
            evidence=["forceEncryptedBackup: false"],
            remediation=(
                "Set forceEncryptedBackup to true in the restrictions payload. "
                "This forces iTunes/Finder to always encrypt device backups, "
                "protecting keychain data at rest."
            ),
            cwe_id="CWE-312",
            cvss_score=6.8,
            profile_identifier=profile_id,
            profile_type=ProfileType.RESTRICTION,
            payload_uuid=puuid,
        ))

    # allowUSBRestrictedMode should be absent or true (default true = restriction enabled)
    usb_mode = payload.get("allowUSBRestrictedMode")
    if usb_mode is False:
        findings.append(ProfileFinding(
            finding_id=f"IOS-RESTR-002-{puuid[:8]}",
            title="USB Restricted Mode Disabled by Profile",
            description=(
                "The restriction payload sets allowUSBRestrictedMode to false, "
                "disabling iOS USB Restricted Mode. This allows USB accessories "
                "and forensic tools (Cellebrite, GrayKey) to access the device "
                "data port at any time, even when the device is locked."
            ),
            severity=FindingSeverity.HIGH,
            category="profile-restriction",
            evidence=["allowUSBRestrictedMode: false"],
            remediation=(
                "Remove this key (defaults to true = restricted) or set it to true. "
                "USB Restricted Mode blocks USB data access after the device has "
                "been locked for more than one hour."
            ),
            cwe_id="CWE-284",
            cvss_score=7.3,
            profile_identifier=profile_id,
            profile_type=ProfileType.RESTRICTION,
            payload_uuid=puuid,
        ))

    # allowCloudBackup should be false on high-security deployments
    if payload.get("allowCloudBackup") is True:
        findings.append(ProfileFinding(
            finding_id=f"IOS-RESTR-003-{puuid[:8]}",
            title="iCloud Backup Permitted on Managed Device",
            description=(
                "iCloud backup is permitted. Corporate data in managed apps may "
                "be included in iCloud backups depending on app-level iCloud data "
                "protection settings and MDM-managed data classification."
            ),
            severity=FindingSeverity.MEDIUM,
            category="profile-restriction",
            evidence=["allowCloudBackup: true"],
            remediation=(
                "For high-sensitivity deployments, set allowCloudBackup to false. "
                "At minimum, ensure managed open-in controls prevent corporate "
                "documents from being backed up in personal iCloud accounts."
            ),
            cwe_id="CWE-200",
            profile_identifier=profile_id,
            profile_type=ProfileType.RESTRICTION,
            payload_uuid=puuid,
        ))

    return findings


def _check_mdm_payload(payload: dict, profile_id: str, puuid: str) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []

    server_url = str(payload.get("ServerURL", ""))
    check_in_url = str(payload.get("CheckInURL", server_url))

    if server_url.startswith("http://"):
        findings.append(ProfileFinding(
            finding_id=f"IOS-MDM-001-{puuid[:8]}",
            title="MDM Server URL Uses Plaintext HTTP",
            description=(
                f"The MDM payload CheckIn/Server URL uses HTTP: {server_url}. "
                "Device management commands, configuration profiles, and device "
                "inventory data are transmitted in cleartext."
            ),
            severity=FindingSeverity.CRITICAL,
            category="profile-mdm",
            evidence=[f"ServerURL: {server_url}"],
            remediation=(
                "Migrate the MDM server to HTTPS with a valid certificate. "
                "Apple's MDM specification requires HTTPS."
            ),
            cwe_id="CWE-319",
            cvss_score=9.1,
            profile_identifier=profile_id,
            profile_type=ProfileType.MDM,
            payload_uuid=puuid,
        ))

    # Access rights — over-privileged MDM
    access_rights = payload.get("AccessRights", 0)
    if isinstance(access_rights, int) and access_rights == 8191:
        findings.append(ProfileFinding(
            finding_id=f"IOS-MDM-002-{puuid[:8]}",
            title="MDM Profile Requests All Access Rights (8191)",
            description=(
                "The MDM payload requests all available access rights (bitmask 8191). "
                "Following least-privilege principles, the MDM should only request "
                "the specific rights needed for its management functions."
            ),
            severity=FindingSeverity.LOW,
            category="profile-mdm",
            evidence=[f"AccessRights: {access_rights} (all bits set)"],
            remediation=(
                "Review which MDM capabilities your deployment actually uses and "
                "set the AccessRights bitmask to only the required capabilities."
            ),
            profile_identifier=profile_id,
            profile_type=ProfileType.MDM,
            payload_uuid=puuid,
        ))

    return findings


def _check_profile_signing(profile: dict, profile_id: str) -> list[ProfileFinding]:
    findings: list[ProfileFinding] = []

    # Apple stores signing state externally (the .mobileconfig wrapper can be
    # a signed CMS envelope). We check the parsed dict for an explicit indicator.
    is_signed = profile.get("_SignedProfile", False)
    if not is_signed and profile.get("PayloadContent"):
        findings.append(ProfileFinding(
            finding_id=f"IOS-SIGN-001-{profile_id[:16]}",
            title="Configuration Profile Is Not Cryptographically Signed",
            description=(
                "The configuration profile has not been signed. Unsigned profiles "
                "display a warning in iOS Settings and can be trivially modified "
                "before installation. A tampered profile could install a malicious "
                "CA or VPN configuration."
            ),
            severity=FindingSeverity.MEDIUM,
            category="profile-integrity",
            evidence=[f"Profile: {profile_id}", "_SignedProfile: absent"],
            remediation=(
                "Sign configuration profiles with your MDM vendor's signing "
                "certificate or an Apple Developer certificate. Signed profiles "
                "show a verified organisation name in Settings and cannot be "
                "modified without invalidating the signature."
            ),
            cwe_id="CWE-345",
            profile_identifier=profile_id,
            profile_type=ProfileType.OTHER,
        ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Loader
# ─────────────────────────────────────────────────────────────────────────────

def _load_profile(raw) -> dict | None:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        try:
            return plistlib.loads(raw)
        except Exception as exc:
            logger.warning("Failed to parse profile bytes: %s", exc)
            return None
    if isinstance(raw, Path):
        try:
            return plistlib.loads(raw.read_bytes())
        except Exception as exc:
            logger.warning("Failed to load profile %s: %s", raw, exc)
            return None
    logger.warning("Unsupported profile type: %s", type(raw))
    return None
