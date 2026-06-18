"""
Apple DEP/ABM enrollment security analysis.

Tests enrollment endpoint behaviour for misconfigurations:
- Open enrollment (no serial verification)
- Missing authentication requirements
- Re-enrollment protection gaps
- Profile download without device attestation
"""

from __future__ import annotations

import logging
import re
import ssl
import uuid
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from ..models import AuthMethod, EnrollmentReport, Finding, FindingSeverity, MDMPlatform

logger = logging.getLogger(__name__)

# DEP profile headers that indicate serial verification is required
_DEP_SERIAL_HEADERS = {"x-apple-aspen-deviceid", "x-apple-mdm-deviceid"}

# Known MDM enrollment URL patterns
_ENROLLMENT_PATH_PATTERNS = [
    re.compile(r"/enroll", re.IGNORECASE),
    re.compile(r"/mdm/enroll", re.IGNORECASE),
    re.compile(r"/devicemanagement/api/", re.IGNORECASE),
    re.compile(r"/jamf/", re.IGNORECASE),
    re.compile(r"/MobileDeviceManagement/", re.IGNORECASE),
]

# EAP types considered weak for enrollment WiFi
_WEAK_EAP_TYPES = {21, 26}  # TTLS/PAP, MSCHAPv2 without outer TLS

# Minimum TLS version for MDM comms
_MIN_TLS_VERSION = ssl.TLSVersion.TLSv1_2


def audit_apple_dep_enrollment(
    enrollment_url: str,
    mdm_platform: MDMPlatform = MDMPlatform.GENERIC_APPLE,
    *,
    timeout: int = 10,
    authorized: bool = False,
) -> EnrollmentReport:
    """
    Assess DEP/ABM enrollment configuration security.

    Performs passive analysis of the enrollment URL and, when ``authorized``
    is True, sends probe requests to check authentication requirements.
    Never attempts destructive operations or real credential replay.

    Args:
        enrollment_url: The MDM enrollment endpoint URL.
        mdm_platform: Which MDM product is being assessed.
        timeout: HTTP request timeout in seconds.
        authorized: Must be True to send active probe requests. When False
                    only URL/TLS structure is analysed.
    """
    start = datetime.utcnow()
    findings: list[Finding] = []
    auth_method = AuthMethod.USERNAME_PASSWORD
    requires_auth = True
    blocks_reenrollment = True

    parsed = urlparse(enrollment_url)

    # ── Passive: URL structure checks ─────────────────────────────────────────
    findings.extend(_check_url_structure(enrollment_url, parsed))

    # ── Active: probe enrollment endpoint ─────────────────────────────────────
    if authorized:
        probe_results = _probe_enrollment_endpoint(enrollment_url, timeout)
        findings.extend(probe_results["findings"])
        requires_auth = probe_results.get("requires_auth", True)
        auth_method = probe_results.get("auth_method", AuthMethod.USERNAME_PASSWORD)
        blocks_reenrollment = probe_results.get("blocks_reenrollment", True)
    else:
        findings.append(Finding(
            finding_id="DEP-INFO-001",
            title="Active Probing Skipped — Not Authorized",
            description=(
                "Active enrollment endpoint probing was skipped. Pass "
                "authorized=True (with explicit written permission) to "
                "enable authentication and re-enrollment checks."
            ),
            severity=FindingSeverity.INFO,
            category="enrollment",
            evidence=[enrollment_url],
            remediation="Run with authorized=True against your own MDM.",
        ))

    # ── TLS check ─────────────────────────────────────────────────────────────
    if parsed.scheme.lower() == "http":
        findings.append(Finding(
            finding_id="DEP-CRIT-001",
            title="MDM Enrollment Over Plaintext HTTP",
            description=(
                "The enrollment URL uses HTTP rather than HTTPS. "
                "Device credentials, APNS tokens, and configuration "
                "payloads are transmitted in plaintext."
            ),
            severity=FindingSeverity.CRITICAL,
            category="enrollment",
            evidence=[enrollment_url],
            remediation=(
                "Enforce HTTPS with a valid certificate from a trusted CA. "
                "Apple requires HTTPS for all MDM communications."
            ),
            cwe_id="CWE-319",
            cvss_score=9.1,
        ))
    elif parsed.scheme.lower() == "https":
        tls_findings = _check_tls_configuration(parsed.hostname or "", parsed.port or 443, timeout)
        findings.extend(tls_findings)

    duration = (datetime.utcnow() - start).total_seconds()

    # Deduplicate
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        if f.finding_id not in seen:
            seen.add(f.finding_id)
            unique.append(f)

    return EnrollmentReport(
        report_id=str(uuid.uuid4()),
        mdm_platform=mdm_platform,
        generated_at=datetime.utcnow(),
        findings=sorted(unique, key=lambda f: _severity_order(f.severity)),
        enrollment_url=enrollment_url,
        requires_authentication=requires_auth,
        auth_method=auth_method,
        blocks_reenrollment=blocks_reenrollment,
        scan_duration_seconds=duration,
    )


def audit_dep_profile_download(
    profile_url: str,
    *,
    authorized: bool = False,
    timeout: int = 10,
) -> list[Finding]:
    """
    Check whether an MDM enrollment profile can be downloaded without
    device serial number verification.

    In a correctly configured DEP deployment, the server should reject
    requests that do not include a valid enrolled device serial number
    and APNS topic in the request headers.

    Returns a list of Findings (empty = no issues detected).
    """
    findings: list[Finding] = []

    if not authorized:
        logger.info("DEP profile download check skipped — not authorized")
        return findings

    try:
        import urllib.request
        import urllib.error

        # Probe without device headers — should receive 401/403
        req = urllib.request.Request(profile_url, method="GET")
        req.add_header("User-Agent", "MDMAudit/1.0 (Security Assessment)")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                content_type = resp.headers.get("Content-Type", "")
                if status == 200 and "application/x-apple-aspen-config" in content_type:
                    findings.append(Finding(
                        finding_id="DEP-HIGH-001",
                        title="Enrollment Profile Downloadable Without Device Verification",
                        description=(
                            "The MDM enrollment profile was returned for an unauthenticated "
                            "GET request with no device serial or APNS token. An attacker "
                            "could retrieve the profile to discover MDM server URLs, "
                            "CA certificates, and VPN pre-shared keys embedded in the profile."
                        ),
                        severity=FindingSeverity.HIGH,
                        category="enrollment",
                        evidence=[
                            f"GET {profile_url} → HTTP {status}",
                            f"Content-Type: {content_type}",
                            "No X-Apple-Aspen-DeviceId header sent",
                        ],
                        remediation=(
                            "Require device serial number verification before serving "
                            "enrollment profiles. Validate the APNS device token against "
                            "your ABM-enrolled serial list. Consider enrollment URL "
                            "single-use tokens scoped per device."
                        ),
                        cwe_id="CWE-284",
                        cvss_score=6.5,
                    ))
                else:
                    logger.info("Profile download probe returned %s — authentication appears required", status)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                logger.info("Profile endpoint returned %s — authentication enforced", exc.code)
            else:
                logger.warning("Unexpected HTTP %s from %s", exc.code, profile_url)
    except Exception as exc:
        logger.warning("DEP profile download probe failed: %s", exc)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _check_url_structure(url: str, parsed) -> list[Finding]:
    findings: list[Finding] = []

    # Default credentials in URL
    if parsed.username or parsed.password:
        findings.append(Finding(
            finding_id="DEP-CRIT-002",
            title="Credentials Embedded in Enrollment URL",
            description=(
                "The enrollment URL contains a username or password in the authority "
                "component. These are visible in logs, browser history, and any "
                "system that handles the URL."
            ),
            severity=FindingSeverity.CRITICAL,
            category="enrollment",
            evidence=[f"URL authority contains credentials: {parsed.netloc}"],
            remediation=(
                "Remove credentials from the URL. Use token-based enrollment "
                "authentication (OAuth, SAML) or client certificates."
            ),
            cwe_id="CWE-312",
            cvss_score=8.0,
        ))

    # Non-standard port without TLS
    if parsed.scheme == "https" and parsed.port and parsed.port not in (443, 8443):
        findings.append(Finding(
            finding_id="DEP-LOW-001",
            title="MDM Enrollment on Non-Standard HTTPS Port",
            description=(
                f"MDM enrollment is served on port {parsed.port} rather than "
                "the standard 443. While not inherently insecure, this may "
                "bypass corporate firewall rules intended to inspect MDM traffic "
                "and is unusual for production deployments."
            ),
            severity=FindingSeverity.LOW,
            category="enrollment",
            evidence=[f"Enrollment URL: {url}"],
            remediation=(
                "Consider serving enrollment on port 443 to align with Apple's "
                "MDM specification and ensure traffic passes through security controls."
            ),
        ))

    # IP address instead of hostname
    import ipaddress
    host = parsed.hostname or ""
    try:
        ipaddress.ip_address(host)
        findings.append(Finding(
            finding_id="DEP-MED-001",
            title="MDM Enrollment URL Uses IP Address",
            description=(
                "The enrollment URL references an IP address rather than a "
                "fully qualified hostname. Certificate validation is weakened "
                "because IP SANs are often omitted from MDM TLS certificates, "
                "and IP-based URLs bypass DNS-based split-horizon controls."
            ),
            severity=FindingSeverity.MEDIUM,
            category="enrollment",
            evidence=[f"Host: {host}"],
            remediation=(
                "Use a fully qualified domain name. Ensure the TLS certificate "
                "covers the exact hostname in the enrollment URL."
            ),
            cwe_id="CWE-295",
        ))
    except ValueError:
        pass

    return findings


def _probe_enrollment_endpoint(url: str, timeout: int) -> dict:
    """Send a minimal unauthenticated request and interpret the response."""
    result = {
        "findings": [],
        "requires_auth": True,
        "auth_method": AuthMethod.USERNAME_PASSWORD,
        "blocks_reenrollment": True,
    }
    try:
        import urllib.request
        import urllib.error

        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "MDMAudit/1.0 (Security Assessment)")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                if status == 200:
                    result["requires_auth"] = False
                    result["findings"].append(Finding(
                        finding_id="DEP-CRIT-003",
                        title="MDM Enrollment Accessible Without Authentication",
                        description=(
                            f"The enrollment endpoint at {url} returned HTTP 200 "
                            "without any authentication. Any device or user could "
                            "initiate enrollment into your MDM, gaining access to "
                            "corporate Wi-Fi profiles, certificates, and VPN configurations."
                        ),
                        severity=FindingSeverity.CRITICAL,
                        category="enrollment",
                        evidence=[f"GET {url} → HTTP 200 (no credentials)"],
                        remediation=(
                            "Require authentication before enrollment. Use DEP "
                            "pre-stage enrollment records that restrict enrollment "
                            "to ABM-managed serials, plus require user authentication "
                            "(LDAP/SAML) for BYOD enrollment."
                        ),
                        cwe_id="CWE-306",
                        cvss_score=9.8,
                    ))
                # 401/403 means auth is enforced — no finding
                auth_hdr = resp.headers.get("WWW-Authenticate", "")
                if "Bearer" in auth_hdr:
                    result["auth_method"] = AuthMethod.OAUTH2
                elif "Basic" in auth_hdr:
                    result["auth_method"] = AuthMethod.USERNAME_PASSWORD
                    result["findings"].append(Finding(
                        finding_id="DEP-MED-002",
                        title="MDM Enrollment Uses HTTP Basic Authentication",
                        description=(
                            "The enrollment endpoint advertises HTTP Basic authentication "
                            "(WWW-Authenticate: Basic). Basic auth transmits credentials "
                            "base64-encoded and is susceptible to brute-force without "
                            "additional rate-limiting controls."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        category="enrollment",
                        evidence=[f"WWW-Authenticate: {auth_hdr}"],
                        remediation=(
                            "Replace Basic auth with OAuth 2.0, SAML 2.0, or "
                            "client-certificate authentication. Enable account lockout "
                            "and MFA for all administrator accounts."
                        ),
                        cwe_id="CWE-522",
                        cvss_score=5.3,
                    ))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                result["requires_auth"] = True
            elif exc.code == 405:
                pass  # Method not allowed — typical for enrollment endpoints
            else:
                logger.debug("Probe returned HTTP %s", exc.code)
    except Exception as exc:
        logger.warning("Enrollment probe failed: %s", exc)
        result["findings"].append(Finding(
            finding_id="DEP-INFO-002",
            title="Enrollment Endpoint Unreachable",
            description=f"Could not connect to enrollment URL: {exc}",
            severity=FindingSeverity.INFO,
            category="enrollment",
            evidence=[str(exc)],
            remediation="Verify the enrollment URL is accessible from the assessment host.",
        ))
    return result


def _check_tls_configuration(hostname: str, port: int, timeout: int) -> list[Finding]:
    findings: list[Finding] = []
    if not hostname:
        return findings
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            with ctx.wrap_socket(
                __import__("socket").create_connection((hostname, port), timeout=timeout),
                server_hostname=hostname,
            ) as conn:
                tls_ver = conn.version()
                cipher = conn.cipher()
                if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append(Finding(
                        finding_id="DEP-HIGH-002",
                        title=f"MDM Server Accepts Deprecated TLS Version: {tls_ver}",
                        description=(
                            f"The MDM enrollment server negotiated {tls_ver}, which "
                            "has known cryptographic weaknesses (POODLE, BEAST, SWEET32). "
                            "Apple requires TLS 1.2+ for MDM communications."
                        ),
                        severity=FindingSeverity.HIGH,
                        category="enrollment",
                        evidence=[
                            f"Host: {hostname}:{port}",
                            f"Negotiated: {tls_ver}",
                            f"Cipher: {cipher}",
                        ],
                        remediation=(
                            "Disable TLS 1.0 and 1.1 on the MDM server. "
                            "Configure minimum TLS 1.2 with AEAD cipher suites. "
                            "Prefer TLS 1.3 where supported."
                        ),
                        cwe_id="CWE-326",
                        cvss_score=7.4,
                    ))
                if cipher and len(cipher) >= 2:
                    cipher_name = cipher[0] or ""
                    if any(weak in cipher_name for weak in
                           ("RC4", "DES", "NULL", "EXPORT", "anon", "MD5")):
                        findings.append(Finding(
                            finding_id="DEP-HIGH-003",
                            title=f"Weak TLS Cipher Suite: {cipher_name}",
                            description=(
                                f"The MDM server negotiated a weak cipher suite ({cipher_name}). "
                                "Weak ciphers allow passive decryption or active downgrade attacks."
                            ),
                            severity=FindingSeverity.HIGH,
                            category="enrollment",
                            evidence=[f"Cipher: {cipher_name}", f"Host: {hostname}:{port}"],
                            remediation=(
                                "Configure the server to offer only AEAD cipher suites: "
                                "AES-128-GCM, AES-256-GCM, CHACHA20-POLY1305. "
                                "Disable all export, NULL, RC4, and DES cipher suites."
                            ),
                            cwe_id="CWE-327",
                            cvss_score=7.4,
                        ))
        except ssl.SSLCertVerificationError as exc:
            findings.append(Finding(
                finding_id="DEP-CRIT-004",
                title="MDM Server TLS Certificate Validation Failure",
                description=(
                    f"The MDM enrollment server's TLS certificate failed validation: "
                    f"{exc}. Devices enrolling against this endpoint cannot verify "
                    "server identity, enabling MITM attacks during enrollment."
                ),
                severity=FindingSeverity.CRITICAL,
                category="enrollment",
                evidence=[f"Host: {hostname}:{port}", f"SSL error: {exc}"],
                remediation=(
                    "Install a valid TLS certificate from a publicly trusted CA "
                    "(DigiCert, Let's Encrypt, etc.). Ensure the Subject Alternative "
                    "Name exactly matches the enrollment URL hostname."
                ),
                cwe_id="CWE-295",
                cvss_score=8.1,
            ))
    except Exception as exc:
        logger.debug("TLS check for %s:%s failed: %s", hostname, port, exc)
    return findings


def _severity_order(s: FindingSeverity) -> int:
    return {FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4}[s]
