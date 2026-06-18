"""
MDM API security assessment.

Tests MDM management API endpoints for authentication strength, TLS
configuration, rate-limiting presence, authorization boundaries, and
common injection surfaces.

All active probing requires explicit authorization=True. Tests are
non-destructive: they detect the presence or absence of security controls
without attempting to exploit or alter data.
"""

from __future__ import annotations

import logging
import re
import ssl
import time
import uuid
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin, urlparse

from ..models import APIFinding, APISecurityReport, AuthMethod, FindingSeverity

logger = logging.getLogger(__name__)

# HTTP headers that suggest rate-limiting is in effect
_RATE_LIMIT_HEADERS = {
    "x-ratelimit-limit", "x-rate-limit-limit",
    "x-ratelimit-remaining", "x-rate-limit-remaining",
    "retry-after", "ratelimit-limit",
}

# Security headers that should be present on MDM APIs
_EXPECTED_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set — forces HTTPS upgrade",
    "x-content-type-options": "X-Content-Type-Options missing — MIME sniffing possible",
    "x-frame-options": "X-Frame-Options missing — clickjacking risk",
    "content-security-policy": "Content-Security-Policy absent",
}

# Patterns in responses that suggest server-side injection surface
_INJECTION_REFLECTION_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),            # XSS reflection
    re.compile(r"syntax error", re.IGNORECASE),        # SQL error
    re.compile(r"ORA-\d{5}", re.IGNORECASE),           # Oracle SQL error
    re.compile(r"com\.mysql\.jdbc", re.IGNORECASE),    # MySQL JDBC error
    re.compile(r"javax\.xml\.", re.IGNORECASE),         # XXE/XML class leak
    re.compile(r"ENTITY", re.IGNORECASE),              # XML entity expansion
    re.compile(r"stack trace", re.IGNORECASE),          # Verbose error
    re.compile(r"at [a-z]+\.[a-z]+\.[A-Z]", re.IGNORECASE),  # Java stack frame
]

# Benign payloads for injection surface detection (non-exploiting)
_INJECTION_PROBES = {
    "sql_comment": "--",
    "xml_entity_ref": "&amp;",
    "script_tag": "<b>mdmaudit</b>",
}


def assess_mdm_api(
    endpoint: str,
    *,
    authorized: bool = False,
    timeout: int = 10,
    api_token: str = "",
    check_cross_device: bool = False,
    device_ids: Optional[list[str]] = None,
) -> APISecurityReport:
    """
    Assess the security of an MDM management API endpoint.

    Args:
        endpoint: Base URL of the MDM management API.
        authorized: Must be True to send active probe requests. Requires
                    written authorisation from the system owner.
        timeout: HTTP request timeout.
        api_token: Optional bearer token for authenticated checks.
        check_cross_device: If True and authorized, test whether one
                            device's token can access another device's data.
        device_ids: List of known device IDs for cross-device checks.
    """
    start = datetime.utcnow()
    findings: list[APIFinding] = []
    tls_version = "unknown"
    tls_ciphers: list[str] = []
    supports_pinning = False
    has_rate_limiting = False
    auth_method = AuthMethod.API_KEY

    parsed = urlparse(endpoint)

    # ── TLS / transport check (passive) ───────────────────────────────────────
    if parsed.scheme == "https":
        tls_info = _check_tls(parsed.hostname or "", parsed.port or 443, timeout)
        tls_version = tls_info["version"]
        tls_ciphers = tls_info["ciphers"]
        findings.extend(tls_info["findings"])
    elif parsed.scheme == "http":
        findings.append(APIFinding(
            finding_id="API-CRIT-001",
            title="MDM Management API Served Over Plaintext HTTP",
            description=(
                "The MDM management API uses HTTP. Management commands, device "
                "inventories, and admin credentials transit the network unencrypted."
            ),
            severity=FindingSeverity.CRITICAL,
            category="api-transport",
            evidence=[f"Endpoint: {endpoint}"],
            remediation="Enforce HTTPS with TLS 1.2+ for all management API traffic.",
            cwe_id="CWE-319",
            cvss_score=9.1,
            endpoint=endpoint,
        ))

    if not authorized:
        findings.append(APIFinding(
            finding_id="API-INFO-001",
            title="Active API Probing Skipped — Not Authorized",
            description=(
                "Authentication, rate-limiting, authorization boundary, and "
                "injection surface checks require authorized=True with explicit "
                "written permission from the system owner."
            ),
            severity=FindingSeverity.INFO,
            category="api-auth",
            evidence=[endpoint],
            remediation="Run with authorized=True against your own MDM deployment.",
            endpoint=endpoint,
        ))
    else:
        # ── Authentication strength ────────────────────────────────────────────
        auth_results = _check_authentication(endpoint, timeout)
        findings.extend(auth_results["findings"])
        auth_method = auth_results["auth_method"]
        has_rate_limiting = auth_results["has_rate_limiting"]

        # ── Security headers ───────────────────────────────────────────────────
        header_findings = _check_security_headers(endpoint, api_token, timeout)
        findings.extend(header_findings)

        # ── Authorization boundaries ───────────────────────────────────────────
        if check_cross_device and device_ids and api_token:
            auth_boundary_findings = _check_authorization_boundaries(
                endpoint, api_token, device_ids, timeout
            )
            findings.extend(auth_boundary_findings)

        # ── Injection surface detection ────────────────────────────────────────
        injection_findings = _check_injection_surfaces(endpoint, api_token, timeout)
        findings.extend(injection_findings)

    duration = (datetime.utcnow() - start).total_seconds()

    # Deduplicate + sort
    seen: set[str] = set()
    unique: list[APIFinding] = []
    for f in sorted(findings, key=lambda x: _severity_order(x.severity)):
        if f.finding_id not in seen:
            seen.add(f.finding_id)
            unique.append(f)

    return APISecurityReport(
        report_id=str(uuid.uuid4()),
        endpoint=endpoint,
        generated_at=datetime.utcnow(),
        tls_version=tls_version,
        tls_ciphers=tls_ciphers,
        supports_certificate_pinning=supports_pinning,
        has_rate_limiting=has_rate_limiting,
        auth_method=auth_method,
        findings=unique,
        scan_duration_seconds=duration,
    )


# ─────────────────────────────────────────────────────────────────────────────
# TLS checks
# ─────────────────────────────────────────────────────────────────────────────

def _check_tls(hostname: str, port: int, timeout: int) -> dict:
    result: dict = {"version": "unknown", "ciphers": [], "findings": []}
    if not hostname:
        return result
    try:
        import socket
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=timeout),
            server_hostname=hostname,
        ) as conn:
            result["version"] = conn.version() or "unknown"
            cipher_info = conn.cipher()
            if cipher_info:
                result["ciphers"] = [cipher_info[0]]

            if result["version"] in ("TLSv1", "TLSv1.1"):
                result["findings"].append(APIFinding(
                    finding_id="API-TLS-001",
                    title=f"MDM API Accepts Deprecated TLS: {result['version']}",
                    description=(
                        f"The MDM API server accepted a connection with "
                        f"{result['version']}, which is deprecated and has known "
                        "weaknesses. Apple and Google require TLS 1.2+ for MDM."
                    ),
                    severity=FindingSeverity.HIGH,
                    category="api-transport",
                    evidence=[
                        f"Host: {hostname}:{port}",
                        f"TLS version: {result['version']}",
                    ],
                    remediation=(
                        "Disable TLS 1.0 and 1.1 on the MDM server. "
                        "Require TLS 1.2 minimum with AEAD cipher suites."
                    ),
                    cwe_id="CWE-326",
                    cvss_score=7.4,
                    endpoint=f"{hostname}:{port}",
                ))

            cipher_name = cipher_info[0] if cipher_info else ""
            if any(w in cipher_name for w in ("RC4", "DES", "NULL", "EXPORT", "anon")):
                result["findings"].append(APIFinding(
                    finding_id="API-TLS-002",
                    title=f"Weak TLS Cipher Suite: {cipher_name}",
                    description=(
                        f"Weak cipher suite '{cipher_name}' negotiated on MDM API. "
                        "Weak ciphers enable traffic decryption or downgrade attacks."
                    ),
                    severity=FindingSeverity.HIGH,
                    category="api-transport",
                    evidence=[f"Cipher: {cipher_name}"],
                    remediation=(
                        "Allow only AEAD cipher suites: AES-GCM, CHACHA20-POLY1305. "
                        "Disable RC4, DES, NULL, and export cipher suites."
                    ),
                    cwe_id="CWE-327",
                    cvss_score=7.4,
                    endpoint=f"{hostname}:{port}",
                ))

    except ssl.SSLCertVerificationError as exc:
        result["findings"].append(APIFinding(
            finding_id="API-TLS-003",
            title="MDM API TLS Certificate Invalid",
            description=(
                f"The MDM API server's certificate failed validation: {exc}. "
                "MDM clients cannot verify server identity, enabling MITM attacks."
            ),
            severity=FindingSeverity.CRITICAL,
            category="api-transport",
            evidence=[str(exc)],
            remediation=(
                "Install a valid TLS certificate from a trusted CA. "
                "Ensure the CN/SAN matches the API hostname exactly."
            ),
            cwe_id="CWE-295",
            cvss_score=8.1,
            endpoint=f"{hostname}:{port}",
        ))
    except Exception as exc:
        logger.debug("TLS check failed for %s:%s — %s", hostname, port, exc)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Authentication checks
# ─────────────────────────────────────────────────────────────────────────────

def _check_authentication(endpoint: str, timeout: int) -> dict:
    """
    Probe authentication requirements on the MDM API.

    Sends at most 3 unauthenticated requests and checks for:
    - Whether the endpoint requires authentication at all
    - Whether HTTP Basic auth is advertised (weaker than token/OAuth)
    - Whether rate-limiting headers appear after failed attempts
    """
    result = {
        "findings": [],
        "auth_method": AuthMethod.USERNAME_PASSWORD,
        "has_rate_limiting": False,
    }

    try:
        import urllib.request
        import urllib.error

        # First probe: unauthenticated GET
        req = urllib.request.Request(endpoint, method="GET")
        req.add_header("User-Agent", "MDMAudit/1.0 (Security Assessment)")
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    result["findings"].append(APIFinding(
                        finding_id="API-AUTH-001",
                        title="MDM API Accessible Without Authentication",
                        description=(
                            f"GET {endpoint} returned HTTP 200 without credentials. "
                            "Unauthenticated access to MDM management APIs exposes "
                            "device inventories, profiles, and management commands."
                        ),
                        severity=FindingSeverity.CRITICAL,
                        category="api-auth",
                        evidence=[f"GET {endpoint} → HTTP 200 (no credentials)"],
                        remediation=(
                            "Require authentication on all management API endpoints. "
                            "Use OAuth 2.0, API keys with IP allowlisting, or "
                            "mutual TLS for service-to-service authentication."
                        ),
                        cwe_id="CWE-306",
                        cvss_score=9.8,
                        endpoint=endpoint,
                        http_method="GET",
                    ))
                auth_hdr = resp.headers.get("WWW-Authenticate", "")
                rl_headers = {h.lower() for h in resp.headers.keys()}
                result["has_rate_limiting"] = bool(rl_headers & _RATE_LIMIT_HEADERS)
                _update_auth_method(result, auth_hdr)

        except urllib.error.HTTPError as exc:
            auth_hdr = exc.headers.get("WWW-Authenticate", "") if exc.headers else ""
            rl_headers = {h.lower() for h in exc.headers.keys()} if exc.headers else set()
            result["has_rate_limiting"] = bool(rl_headers & _RATE_LIMIT_HEADERS)
            _update_auth_method(result, auth_hdr)

            if "Basic" in auth_hdr:
                result["findings"].append(APIFinding(
                    finding_id="API-AUTH-002",
                    title="MDM API Advertises HTTP Basic Authentication",
                    description=(
                        "The API's WWW-Authenticate header advertises HTTP Basic "
                        "authentication. Basic auth sends credentials as base64 "
                        "(easily decoded) and provides no protection against "
                        "credential replay without additional controls."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    category="api-auth",
                    evidence=[f"WWW-Authenticate: {auth_hdr}"],
                    remediation=(
                        "Replace Basic auth with OAuth 2.0 Bearer tokens or API "
                        "keys paired with IP allowlisting. Enforce MFA for all "
                        "MDM administrator accounts."
                    ),
                    cwe_id="CWE-522",
                    cvss_score=5.3,
                    endpoint=endpoint,
                ))

        # Check for rate limiting: two sequential failed attempts
        if not result["has_rate_limiting"]:
            for _ in range(2):
                try:
                    bad_req = urllib.request.Request(endpoint, method="GET")
                    bad_req.add_header("Authorization", "Bearer INVALID_TOKEN_MDMAUDIT")
                    bad_req.add_header("User-Agent", "MDMAudit/1.0 (Security Assessment)")
                    with urllib.request.urlopen(bad_req, timeout=timeout) as r:
                        rl_hdrs = {h.lower() for h in r.headers.keys()}
                        if rl_hdrs & _RATE_LIMIT_HEADERS:
                            result["has_rate_limiting"] = True
                            break
                except urllib.error.HTTPError as exc:
                    if exc.code == 429:
                        result["has_rate_limiting"] = True
                        break
                    rl_hdrs = {h.lower() for h in exc.headers.keys()} if exc.headers else set()
                    if rl_hdrs & _RATE_LIMIT_HEADERS:
                        result["has_rate_limiting"] = True
                        break
                except Exception:
                    break
                time.sleep(0.5)

            if not result["has_rate_limiting"]:
                result["findings"].append(APIFinding(
                    finding_id="API-AUTH-003",
                    title="No Rate-Limiting Detected on MDM API Authentication",
                    description=(
                        "Sequential authentication attempts received no rate-limiting "
                        "response (HTTP 429 or rate-limit headers). Without rate-limiting, "
                        "the authentication endpoint is susceptible to credential "
                        "stuffing and password spray attacks."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    category="api-auth",
                    evidence=[
                        f"Endpoint: {endpoint}",
                        "No X-RateLimit-* or Retry-After headers observed",
                        "No HTTP 429 response received",
                    ],
                    remediation=(
                        "Implement per-IP and per-account rate-limiting on the "
                        "authentication endpoint. Lock accounts after 10 failed "
                        "attempts. Consider adaptive MFA triggers on unusual "
                        "access patterns."
                    ),
                    cwe_id="CWE-307",
                    cvss_score=6.5,
                    endpoint=endpoint,
                ))

    except Exception as exc:
        logger.warning("Auth check failed for %s: %s", endpoint, exc)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Security header checks
# ─────────────────────────────────────────────────────────────────────────────

def _check_security_headers(endpoint: str, token: str, timeout: int) -> list[APIFinding]:
    findings: list[APIFinding] = []
    try:
        import urllib.request
        import urllib.error

        req = urllib.request.Request(endpoint, method="GET")
        req.add_header("User-Agent", "MDMAudit/1.0 (Security Assessment)")
        if token:
            req.add_header("Authorization", f"Bearer {token}")

        try:
            resp_headers = {}
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    resp_headers = {h.lower(): v for h, v in resp.headers.items()}
            except urllib.error.HTTPError as exc:
                if exc.headers:
                    resp_headers = {h.lower(): v for h, v in exc.headers.items()}

            for header, description in _EXPECTED_SECURITY_HEADERS.items():
                if header not in resp_headers:
                    if header == "content-security-policy":
                        severity = FindingSeverity.LOW
                    elif header == "strict-transport-security":
                        severity = FindingSeverity.MEDIUM
                    else:
                        severity = FindingSeverity.LOW

                    findings.append(APIFinding(
                        finding_id=f"API-HDR-{header[:16].upper().replace('-', '_')}",
                        title=f"Missing Security Header: {header}",
                        description=description,
                        severity=severity,
                        category="api-headers",
                        evidence=[f"Header '{header}' absent from response"],
                        remediation=f"Add the '{header}' response header with an appropriate value.",
                        endpoint=endpoint,
                    ))

            # HSTS max-age check
            hsts = resp_headers.get("strict-transport-security", "")
            if hsts:
                import re as _re
                m = _re.search(r"max-age=(\d+)", hsts)
                if m and int(m.group(1)) < 31536000:  # less than 1 year
                    findings.append(APIFinding(
                        finding_id="API-HDR-HSTS_SHORT",
                        title="HSTS max-age Below Recommended 1 Year",
                        description=(
                            f"Strict-Transport-Security max-age is {m.group(1)} seconds "
                            "(<1 year). Short HSTS lifetimes leave gaps after cache expiry."
                        ),
                        severity=FindingSeverity.LOW,
                        category="api-headers",
                        evidence=[f"Strict-Transport-Security: {hsts}"],
                        remediation="Set max-age=31536000 (1 year) or higher. Include 'includeSubDomains'.",
                        endpoint=endpoint,
                    ))

        except Exception as exc:
            logger.debug("Header check error: %s", exc)
    except Exception as exc:
        logger.warning("Security header check failed: %s", exc)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Authorization boundary checks
# ─────────────────────────────────────────────────────────────────────────────

def _check_authorization_boundaries(
    endpoint: str,
    token: str,
    device_ids: list[str],
    timeout: int,
) -> list[APIFinding]:
    """
    Test whether a device token can access another device's management data.

    Uses only the first two device IDs: token from device[0], access attempt
    to device[1]'s data. Non-destructive — only performs GET requests.
    """
    findings: list[APIFinding] = []
    if len(device_ids) < 2:
        return findings

    import urllib.request
    import urllib.error

    device_url = urljoin(endpoint.rstrip("/") + "/", f"devices/{device_ids[1]}")
    req = urllib.request.Request(device_url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("User-Agent", "MDMAudit/1.0 (Security Assessment)")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                findings.append(APIFinding(
                    finding_id="API-AUTHZ-001",
                    title="Cross-Device Data Access: IDOR Vulnerability",
                    description=(
                        f"A token from device '{device_ids[0]}' was able to access "
                        f"the management record for device '{device_ids[1]}' at "
                        f"{device_url}. This Insecure Direct Object Reference (IDOR) "
                        "allows any enrolled device to read or modify any other "
                        "device's configuration."
                    ),
                    severity=FindingSeverity.CRITICAL,
                    category="api-authorization",
                    evidence=[
                        f"Token device: {device_ids[0]}",
                        f"Accessed device: {device_ids[1]}",
                        f"URL: {device_url} → HTTP 200",
                    ],
                    remediation=(
                        "Enforce object-level authorization on all device management "
                        "endpoints. Verify that the authenticated device/user identity "
                        "matches the requested resource. Implement server-side "
                        "authorization checks — never rely on client-supplied identifiers."
                    ),
                    cwe_id="CWE-639",
                    cvss_score=9.1,
                    endpoint=device_url,
                    http_method="GET",
                ))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            logger.info("Cross-device access correctly denied: HTTP %s", exc.code)
        else:
            logger.debug("Cross-device check returned HTTP %s", exc.code)
    except Exception as exc:
        logger.debug("Cross-device check failed: %s", exc)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Injection surface detection
# ─────────────────────────────────────────────────────────────────────────────

def _check_injection_surfaces(endpoint: str, token: str, timeout: int) -> list[APIFinding]:
    """
    Send benign probe values via query parameters and check whether they
    appear verbatim in responses (reflection) or trigger error messages
    that suggest SQL/XML injection surfaces.

    This is detection-only: no exploitation, no data modification.
    """
    findings: list[APIFinding] = []
    import urllib.request
    import urllib.error
    from urllib.parse import urlencode

    probe_url = endpoint.rstrip("/") + "/devices?" + urlencode({"search": _INJECTION_PROBES["sql_comment"]})
    req = urllib.request.Request(probe_url, method="GET")
    req.add_header("User-Agent", "MDMAudit/1.0 (Security Assessment)")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        body = b""
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(4096)
        except urllib.error.HTTPError as exc:
            body = exc.read(4096) if exc.fp else b""

        body_text = body.decode("utf-8", errors="replace")
        for pattern in _INJECTION_REFLECTION_PATTERNS:
            if pattern.search(body_text):
                findings.append(APIFinding(
                    finding_id="API-INJECT-001",
                    title="Possible Injection Surface: Error/Reflection Detected",
                    description=(
                        f"A benign probe to {probe_url} produced a response matching "
                        f"a pattern associated with injection vulnerabilities "
                        f"(pattern: {pattern.pattern!r}). This warrants manual "
                        "investigation with authorised penetration testing."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    category="api-injection",
                    evidence=[
                        f"Probe URL: {probe_url}",
                        f"Response pattern match: {pattern.pattern}",
                        f"Response snippet: {body_text[:200]}",
                    ],
                    remediation=(
                        "Audit all API parameters for injection vulnerabilities. "
                        "Use parameterised queries, XML schema validation, and "
                        "output encoding. Ensure error messages do not leak "
                        "implementation details to clients."
                    ),
                    cwe_id="CWE-74",
                    cvss_score=6.5,
                    endpoint=probe_url,
                    http_method="GET",
                    parameter="search",
                ))
                break  # One finding per probe is sufficient
    except Exception as exc:
        logger.debug("Injection probe failed: %s", exc)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _update_auth_method(result: dict, auth_hdr: str) -> None:
    if "Bearer" in auth_hdr:
        result["auth_method"] = AuthMethod.OAUTH2
    elif "Basic" in auth_hdr:
        result["auth_method"] = AuthMethod.USERNAME_PASSWORD
    elif "SAML" in auth_hdr.upper():
        result["auth_method"] = AuthMethod.SAML


def _severity_order(s: FindingSeverity) -> int:
    return {FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4}[s]
