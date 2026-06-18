"""
Automated vulnerability detection via runtime observation.

Analyses TraceSession events and live ADB/lockdown data to surface
OWASP MASVS findings with severity and remediation guidance.
"""

from __future__ import annotations

import re
import uuid
import logging
from datetime import datetime
from typing import Any

from ..models import (
    Platform,
    Severity,
    TargetApp,
    TraceCategory,
    TraceEvent,
    TraceSession,
    Vulnerability,
    VulnReport,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Secret / credential patterns for memory / log scanning
# ─────────────────────────────────────────────────────────────────────────────
SECRET_PATTERNS: dict[str, re.Pattern] = {
    "AWS Access Key":      re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret":          re.compile(r"['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Google API Key":      re.compile(r"AIza[0-9A-Za-z_-]{25,40}"),
    "JWT Token":           re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "Private Key (PEM)":   re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
    "Generic Password":    re.compile(
        r"(?i)(password|passwd|secret|api_key|apikey|token)['\"]?\s*[:=]\s*['\"]([^'\"]{6,})['\"]"
    ),
    "Bearer Token":        re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}"),
    "Stripe Key":          re.compile(r"(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}"),
    "SendGrid Key":        re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    "Slack Token":         re.compile(r"xox[baprs]-[0-9]{10,}-[0-9a-zA-Z]{10,}"),
}

# SharedPreferences / SQLite field names that suggest sensitive plaintext storage
SENSITIVE_FIELD_PATTERNS = [
    re.compile(r"(?i)(password|passwd|secret|token|key|credential|auth|pin|cvv|ssn)"),
]

# Plaintext HTTP (not HTTPS)
HTTP_PATTERN = re.compile(r"^http://", re.IGNORECASE)

# Algorithms that indicate weak crypto
WEAK_CRYPTO_ALGOS = {
    "DES", "RC2", "RC4", "MD5", "SHA1", "ECB",
    "DES/ECB", "AES/ECB", "DES/CBC",  # ECB mode regardless of cipher
}


class VulnerabilityScanner:
    """
    Analyses a completed (or live) TraceSession for OWASP MASVS vulnerabilities.
    Also accepts raw evidence strings for supplemental checks (e.g. memory scan results).
    """

    def __init__(self, app: TargetApp, trace: TraceSession | None = None):
        self.app = app
        self.trace = trace
        self._vulns: list[Vulnerability] = []

    def scan(self) -> VulnReport:
        start = datetime.utcnow()

        if self.trace:
            self._check_insecure_storage()
            self._check_weak_crypto()
            self._check_cleartext_network()
            self._check_debug_artifacts()
            self._check_biometric_bypass_risk()
            self._check_hardcoded_secrets_in_trace()

        report = VulnReport(
            report_id=str(uuid.uuid4()),
            app=self.app,
            generated_at=datetime.utcnow(),
            vulnerabilities=self._vulns,
            scan_duration_seconds=(datetime.utcnow() - start).total_seconds(),
        )
        # Sort: CRITICAL → INFO
        _order = {Severity.CRITICAL: 0, Severity.HIGH: 1,
                  Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        report.vulnerabilities.sort(key=lambda v: (_order[v.severity], v.title))
        return report

    # ------------------------------------------------------------------
    # Supplemental entry point for memory / static evidence
    # ------------------------------------------------------------------

    def add_memory_scan_results(self, memory_chunks: list[str]) -> None:
        """Feed raw memory strings for secret pattern matching."""
        for chunk in memory_chunks:
            self._check_chunk_for_secrets(chunk)

    # ------------------------------------------------------------------
    # Check implementations
    # ------------------------------------------------------------------

    def _check_insecure_storage(self) -> None:
        if not self.trace:
            return
        evidence: list[str] = []
        for ev in self.trace.events_by_category(TraceCategory.FILESYSTEM):
            args = ev.args if isinstance(ev.args, dict) else {}

            # SQLite raw queries that INSERT sensitive field names
            sql = str(args.get("sql", ""))
            if any(p.search(sql) for p in SENSITIVE_FIELD_PATTERNS):
                evidence.append(f"SQLite: {sql[:120]}")

            # SharedPreferences putString with sensitive key
            key = str(args.get("key", ""))
            if any(p.search(key) for p in SENSITIVE_FIELD_PATTERNS):
                val_preview = str(args.get("value_preview", ""))
                evidence.append(f"SharedPreferences key='{key}' value='{val_preview[:40]}'")

            # File path in app-external storage
            path = str(args.get("path", ""))
            if any(ext in path.lower() for ext in
                   ["/sdcard/", "/external_storage/", "/downloads/"]):
                evidence.append(f"Write to external storage: {path}")

        if evidence:
            self._add(
                "MASVS-STORAGE-1",
                "Sensitive Data Written to Insecure Storage",
                "The application writes data that may contain credentials, tokens, or "
                "personal information to plaintext storage (SharedPreferences, SQLite, "
                "external storage) without encryption.",
                Severity.HIGH,
                "MASVS-STORAGE",
                evidence,
                "Encrypt sensitive fields before persisting. Use Android Keystore-backed "
                "encryption for credentials. Avoid writing sensitive data to external "
                "storage. Consider using EncryptedSharedPreferences.",
                "CWE-312",
            )

        # iOS plist / clipboard
        for ev in self.trace.events_by_category(TraceCategory.FILESYSTEM):
            args = ev.args if isinstance(ev.args, dict) else {}
            path = str(args.get("path", ""))
            if path.endswith(".plist") and any(
                p.search(path) for p in SENSITIVE_FIELD_PATTERNS
            ):
                self._add(
                    "MASVS-STORAGE-1-plist",
                    "Sensitive Data in Plist File",
                    f"Sensitive data written to plist: {path}",
                    Severity.MEDIUM,
                    "MASVS-STORAGE",
                    [path],
                    "Store sensitive values in the Keychain rather than plist files.",
                    "CWE-312",
                )

    def _check_weak_crypto(self) -> None:
        if not self.trace:
            return
        found: dict[str, list[str]] = {}
        for ev in self.trace.events_by_category(TraceCategory.CRYPTO):
            args = ev.args if isinstance(ev.args, dict) else {}
            algo = str(args.get("transformation", "") or args.get("algorithm", ""))
            for weak in WEAK_CRYPTO_ALGOS:
                if weak.upper() in algo.upper():
                    found.setdefault(weak, []).append(
                        f"{ev.class_name}.{ev.method_name} → {algo}"
                    )

        for weak_algo, instances in found.items():
            self._add(
                f"MASVS-CRYPTO-1-{weak_algo}",
                f"Weak Cryptographic Algorithm: {weak_algo}",
                f"The application uses the weak or broken algorithm '{weak_algo}'. "
                f"This was observed in {len(instances)} call(s).",
                Severity.HIGH if weak_algo in {"RC4", "DES", "MD5"} else Severity.MEDIUM,
                "MASVS-CRYPTO",
                instances,
                f"Replace {weak_algo} with a strong modern algorithm: "
                "AES-256-GCM for symmetric encryption, SHA-256+ for hashing, "
                "RSA-2048+ or EC P-256+ for asymmetric operations.",
                "CWE-327",
            )

    def _check_cleartext_network(self) -> None:
        if not self.trace:
            return
        evidence: list[str] = []
        for ev in self.trace.events_by_category(TraceCategory.NETWORK):
            args = ev.args if isinstance(ev.args, dict) else {}
            url = str(args.get("url", ""))
            if HTTP_PATTERN.match(url):
                evidence.append(f"{args.get('method', 'GET')} {url}")

        if evidence:
            self._add(
                "MASVS-NETWORK-1",
                "Unencrypted HTTP Traffic",
                "The application sends data over unencrypted HTTP. "
                "Credentials, session tokens, and personal data are exposed to "
                "network observers.",
                Severity.HIGH,
                "MASVS-NETWORK",
                evidence,
                "Enforce HTTPS for all network communication. "
                "Add a Network Security Config (Android) or App Transport Security "
                "(iOS) policy that blocks cleartext traffic.",
                "CWE-319",
            )

    def _check_debug_artifacts(self) -> None:
        if not self.trace:
            return
        evidence: list[str] = []
        for ev in self.trace.events:
            args = ev.args if isinstance(ev.args, dict) else {}
            # Look for logging calls that emit sensitive field names
            for v in args.values():
                vstr = str(v)
                if any(p.search(vstr) for p in SENSITIVE_FIELD_PATTERNS):
                    evidence.append(
                        f"{ev.class_name}.{ev.method_name}: '{vstr[:80]}'"
                    )
                    if len(evidence) >= 10:
                        break

        if evidence:
            self._add(
                "MASVS-CODE-4",
                "Sensitive Data in Debug Logs",
                "The application logs data that may contain credentials, tokens, "
                "or personal information. Debug logging of sensitive data exposes "
                "it to anyone with device logcat/console access.",
                Severity.MEDIUM,
                "MASVS-CODE",
                evidence,
                "Remove or sanitise logging of sensitive fields before release. "
                "Use ProGuard rules to strip logging calls in release builds.",
                "CWE-532",
            )

    def _check_biometric_bypass_risk(self) -> None:
        if not self.trace:
            return
        biometric_events = self.trace.events_by_category(TraceCategory.BIOMETRICS)
        if not biometric_events:
            return

        # If biometrics used but no CryptoObject, the auth can be bypassed at runtime
        no_crypto = [
            ev for ev in biometric_events
            if not (ev.args or {}).get("has_crypto", True)
        ]
        if no_crypto:
            self._add(
                "MASVS-AUTH-2",
                "Biometric Authentication Without Cryptographic Binding",
                f"BiometricPrompt.authenticate was called {len(no_crypto)} time(s) "
                "without a CryptoObject. Authentication without cryptographic binding "
                "can be bypassed via runtime instrumentation by directly invoking "
                "the onAuthenticationSucceeded callback.",
                Severity.HIGH,
                "MASVS-AUTH",
                [f"Call #{i+1}: {ev.class_name}.{ev.method_name}" for i, ev in enumerate(no_crypto)],
                "Always bind biometric authentication to a cryptographic operation "
                "(e.g. decrypt a session key with a Keystore-backed key unlocked by "
                "biometrics). Use CryptoObject with BiometricPrompt.",
                "CWE-287",
            )

    def _check_hardcoded_secrets_in_trace(self) -> None:
        for ev in self.trace.events:
            args_str = str(ev.args) + str(ev.return_value)
            self._check_chunk_for_secrets(args_str, source=f"{ev.class_name}.{ev.method_name}")

    def _check_chunk_for_secrets(self, text: str, source: str = "memory") -> None:
        for name, pattern in SECRET_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                self._add(
                    f"MASVS-STORAGE-2-{name.replace(' ', '_')}",
                    f"Potential Hardcoded Secret: {name}",
                    f"A value matching the pattern for '{name}' was found at runtime "
                    f"in {source}. Hardcoded secrets can be extracted from app memory "
                    "or binaries.",
                    Severity.HIGH,
                    "MASVS-STORAGE",
                    [f"Pattern '{name}' matched in {source}: "
                     f"'{str(matches[0])[:40]}...'"],
                    f"Move '{name}' values to a secure backend. Never embed secrets "
                    "in app binaries or local storage. Use ephemeral tokens obtained "
                    "from the server after authentication.",
                    "CWE-798",
                )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add(
        self,
        vuln_id: str,
        title: str,
        description: str,
        severity: Severity,
        category: str,
        evidence: list[str],
        remediation: str,
        cwe_id: str = "",
    ) -> None:
        # Deduplicate by vuln_id
        if any(v.vuln_id == vuln_id for v in self._vulns):
            return
        self._vulns.append(Vulnerability(
            vuln_id=vuln_id,
            title=title,
            description=description,
            severity=severity,
            category=category,
            evidence=evidence[:10],  # cap evidence list
            remediation=remediation,
            cwe_id=cwe_id,
        ))
