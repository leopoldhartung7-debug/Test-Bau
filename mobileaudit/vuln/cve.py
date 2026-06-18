"""CVE vulnerability lookup via the NIST NVD API v2."""

from __future__ import annotations

import logging
import time
from functools import lru_cache
from typing import Any

import requests

from ..models import Platform, Severity, Vulnerability

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_DELAY = 0.6   # NVD allows ~5 req/s without an API key

# CPE prefixes for iOS and Android OS
_CPE_MAP = {
    Platform.IOS: "cpe:2.3:o:apple:iphone_os",
    Platform.ANDROID: "cpe:2.3:o:google:android",
}

# Severity thresholds (CVSS v3)
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "NONE": Severity.INFO,
}

# Known exploit types by keyword in CVE description
_EXPLOIT_KEYWORDS = {
    "jailbreak": "jailbreak",
    "checkm8": "jailbreak",
    "checkra1n": "jailbreak",
    "webkit": "browser_rce",
    "use-after-free": "memory_corruption",
    "buffer overflow": "memory_corruption",
    "privilege escalation": "privilege_escalation",
    "remote code execution": "remote_code_execution",
    "bootloader": "bootloader_exploit",
    "kernel": "kernel_vulnerability",
    "qualcomm": "soc_vulnerability",
    "samsung": "vendor_vulnerability",
}


class NVDClient:
    def __init__(self, api_key: str | None = None):
        self._api_key = api_key
        self._session = requests.Session()
        if api_key:
            self._session.headers["apiKey"] = api_key

    def search_by_cpe(
        self,
        platform: Platform,
        os_version: str,
        results_per_page: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Query NVD for CVEs affecting the given OS version.

        Returns raw NVD CVE items (not yet parsed into Vulnerability objects).
        """
        cpe_prefix = _CPE_MAP[platform]
        # Normalise version: "16.5.1" → "16.5.1", "14" → "14"
        version = os_version.split(" ")[0]

        params: dict[str, Any] = {
            "cpeName": f"{cpe_prefix}:{version}:*:*:*:*:*:*:*",
            "resultsPerPage": results_per_page,
        }

        all_items: list[dict[str, Any]] = []
        start_index = 0

        while True:
            params["startIndex"] = start_index
            try:
                resp = self._session.get(NVD_API_BASE, params=params, timeout=20)
                resp.raise_for_status()
            except requests.RequestException as exc:
                logger.warning("NVD API request failed: %s", exc)
                break

            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            all_items.extend(vulnerabilities)

            total = data.get("totalResults", 0)
            start_index += len(vulnerabilities)
            if start_index >= total:
                break

            # Respect NVD rate limit
            time.sleep(NVD_RATE_LIMIT_DELAY)

        return all_items

    def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        try:
            resp = self._session.get(NVD_API_BASE, params={"cveId": cve_id}, timeout=20)
            resp.raise_for_status()
            items = resp.json().get("vulnerabilities", [])
            return items[0] if items else None
        except requests.RequestException as exc:
            logger.warning("NVD lookup for %s failed: %s", cve_id, exc)
            return None


def parse_nvd_item(item: dict[str, Any], platform: Platform, os_version: str) -> Vulnerability:
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id", "")

    descriptions = cve_data.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), ""
    )

    # Extract CVSS v3 score and severity (fall back to v2)
    cvss_score = 0.0
    severity = Severity.INFO
    metrics = cve_data.get("metrics", {})
    if "cvssMetricV31" in metrics:
        m = metrics["cvssMetricV31"][0]["cvssData"]
        cvss_score = float(m.get("baseScore", 0))
        severity = _SEVERITY_MAP.get(m.get("baseSeverity", "NONE"), Severity.INFO)
    elif "cvssMetricV30" in metrics:
        m = metrics["cvssMetricV30"][0]["cvssData"]
        cvss_score = float(m.get("baseScore", 0))
        severity = _SEVERITY_MAP.get(m.get("baseSeverity", "NONE"), Severity.INFO)
    elif "cvssMetricV2" in metrics:
        m = metrics["cvssMetricV2"][0]["cvssData"]
        cvss_score = float(m.get("baseScore", 0))
        # Map CVSS v2 score to severity
        if cvss_score >= 7.0:
            severity = Severity.HIGH
        elif cvss_score >= 4.0:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

    # Determine exploit type from description text
    desc_lower = description.lower()
    exploit_type = ""
    for keyword, etype in _EXPLOIT_KEYWORDS.items():
        if keyword in desc_lower:
            exploit_type = etype
            break

    # Check exploit availability (EPSS or references to PoC/exploit code)
    refs = cve_data.get("references", [])
    ref_urls = [r["url"] for r in refs if "url" in r]
    exploit_available = any(
        any(kw in url.lower() for kw in ("exploit", "poc", "proof-of-concept", "metasploit",
                                          "nuclei", "rapid7"))
        for url in ref_urls
    )
    # Also flag jailbreaks as having exploit available
    if exploit_type == "jailbreak":
        exploit_available = True

    return Vulnerability(
        cve_id=cve_id,
        title=cve_id,
        description=description,
        severity=severity,
        cvss_score=cvss_score,
        affected_versions=[os_version],
        platform=platform,
        exploit_available=exploit_available,
        exploit_type=exploit_type,
        reference_urls=ref_urls[:10],  # cap at 10 refs
    )


# ------------------------------------------------------------------
# Offline / built-in high-value vulnerability signatures
# (supplements NVD lookups for well-known issues)
# ------------------------------------------------------------------

KNOWN_IOS_VULNERABILITIES: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2019-8900",
        "title": "checkm8 bootrom exploit (A5–A11 chips)",
        "description": (
            "The checkm8 bootrom vulnerability affects Apple devices with A5–A11 SoCs "
            "(iPhone 4S through iPhone X). It allows an unpatchable tethered/semi-tethered "
            "jailbreak via DFU mode. All iOS versions on affected hardware are vulnerable."
        ),
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        # Model prefixes for A5–A11 devices (iPhone4,1 through iPhone10,x)
        # iPhone11,x = A12 Bionic and later — NOT vulnerable
        "affected_model_prefixes": [
            "iPhone4,", "iPhone5,", "iPhone6,", "iPhone7,",
            "iPhone8,", "iPhone9,", "iPhone10,",
            "iPad2,", "iPad3,", "iPad4,", "iPad5,", "iPad6,", "iPad7,",
            "iPod7,", "iPod9,",
        ],
        "exploit_available": True,
        "exploit_type": "jailbreak",
        "patch_version": "N/A (hardware vulnerability)",
    },
    {
        "cve_id": "CVE-2023-41064",
        "title": "BLASTPASS — iMessage zero-click (iOS < 16.6.1)",
        "description": (
            "A buffer overflow in ImageIO when processing specially crafted image files "
            "allows remote code execution without user interaction. Actively exploited by "
            "Pegasus spyware (NSO Group) as a zero-click vector."
        ),
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "affected_versions_max": "16.6",
        "exploit_available": True,
        "exploit_type": "remote_code_execution",
        "patch_version": "16.6.1",
    },
    {
        "cve_id": "CVE-2023-32434",
        "title": "Operation Triangulation kernel integer overflow (iOS < 16.5.1)",
        "description": (
            "An integer overflow vulnerability in the XNU kernel allows local privilege "
            "escalation. Used in the Operation Triangulation APT campaign."
        ),
        "severity": Severity.CRITICAL,
        "cvss_score": 8.6,
        "affected_versions_max": "16.5",
        "exploit_available": True,
        "exploit_type": "kernel_vulnerability",
        "patch_version": "16.5.1",
    },
    {
        "cve_id": "CVE-2022-22620",
        "title": "WebKit use-after-free (iOS < 15.3.1) — exploited in the wild",
        "description": (
            "A use-after-free in WebKit processing maliciously crafted web content "
            "allows arbitrary code execution. Actively exploited at time of disclosure."
        ),
        "severity": Severity.HIGH,
        "cvss_score": 8.8,
        "affected_versions_max": "15.3",
        "exploit_available": True,
        "exploit_type": "browser_rce",
        "patch_version": "15.3.1",
    },
]

KNOWN_ANDROID_VULNERABILITIES: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2023-21282",
        "title": "Android Bluetooth RCE (Android < 13 QPR2)",
        "description": (
            "A remote code execution vulnerability in the Bluetooth stack allows a "
            "nearby attacker to execute arbitrary code with elevated privileges."
        ),
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "affected_versions_max": "12",
        "exploit_available": False,
        "exploit_type": "remote_code_execution",
        "patch_version": "2023-02-05 SPL",
    },
    {
        "cve_id": "CVE-2023-26083",
        "title": "Mali GPU kernel driver info leak (Samsung/Mali devices)",
        "description": (
            "An information disclosure vulnerability in the Arm Mali GPU kernel driver "
            "allows a local attacker to access kernel memory. Exploited in the wild "
            "against Samsung devices."
        ),
        "severity": Severity.HIGH,
        "cvss_score": 7.8,
        "affected_vendors": ["Samsung"],
        "exploit_available": True,
        "exploit_type": "kernel_vulnerability",
        "patch_version": "2023-03-05 SPL",
    },
    {
        "cve_id": "CVE-2023-24033",
        "title": "Samsung Exynos RCE via baseband (Exynos 850/980/990/1080/2200 etc.)",
        "description": (
            "Multiple critical vulnerabilities in Samsung's Exynos baseband modem allow "
            "remote code execution from the internet with no user interaction, requiring "
            "only the victim's phone number."
        ),
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "affected_vendors": ["Samsung"],
        "exploit_available": True,
        "exploit_type": "remote_code_execution",
        "patch_version": "2023-03 Samsung SVE",
    },
    {
        "cve_id": "CVE-2021-1048",
        "title": "Android kernel use-after-free (Qualcomm SoCs)",
        "description": (
            "A use-after-free in the Android kernel allows a local attacker to escalate "
            "privileges. Exploited in the wild on Qualcomm-based devices."
        ),
        "severity": Severity.HIGH,
        "cvss_score": 7.8,
        "affected_soc": "Qualcomm",
        "exploit_available": True,
        "exploit_type": "privilege_escalation",
        "patch_version": "2021-11-05 SPL",
    },
]


def _version_le(version: str, max_version: str) -> bool:
    """Return True if version <= max_version using tuple comparison."""
    try:
        v = tuple(int(x) for x in version.split(".")[:3])
        mv = tuple(int(x) for x in max_version.split(".")[:3])
        return v <= mv
    except ValueError:
        return False


def get_builtin_vulnerabilities(
    platform: Platform,
    os_version: str,
    model: str = "",
    manufacturer: str = "",
) -> list[Vulnerability]:
    """Return built-in high-value vulnerabilities relevant for this device."""
    results: list[Vulnerability] = []
    entries = (
        KNOWN_IOS_VULNERABILITIES if platform == Platform.IOS
        else KNOWN_ANDROID_VULNERABILITIES
    )

    for entry in entries:
        max_ver = entry.get("affected_versions_max", "")
        if max_ver and not _version_le(os_version, max_ver):
            continue

        # Model prefix filtering (used by checkm8 to restrict to A5–A11 hardware)
        if entry.get("affected_model_prefixes"):
            if not any(model.startswith(prefix) for prefix in entry["affected_model_prefixes"]):
                continue

        # Vendor/SoC filtering for Android
        if entry.get("affected_vendors"):
            if not any(v.lower() in manufacturer.lower() for v in entry["affected_vendors"]):
                continue
        if entry.get("affected_soc"):
            if entry["affected_soc"].lower() not in model.lower():
                continue

        results.append(Vulnerability(
            cve_id=entry["cve_id"],
            title=entry["title"],
            description=entry["description"],
            severity=entry["severity"],
            cvss_score=entry["cvss_score"],
            affected_versions=[os_version],
            platform=platform,
            exploit_available=entry.get("exploit_available", False),
            exploit_type=entry.get("exploit_type", ""),
            patch_version=entry.get("patch_version", ""),
        ))

    return results
