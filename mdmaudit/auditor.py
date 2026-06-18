"""
MDMSecurityAuditor — unified entry point for MDM security assessments.
"""

from __future__ import annotations

import logging
from typing import Optional

from .enrollment.apple_dep import audit_apple_dep_enrollment
from .enrollment.android_enroll import audit_android_enterprise_enrollment
from .models import (
    APISecurityReport,
    AttackGraph,
    DeviceOwnership,
    EnrollmentReport,
    MDMDeployment,
    MDMPlatform,
    ProfileReport,
    RogueProfile,
)
from .profiles.android_profiles import analyze_android_policies
from .profiles.ios_profiles import analyze_ios_profiles
from .api_security.protocol import assess_mdm_api
from .privesc.attack_paths import map_attack_paths
from .rogue.detector import detect_rogue_mdm

logger = logging.getLogger(__name__)


class MDMSecurityAuditor:
    """
    Unified MDM security assessment tool.

    Each method maps to a specific assessment domain. Methods are independent
    and can be called individually or combined into a full assessment.

    All active network probing requires ``authorized=True`` plus an out-of-band
    written authorisation from the MDM system owner.
    """

    def __init__(
        self,
        *,
        timeout: int = 10,
        verbose: bool = False,
    ):
        self.timeout = timeout
        if verbose:
            logging.basicConfig(level=logging.DEBUG)

    # ------------------------------------------------------------------
    # 1. Enrollment analysis
    # ------------------------------------------------------------------

    def audit_enrollment(
        self,
        mdm_platform: MDMPlatform,
        *,
        enrollment_url: str = "",
        emm_config: Optional[dict] = None,
        device_ownership: DeviceOwnership = DeviceOwnership.CORPORATE,
        authorized: bool = False,
    ) -> EnrollmentReport:
        """
        Assess the security of device enrollment processes.

        For Apple DEP/ABM: pass ``enrollment_url``.
        For Android Enterprise: pass ``emm_config`` dict.
        """
        if mdm_platform == MDMPlatform.ANDROID_ENTERPRISE:
            return audit_android_enterprise_enrollment(
                emm_config or {},
                ownership=device_ownership,
                authorized=authorized,
            )
        else:
            return audit_apple_dep_enrollment(
                enrollment_url,
                mdm_platform=mdm_platform,
                timeout=self.timeout,
                authorized=authorized,
            )

    # ------------------------------------------------------------------
    # 2. Profile configuration analysis
    # ------------------------------------------------------------------

    def analyze_profiles(
        self,
        device_platform: str,
        profiles,
        device_identifier: str = "unknown",
        *,
        android_policies: Optional[dict] = None,
    ) -> ProfileReport:
        """
        Examine deployed MDM profiles for security misconfigurations.

        For iOS: ``profiles`` is a list of .mobileconfig dicts/bytes/Paths.
        For Android: pass ``android_policies`` dict from the EMM console.
        """
        if device_platform.lower() in ("android",):
            return analyze_android_policies(
                android_policies or {},
                device_identifier=device_identifier,
            )
        else:
            return analyze_ios_profiles(
                profiles,
                device_identifier=device_identifier,
            )

    # ------------------------------------------------------------------
    # 3. MDM protocol / API security
    # ------------------------------------------------------------------

    def assess_mdm_api(
        self,
        endpoint: str,
        *,
        authorized: bool = False,
        api_token: str = "",
        check_cross_device: bool = False,
        device_ids: Optional[list[str]] = None,
    ) -> APISecurityReport:
        """
        Test the security of MDM server communications and management APIs.

        Performs TLS, authentication, rate-limiting, authorization boundary,
        and injection surface checks. Active probing requires authorized=True.
        """
        return assess_mdm_api(
            endpoint,
            authorized=authorized,
            timeout=self.timeout,
            api_token=api_token,
            check_cross_device=check_cross_device,
            device_ids=device_ids,
        )

    # ------------------------------------------------------------------
    # 4. Attack path mapping
    # ------------------------------------------------------------------

    def map_attack_paths(self, mdm_deployment: MDMDeployment) -> AttackGraph:
        """
        Identify privilege escalation and lateral movement paths within
        an MDM deployment.

        Returns an AttackGraph with prioritised attack paths, MITRE technique
        mappings, and remediation guidance.
        """
        return map_attack_paths(mdm_deployment)

    # ------------------------------------------------------------------
    # 5. Rogue MDM detection
    # ------------------------------------------------------------------

    def detect_rogue_mdm(
        self,
        device_profiles: list[dict],
        *,
        trusted_mdm_domains: Optional[list[str]] = None,
        device_ownership: str = "corporate",
    ) -> list[RogueProfile]:
        """
        Identify unauthorised or rogue MDM profiles on a device.

        Detects stalkerware, unrecognised MDM servers, excessive-permission
        profiles on BYOD devices, and rogue CA certificates.
        """
        return detect_rogue_mdm(
            device_profiles,
            trusted_mdm_domains=trusted_mdm_domains,
            device_ownership=device_ownership,
        )
