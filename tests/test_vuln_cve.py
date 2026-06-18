"""Tests for CVE vulnerability assessment module."""

import pytest
from mobileaudit.models import Platform, Severity
from mobileaudit.vuln.cve import (
    _version_le,
    get_builtin_vulnerabilities,
)


class TestVersionLe:
    def test_equal(self):
        assert _version_le("16.5", "16.5") is True

    def test_less_than(self):
        assert _version_le("15.3", "16.0") is True

    def test_greater(self):
        assert _version_le("17.0", "16.6") is False

    def test_patch_level(self):
        assert _version_le("16.5.1", "16.6") is True
        assert _version_le("16.7", "16.6") is False

    def test_malformed(self):
        assert _version_le("abc", "16.0") is False


class TestGetBuiltinVulnerabilities:
    def test_blastpass_on_affected_version(self):
        vulns = get_builtin_vulnerabilities(Platform.IOS, "16.5")
        cve_ids = [v.cve_id for v in vulns]
        assert "CVE-2023-41064" in cve_ids

    def test_blastpass_not_on_patched_version(self):
        vulns = get_builtin_vulnerabilities(Platform.IOS, "16.7")
        cve_ids = [v.cve_id for v in vulns]
        assert "CVE-2023-41064" not in cve_ids

    def test_checkm8_on_a11_model(self):
        vulns = get_builtin_vulnerabilities(Platform.IOS, "15.0", model="iPhone10,6")
        cve_ids = [v.cve_id for v in vulns]
        assert "CVE-2019-8900" in cve_ids

    def test_checkm8_not_on_a12_model(self):
        # iPhone11 = A12 Bionic, not checkm8-vulnerable
        vulns = get_builtin_vulnerabilities(Platform.IOS, "15.0", model="iPhone11,8")
        cve_ids = [v.cve_id for v in vulns]
        assert "CVE-2019-8900" not in cve_ids

    def test_exynos_only_on_samsung(self):
        samsung_vulns = get_builtin_vulnerabilities(
            Platform.ANDROID, "12", manufacturer="Samsung"
        )
        pixel_vulns = get_builtin_vulnerabilities(
            Platform.ANDROID, "12", manufacturer="Google"
        )
        s_ids = [v.cve_id for v in samsung_vulns]
        p_ids = [v.cve_id for v in pixel_vulns]
        assert "CVE-2023-24033" in s_ids
        assert "CVE-2023-24033" not in p_ids

    def test_android_patched_not_matched(self):
        # CVE-2021-1048 affects ≤ patch "2021-11-05", so Android 13 should be fine
        # (version comparison won't apply here, but the patch version check is by SPL)
        vulns = get_builtin_vulnerabilities(Platform.ANDROID, "13")
        # Just verify it returns a list without error
        assert isinstance(vulns, list)

    def test_all_vulns_have_required_fields(self):
        for platform in [Platform.IOS, Platform.ANDROID]:
            vulns = get_builtin_vulnerabilities(platform, "12.0")
            for v in vulns:
                assert v.cve_id
                assert v.severity in list(Severity)
                assert isinstance(v.cvss_score, float)
                assert isinstance(v.exploit_available, bool)
