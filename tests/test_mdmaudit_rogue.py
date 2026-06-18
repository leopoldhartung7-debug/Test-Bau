"""Tests for rogue MDM profile detection and attack path analysis."""

import pytest
from datetime import datetime

from mdmaudit.rogue.detector import (
    detect_rogue_mdm,
    check_ca_certificates,
    KNOWN_STALKERWARE_ORGS,
    STALKERWARE_DOMAIN_PATTERNS,
)
from mdmaudit.privesc.attack_paths import map_attack_paths
from mdmaudit.models import (
    DeviceOwnership,
    DevicePlatform,
    FindingSeverity,
    MDMDeployment,
    MDMPlatform,
    ProfileType,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_profile(
    org: str,
    server_url: str = "https://mdm.corp.example.com",
    profile_id: str = "com.example.mdm",
    payloads: list | None = None,
    install_date: str = "2024-01-15T09:00:00Z",
) -> dict:
    return {
        "PayloadIdentifier": profile_id,
        "PayloadDisplayName": "Corporate MDM",
        "PayloadOrganization": org,
        "ServerURL": server_url,
        "InstallDate": install_date,
        "PayloadContent": payloads or [
            {
                "PayloadType": "com.apple.mdm",
                "PayloadUUID": "mdm-uuid-001",
                "PayloadDisplayName": "MDM Payload",
            }
        ],
    }


def _ca_payload(name: str = "Corp Root CA") -> dict:
    return {
        "PayloadType": "com.apple.security.root",
        "PayloadUUID": "ca-uuid-001",
        "PayloadDisplayName": name,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Rogue MDM detection tests
# ─────────────────────────────────────────────────────────────────────────────

class TestStalkerwareDetection:
    def test_known_stalkerware_org_flagged_critical(self):
        profile = _make_profile("FlexiSpy", "https://flexispy.com/mdm")
        rogue = detect_rogue_mdm([profile])
        assert len(rogue) >= 1
        assert rogue[0].severity == FindingSeverity.CRITICAL
        assert rogue[0].is_suspicious is True

    def test_stalkerware_domain_flagged_critical(self):
        profile = _make_profile("Unknown Corp", "https://mspy.com/enroll")
        rogue = detect_rogue_mdm([profile])
        critical = [r for r in rogue if r.severity == FindingSeverity.CRITICAL]
        assert len(critical) >= 1

    def test_mspy_org_flagged(self):
        profile = _make_profile("mSpy", "https://partner.mspy.com/mdm")
        rogue = detect_rogue_mdm([profile])
        assert any("stalkerware" in r.reason.lower() or "surveillance" in r.reason.lower()
                   for r in rogue)

    def test_legitimate_org_not_flagged_as_stalkerware(self):
        profile = _make_profile("Acme Corporation", "https://mdm.acme.example.com")
        rogue = detect_rogue_mdm([profile])
        stalkerware = [r for r in rogue if "stalkerware" in r.reason.lower()]
        assert len(stalkerware) == 0

    def test_case_insensitive_org_match(self):
        profile = _make_profile("FLEXISPY", "https://flexispy.com/enroll")
        rogue = detect_rogue_mdm([profile])
        assert any(r.severity == FindingSeverity.CRITICAL for r in rogue)


class TestDeceptiveOrganisationDetection:
    def test_impersonating_apple_flagged(self):
        profile = _make_profile("Apple Inc", "https://mdm.legitimate.example.com")
        rogue = detect_rogue_mdm([profile])
        deceptive = [r for r in rogue if "impersonat" in r.reason.lower()
                     or "deceptive" in r.reason.lower()]
        assert len(deceptive) >= 1
        assert deceptive[0].severity == FindingSeverity.HIGH

    def test_system_service_name_flagged(self):
        profile = _make_profile("System Services", "https://mdm.example.com")
        rogue = detect_rogue_mdm([profile])
        assert len(rogue) >= 1
        assert any(r.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)
                   for r in rogue)


class TestUnrecognisedMDMServer:
    def test_unknown_domain_flagged_medium(self):
        profile = _make_profile(
            "Unknown Corp",
            "https://unknown-mdm-server.io/enroll",
        )
        rogue = detect_rogue_mdm(
            [profile],
            trusted_mdm_domains=["mdm.corp.example.com", "jamf.corp.com"],
        )
        unrecognised = [r for r in rogue if "not in the list" in r.reason]
        assert len(unrecognised) >= 1

    def test_trusted_domain_not_flagged_as_unrecognised(self):
        profile = _make_profile(
            "IT Department",
            "https://mdm.corp.example.com/enroll",
        )
        rogue = detect_rogue_mdm(
            [profile],
            trusted_mdm_domains=["corp.example.com"],
        )
        unrecognised = [r for r in rogue if "not in the list" in r.reason]
        assert len(unrecognised) == 0

    def test_subdomain_of_trusted_domain_not_flagged(self):
        profile = _make_profile(
            "IT Department",
            "https://jamf.prod.corp.example.com/enroll",
        )
        rogue = detect_rogue_mdm(
            [profile],
            trusted_mdm_domains=["corp.example.com"],
        )
        unrecognised = [r for r in rogue if "not in the list" in r.reason]
        assert len(unrecognised) == 0

    def test_ip_address_server_url_flagged_high(self):
        profile = _make_profile(
            "IT Department",
            "https://192.168.1.100/enroll",
        )
        rogue = detect_rogue_mdm(
            [profile],
            trusted_mdm_domains=["corp.example.com"],
        )
        ip_findings = [r for r in rogue if r.severity == FindingSeverity.HIGH
                       and "not in the list" in r.reason]
        assert len(ip_findings) >= 1

    def test_no_trusted_domains_no_unrecognised_finding(self):
        profile = _make_profile("Corp IT", "https://any-mdm.example.com")
        rogue = detect_rogue_mdm([profile], trusted_mdm_domains=None)
        # Without a trusted list, unknown-server check should not fire
        unrecognised = [r for r in rogue if "not in the list" in r.reason]
        assert len(unrecognised) == 0


class TestBYODFullManagement:
    def test_full_mdm_on_byod_flagged_high(self):
        profile = _make_profile(
            "Corp IT",
            payloads=[{"PayloadType": "com.apple.mdm", "PayloadUUID": "u1",
                       "PayloadDisplayName": "MDM"}],
        )
        rogue = detect_rogue_mdm([profile], device_ownership="byod")
        byod_findings = [r for r in rogue if "BYOD" in r.reason or "byod" in str(r.indicators)]
        assert len(byod_findings) >= 1
        assert byod_findings[0].severity == FindingSeverity.HIGH

    def test_full_mdm_on_corporate_not_byod_flagged(self):
        profile = _make_profile(
            "Corp IT",
            payloads=[{"PayloadType": "com.apple.mdm", "PayloadUUID": "u1",
                       "PayloadDisplayName": "MDM"}],
        )
        rogue = detect_rogue_mdm([profile], device_ownership="corporate")
        byod_findings = [r for r in rogue if "BYOD" in r.reason]
        assert len(byod_findings) == 0


class TestCACertificateDetection:
    def test_root_ca_flagged_medium(self):
        profile = _make_profile(
            "Corp IT",
            payloads=[_ca_payload("Corp Root CA")],
        )
        ca_findings = check_ca_certificates([profile])
        assert len(ca_findings) >= 1
        assert all(r.severity == FindingSeverity.MEDIUM for r in ca_findings)
        assert all(r.profile_type == ProfileType.CERTIFICATE for r in ca_findings)

    def test_no_ca_no_findings(self):
        profile = _make_profile(
            "Corp IT",
            payloads=[{"PayloadType": "com.apple.wifi.managed",
                       "PayloadUUID": "w1", "PayloadDisplayName": "WiFi"}],
        )
        ca_findings = check_ca_certificates([profile])
        assert len(ca_findings) == 0

    def test_ca_reason_mentions_mitm(self):
        profile = _make_profile("Corp IT", payloads=[_ca_payload()])
        ca_findings = check_ca_certificates([profile])
        assert any("MITM" in r.reason or "intercept" in r.reason.lower()
                   for r in ca_findings)


class TestSortingAndMultipleProfiles:
    def test_sorted_critical_first(self):
        profiles = [
            _make_profile("Corp IT", "https://mdm.corp.example.com"),  # medium/none
            _make_profile("FlexiSpy", "https://flexispy.com/enroll"),  # critical
        ]
        rogue = detect_rogue_mdm(profiles)
        severities = [r.severity for r in rogue]
        _order = {FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1,
                  FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 3,
                  FindingSeverity.INFO: 4}
        vals = [_order[s] for s in severities]
        assert vals == sorted(vals)

    def test_empty_profiles_list(self):
        rogue = detect_rogue_mdm([])
        assert rogue == []


# ─────────────────────────────────────────────────────────────────────────────
# Attack path analysis tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackPathMapping:
    def _make_deployment(self, **kwargs) -> MDMDeployment:
        defaults = {
            "deployment_id": "test-deploy",
            "platform": MDMPlatform.JAMF,
            "server_url": "https://jamf.corp.example.com",
            "organization": "Test Corp",
            "device_count": 500,
            "managed_platforms": [DevicePlatform.IOS],
        }
        defaults.update(kwargs)
        return MDMDeployment(**defaults)

    def test_graph_has_nodes_and_edges(self):
        deployment = self._make_deployment()
        graph = map_attack_paths(deployment)
        assert len(graph.nodes) >= 2
        assert len(graph.edges) >= 1

    def test_graph_has_attack_paths(self):
        deployment = self._make_deployment()
        graph = map_attack_paths(deployment)
        assert len(graph.attack_paths) >= 1

    def test_critical_path_present(self):
        deployment = self._make_deployment(mfa_required=False)
        graph = map_attack_paths(deployment)
        assert len(graph.critical_paths) >= 1

    def test_ldap_integration_adds_paths(self):
        deployment_no_ldap = self._make_deployment(ldap_integrated=False)
        deployment_ldap = self._make_deployment(ldap_integrated=True)
        graph_no_ldap = map_attack_paths(deployment_no_ldap)
        graph_ldap = map_attack_paths(deployment_ldap)
        assert len(graph_ldap.attack_paths) > len(graph_no_ldap.attack_paths)

    def test_pki_integration_adds_paths(self):
        deployment_no_pki = self._make_deployment(pki_integrated=False)
        deployment_pki = self._make_deployment(pki_integrated=True)
        graph_no_pki = map_attack_paths(deployment_no_pki)
        graph_pki = map_attack_paths(deployment_pki)
        assert len(graph_pki.attack_paths) > len(graph_no_pki.attack_paths)

    def test_paths_sorted_critical_first(self):
        deployment = self._make_deployment(ldap_integrated=True, pki_integrated=True)
        graph = map_attack_paths(deployment)
        _order = {FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1,
                  FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 3,
                  FindingSeverity.INFO: 4}
        severities = [_order[p.severity] for p in graph.attack_paths]
        assert severities == sorted(severities)

    def test_all_paths_have_remediation(self):
        deployment = self._make_deployment(ldap_integrated=True, pki_integrated=True)
        graph = map_attack_paths(deployment)
        for path in graph.attack_paths:
            assert len(path.remediation) > 20

    def test_all_paths_have_mitre_techniques(self):
        deployment = self._make_deployment(ldap_integrated=True)
        graph = map_attack_paths(deployment)
        for path in graph.attack_paths:
            assert len(path.mitre_techniques) >= 1

    def test_graph_summary(self):
        deployment = self._make_deployment()
        graph = map_attack_paths(deployment)
        summary = graph.summary()
        assert "Attack" in summary or "paths" in summary.lower()

    def test_edges_to(self):
        deployment = self._make_deployment()
        graph = map_attack_paths(deployment)
        mdm_node = next((n for n in graph.nodes if n.node_type == "service"), None)
        if mdm_node:
            incoming = graph.edges_to(mdm_node.node_id)
            assert len(incoming) >= 1

    def test_mfa_deployment_has_no_no_mfa_edge(self):
        """With MFA required, the no-MFA credential theft edge should not exist."""
        deployment = self._make_deployment(mfa_required=True)
        graph = map_attack_paths(deployment)
        no_mfa_edges = [e for e in graph.edges if "No MFA" in e.description]
        assert len(no_mfa_edges) == 0
