"""
MDMAudit CLI — MDM security assessment from the command line.

Usage examples:

  # Audit Apple DEP enrollment endpoint
  mdmaudit enrollment --platform generic_apple --url https://mdm.corp.example.com/enroll

  # Analyse iOS profiles from directory
  mdmaudit profiles --platform ios --path /path/to/profiles/

  # Assess MDM management API
  mdmaudit api --endpoint https://mdm.corp.example.com/api/v1 --authorized

  # Map attack paths for a deployment
  mdmaudit attack-paths --platform jamf --url https://jamf.corp.example.com \
      --ldap --pki --devices 1200

  # Scan device for rogue MDM profiles
  mdmaudit rogue --profiles profiles.json --trusted-domains corp.example.com
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

try:
    import click
except ImportError:
    sys.exit("click is required: pip install click")

from .auditor import MDMSecurityAuditor
from .models import (
    DeviceOwnership,
    FindingSeverity,
    MDMDeployment,
    MDMPlatform,
)

_SEVERITY_COLOURS = {
    FindingSeverity.CRITICAL: "red",
    FindingSeverity.HIGH: "yellow",
    FindingSeverity.MEDIUM: "yellow",
    FindingSeverity.LOW: "cyan",
    FindingSeverity.INFO: "green",
}


@click.group()
@click.option("--verbose", "-v", is_flag=True)
@click.option("--output", "-o", default=None, type=click.Path(),
              help="Save report as JSON to this path")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, output: Optional[str]) -> None:
    """MDMAudit — MDM security assessment tool."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["output"] = output
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=logging.DEBUG if verbose else logging.WARNING,
    )


@cli.command("enrollment")
@click.option("--platform", "-p",
              type=click.Choice([p.value for p in MDMPlatform]), required=True)
@click.option("--url", default="", help="Enrollment endpoint URL (Apple DEP)")
@click.option("--emm-config", default=None, type=click.Path(exists=True),
              help="Path to EMM config JSON (Android Enterprise)")
@click.option("--ownership",
              type=click.Choice(["corporate", "byod", "cope"]), default="corporate")
@click.option("--authorized", is_flag=True, default=False,
              help="Enable active probing (requires written authorisation)")
@click.pass_context
def enrollment_cmd(
    ctx: click.Context,
    platform: str,
    url: str,
    emm_config: Optional[str],
    ownership: str,
    authorized: bool,
) -> None:
    """Assess MDM enrollment security."""
    auditor = MDMSecurityAuditor(verbose=ctx.obj["verbose"])
    ownership_map = {
        "corporate": DeviceOwnership.CORPORATE,
        "byod": DeviceOwnership.BYOD,
        "cope": DeviceOwnership.COPE,
    }

    emm_config_dict: dict = {}
    if emm_config:
        with open(emm_config) as f:
            emm_config_dict = json.load(f)

    report = auditor.audit_enrollment(
        MDMPlatform(platform),
        enrollment_url=url,
        emm_config=emm_config_dict,
        device_ownership=ownership_map[ownership],
        authorized=authorized,
    )

    if ctx.obj["output"]:
        _save_json({"type": "enrollment", "findings": [f.to_dict() for f in report.findings]},
                   ctx.obj["output"])
    else:
        click.echo(report.summary())
        _print_findings(report.findings)


@cli.command("profiles")
@click.option("--platform", "-p",
              type=click.Choice(["ios", "ipados", "macos", "android"]), required=True)
@click.option("--path", type=click.Path(exists=True),
              help="Path to .mobileconfig file or directory")
@click.option("--policies", default=None, type=click.Path(exists=True),
              help="Android policy JSON file")
@click.option("--device-id", default="unknown")
@click.pass_context
def profiles_cmd(
    ctx: click.Context,
    platform: str,
    path: Optional[str],
    policies: Optional[str],
    device_id: str,
) -> None:
    """Analyse MDM profile configurations for security issues."""
    auditor = MDMSecurityAuditor(verbose=ctx.obj["verbose"])

    profiles_input = []
    android_policies_dict: dict = {}

    if platform == "android":
        if policies:
            with open(policies) as f:
                android_policies_dict = json.load(f)
    else:
        if path:
            p = Path(path)
            if p.is_dir():
                profiles_input = list(p.glob("*.mobileconfig"))
            else:
                profiles_input = [p]

    report = auditor.analyze_profiles(
        platform,
        profiles_input,
        device_identifier=device_id,
        android_policies=android_policies_dict,
    )

    if ctx.obj["output"]:
        _save_json({"type": "profiles", "findings": [f.to_dict() for f in report.findings]},
                   ctx.obj["output"])
    else:
        click.echo(report.summary())
        _print_findings(report.findings)


@cli.command("api")
@click.option("--endpoint", required=True, help="MDM management API base URL")
@click.option("--token", default="", help="API bearer token for authenticated checks")
@click.option("--authorized", is_flag=True, default=False,
              help="Enable active probing (requires written authorisation)")
@click.option("--check-cross-device", is_flag=True, default=False)
@click.option("--device-ids", default="",
              help="Comma-separated device IDs for cross-device checks")
@click.pass_context
def api_cmd(
    ctx: click.Context,
    endpoint: str,
    token: str,
    authorized: bool,
    check_cross_device: bool,
    device_ids: str,
) -> None:
    """Assess MDM management API security."""
    auditor = MDMSecurityAuditor(verbose=ctx.obj["verbose"])
    ids = [d.strip() for d in device_ids.split(",") if d.strip()]

    report = auditor.assess_mdm_api(
        endpoint,
        authorized=authorized,
        api_token=token,
        check_cross_device=check_cross_device,
        device_ids=ids or None,
    )

    if ctx.obj["output"]:
        _save_json({"type": "api", "findings": [f.to_dict() for f in report.findings]},
                   ctx.obj["output"])
    else:
        click.echo(report.summary())
        _print_findings(report.findings)


@cli.command("attack-paths")
@click.option("--platform", "-p",
              type=click.Choice([p.value for p in MDMPlatform]), required=True)
@click.option("--url", required=True, help="MDM server URL")
@click.option("--org", default="Unknown Org", help="Organisation name")
@click.option("--devices", default=0, type=int, help="Number of enrolled devices")
@click.option("--ldap", "ldap_integrated", is_flag=True, default=False)
@click.option("--pki", "pki_integrated", is_flag=True, default=False)
@click.option("--mfa", "mfa_required", is_flag=True, default=False)
@click.option("--linked-services", default="",
              help="Comma-separated list of linked services (e.g. SIEM,JIRA)")
@click.pass_context
def attack_paths_cmd(
    ctx: click.Context,
    platform: str,
    url: str,
    org: str,
    devices: int,
    ldap_integrated: bool,
    pki_integrated: bool,
    mfa_required: bool,
    linked_services: str,
) -> None:
    """Map privilege escalation and lateral movement attack paths."""
    auditor = MDMSecurityAuditor(verbose=ctx.obj["verbose"])
    services = [s.strip() for s in linked_services.split(",") if s.strip()]

    deployment = MDMDeployment(
        deployment_id="cli-assessment",
        platform=MDMPlatform(platform),
        server_url=url,
        organization=org,
        device_count=devices,
        ldap_integrated=ldap_integrated,
        pki_integrated=pki_integrated,
        mfa_required=mfa_required,
        linked_services=services,
    )

    graph = auditor.map_attack_paths(deployment)

    if ctx.obj["output"]:
        data = {
            "type": "attack_graph",
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "paths": [
                {
                    "id": p.path_id,
                    "name": p.name,
                    "severity": p.severity.value,
                    "description": p.description,
                    "remediation": p.remediation,
                    "mitre": p.mitre_techniques,
                }
                for p in graph.attack_paths
            ],
        }
        _save_json(data, ctx.obj["output"])
    else:
        click.echo(graph.summary())
        click.echo()
        for path in graph.attack_paths:
            colour = _SEVERITY_COLOURS[path.severity]
            click.secho(
                f"[{path.severity.value.upper():8}] {path.name}",
                fg=colour, bold=True,
            )
            click.echo(f"  {path.description[:200]}")
            click.echo(f"  MITRE: {', '.join(path.mitre_techniques)}")
            click.echo(f"  Fix: {path.remediation[:160]}")
            click.echo()


@cli.command("rogue")
@click.option("--profiles", "profiles_file", required=True, type=click.Path(exists=True),
              help="JSON file containing list of installed profiles")
@click.option("--trusted-domains", default="",
              help="Comma-separated list of approved MDM domains")
@click.option("--ownership",
              type=click.Choice(["corporate", "byod"]), default="corporate")
@click.pass_context
def rogue_cmd(
    ctx: click.Context,
    profiles_file: str,
    trusted_domains: str,
    ownership: str,
) -> None:
    """Detect rogue or unauthorised MDM profiles on a device."""
    with open(profiles_file) as f:
        profiles = json.load(f)

    auditor = MDMSecurityAuditor(verbose=ctx.obj["verbose"])
    domains = [d.strip() for d in trusted_domains.split(",") if d.strip()]

    rogue = auditor.detect_rogue_mdm(
        profiles,
        trusted_mdm_domains=domains or None,
        device_ownership=ownership,
    )

    if not rogue:
        click.secho("No rogue profiles detected.", fg="green")
        return

    if ctx.obj["output"]:
        _save_json([r.to_dict() for r in rogue], ctx.obj["output"])
    else:
        click.secho(f"\n{len(rogue)} suspicious profile(s) detected:", bold=True)
        for r in rogue:
            colour = _SEVERITY_COLOURS[r.severity]
            click.secho(f"[{r.severity.value.upper():8}] {r.display_name}", fg=colour, bold=True)
            click.echo(f"  Organisation: {r.organization}")
            click.echo(f"  Server: {r.server_url or '(none)'}")
            click.echo(f"  Reason: {r.reason[:160]}")
            click.echo()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _print_findings(findings) -> None:
    if not findings:
        click.secho("No findings.", fg="green")
        return
    click.echo()
    for f in findings:
        colour = _SEVERITY_COLOURS[f.severity]
        click.secho(f"[{f.severity.value.upper():8}] {f.title}", fg=colour, bold=True)
        click.echo(f"  {f.description[:200]}")
        for ev in f.evidence[:2]:
            click.echo(f"  Evidence:    {ev[:100]}")
        click.echo(f"  Fix: {f.remediation[:160]}")
        if f.cwe_id:
            click.echo(f"  CWE: {f.cwe_id}")
        click.echo()


def _save_json(data, path: str) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    click.secho(f"Report saved to {path}", fg="green")


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
