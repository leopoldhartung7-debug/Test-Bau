"""
MobileAudit CLI — run security assessments from the command line.

Usage examples:

  # Scan a USB-connected iOS device
  mobileaudit scan ios --serial 00008020-000...

  # Scan a USB-connected Android device
  mobileaudit scan android

  # Scan Android by ADB serial
  mobileaudit scan android --serial emulator-5554

  # Full scan with monitoring agent deployment
  mobileaudit scan ios --serial ... --deploy-agent --mdm-url https://mdm.corp.example.com

  # List connected ADB devices
  mobileaudit list-android
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import asdict
from typing import Optional

try:
    import click
except ImportError:
    sys.exit("click is required for the CLI. Install with: pip install click")

from .models import ConnectionType, Platform, Severity
from .scanner import DeviceConnection, MobileReconScanner


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=level,
    )


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """MobileAudit — Enterprise mobile device security assessment."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


@cli.group()
def scan() -> None:
    """Scan a mobile device for security issues."""


@scan.command("ios")
@click.option("--serial", default=None, help="iOS device UDID (default: first connected device)")
@click.option("--mdm-json", default=None, type=click.Path(exists=True),
              help="Path to MDM DeviceInformation JSON file (for MDM-mode scan)")
@click.option("--nvd-api-key", envvar="NVD_API_KEY", default=None,
              help="NIST NVD API key for higher rate limits")
@click.option("--mdm-url", envvar="MDM_URL", default="",
              help="MDM server URL for monitoring agent push")
@click.option("--webhook-url", envvar="ALERT_WEBHOOK_URL", default="",
              help="Webhook URL for security alerts")
@click.option("--deploy-agent", is_flag=True, default=False,
              help="Deploy monitoring agent after scan")
@click.option("--output", "-o", type=click.Choice(["text", "json"]), default="text",
              help="Output format")
@click.option("--offline", is_flag=True, default=False,
              help="Skip NVD queries (use built-in signatures only)")
@click.pass_context
def scan_ios(
    ctx: click.Context,
    serial: Optional[str],
    mdm_json: Optional[str],
    nvd_api_key: Optional[str],
    mdm_url: str,
    webhook_url: str,
    deploy_agent: bool,
    output: str,
    offline: bool,
) -> None:
    """Scan an iOS device (USB or MDM)."""
    scanner = MobileReconScanner(
        nvd_api_key=nvd_api_key,
        mdm_server_url=mdm_url,
        alert_webhook_url=webhook_url,
        fetch_nvd=not offline,
    )

    if mdm_json:
        with open(mdm_json) as f:
            mdm_info = json.load(f)
        conn = DeviceConnection(
            platform=Platform.IOS,
            connection_type=ConnectionType.MDM,
            mdm_device_info=mdm_info,
        )
    else:
        conn = DeviceConnection(
            platform=Platform.IOS,
            connection_type=ConnectionType.USB,
            serial=serial,
        )

    result = scanner.full_scan(conn, deploy_agent=deploy_agent)
    _print_result(result, output)


@scan.command("android")
@click.option("--serial", default=None, help="ADB device serial (default: auto-detect)")
@click.option("--mdm-json", default=None, type=click.Path(exists=True),
              help="Path to Android Enterprise EMM inventory JSON")
@click.option("--nvd-api-key", envvar="NVD_API_KEY", default=None)
@click.option("--mdm-url", envvar="MDM_URL", default="")
@click.option("--webhook-url", envvar="ALERT_WEBHOOK_URL", default="")
@click.option("--deploy-agent", is_flag=True, default=False)
@click.option("--output", "-o", type=click.Choice(["text", "json"]), default="text")
@click.option("--offline", is_flag=True, default=False)
@click.pass_context
def scan_android(
    ctx: click.Context,
    serial: Optional[str],
    mdm_json: Optional[str],
    nvd_api_key: Optional[str],
    mdm_url: str,
    webhook_url: str,
    deploy_agent: bool,
    output: str,
    offline: bool,
) -> None:
    """Scan an Android device (USB via ADB or MDM)."""
    scanner = MobileReconScanner(
        nvd_api_key=nvd_api_key,
        mdm_server_url=mdm_url,
        alert_webhook_url=webhook_url,
        fetch_nvd=not offline,
    )

    if mdm_json:
        with open(mdm_json) as f:
            mdm_info = json.load(f)
        conn = DeviceConnection(
            platform=Platform.ANDROID,
            connection_type=ConnectionType.MDM,
            mdm_device_info=mdm_info,
        )
    else:
        conn = DeviceConnection(
            platform=Platform.ANDROID,
            connection_type=ConnectionType.USB,
            adb_serial=serial,
        )

    result = scanner.full_scan(conn, deploy_agent=deploy_agent)
    _print_result(result, output)


@cli.command("list-android")
def list_android() -> None:
    """List connected Android devices (ADB)."""
    from .android.fingerprint import list_connected_devices
    devices = list_connected_devices()
    if not devices:
        click.echo("No ADB devices found. Ensure USB debugging is enabled.")
        return
    click.echo(f"Found {len(devices)} device(s):")
    for d in devices:
        click.echo(f"  {d}")


def _print_result(result: "ScanResult", fmt: str) -> None:  # noqa: F821 — forward ref
    from .models import Severity

    SEVERITY_COLOURS = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "yellow",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "green",
    }

    if fmt == "json":
        # Minimal JSON-serialisable output
        out = {
            "device": {
                "udid": result.profile.udid,
                "model": result.profile.model,
                "platform": result.profile.platform.value,
                "os_version": result.profile.os_version,
                "is_jailbroken": result.profile.is_jailbroken,
                "is_rooted": result.profile.is_rooted,
            },
            "risk_score": result.risk_score,
            "risk_level": result.risk_level.value,
            "vulnerabilities": [
                {
                    "cve_id": v.cve_id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "exploit_available": v.exploit_available,
                }
                for v in result.vulnerabilities
            ],
            "compliance": {
                "score": result.compliance_report.overall_score,
                "risk_level": result.compliance_report.risk_level.value,
                "failed_controls": [
                    {
                        "id": c.control_id,
                        "title": c.title,
                        "severity": c.severity.value,
                        "remediation": c.remediation,
                    }
                    for c in result.compliance_report.failed()
                ],
            },
            "iocs": [
                {
                    "name": i.name,
                    "severity": i.severity.value,
                    "threat_family": i.threat_family,
                    "confidence": i.confidence,
                    "indicator_type": i.indicator_type,
                    "value": i.value,
                }
                for i in result.iocs
            ],
            "scan_duration_seconds": result.scan_duration_seconds,
        }
        click.echo(json.dumps(out, indent=2))
        return

    # Text output
    click.echo()
    click.secho("=" * 60, bold=True)
    click.secho("  MobileAudit Security Assessment Report", bold=True)
    click.secho("=" * 60, bold=True)
    click.echo(result.summary())
    click.echo()

    if result.iocs:
        click.secho(f"[!] Compromise Indicators ({len(result.iocs)})", fg="red", bold=True)
        for ioc in result.iocs:
            colour = SEVERITY_COLOURS[ioc.severity]
            click.secho(
                f"  [{ioc.severity.value.upper():8}] [{ioc.confidence:.0%} confidence] "
                f"{ioc.name}",
                fg=colour,
            )
            click.echo(f"           Threat: {ioc.threat_family}")
        click.echo()

    if result.vulnerabilities:
        click.secho(
            f"[!] Vulnerabilities ({len(result.vulnerabilities)})", fg="yellow", bold=True
        )
        for v in result.vulnerabilities[:20]:  # cap display at 20
            exploit_tag = " [EXPLOIT AVAILABLE]" if v.exploit_available else ""
            colour = SEVERITY_COLOURS[v.severity]
            click.secho(
                f"  [{v.severity.value.upper():8}] CVSS {v.cvss_score:.1f}{exploit_tag} "
                f"{v.cve_id}: {v.title[:60]}",
                fg=colour,
            )
        if len(result.vulnerabilities) > 20:
            click.echo(f"  ... and {len(result.vulnerabilities) - 20} more (use --output json for full list)")
        click.echo()

    failed = result.compliance_report.failed()
    if failed:
        click.secho(f"[!] Failed Compliance Controls ({len(failed)})", fg="yellow", bold=True)
        for c in failed:
            colour = SEVERITY_COLOURS[c.severity]
            click.secho(f"  [{c.severity.value.upper():8}] {c.control_id}: {c.title}", fg=colour)
            click.echo(f"             Remediation: {c.remediation}")
        click.echo()

    risk_colour = SEVERITY_COLOURS[result.risk_level]
    click.secho(
        f"Overall Risk: {result.risk_level.value.upper()} ({result.risk_score:.0f}/100)",
        fg=risk_colour,
        bold=True,
    )
    click.echo(f"Scan completed in {result.scan_duration_seconds:.1f}s")


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
