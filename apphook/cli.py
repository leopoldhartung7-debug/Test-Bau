"""
AppHook CLI — dynamic instrumentation from the command line.

Usage examples:

  # Attach and bypass SSL pinning (routes through Burp on :8080)
  apphook ssl-bypass com.example.app --platform android --proxy-port 8080

  # Trace crypto + network calls for 30 seconds
  apphook trace com.example.app --platform ios --categories crypto,network --duration 30

  # Inject a named behavior
  apphook inject com.example.app --behavior bypass_root_detect --platform android

  # Automated vulnerability scan (trace for 60s then report)
  apphook scan com.example.app --platform android --output report.json
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Optional

try:
    import click
except ImportError:
    sys.exit("click is required. Install with: pip install click")

from .models import Platform, TraceCategory
from .instrumentor import RuntimeInstrumentor

_CAT_MAP = {c.value: c for c in TraceCategory}
_ALL_CATEGORIES = list(TraceCategory)


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=logging.DEBUG if verbose else logging.INFO,
    )


@click.group()
@click.option("--verbose", "-v", is_flag=True)
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """AppHook — mobile app runtime instrumentation & security testing."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


def _common_options(fn):
    fn = click.option("--platform", "-p",
                      type=click.Choice(["ios", "android"]), required=True)(fn)
    fn = click.option("--device", default=None, help="Frida device serial")(fn)
    fn = click.option("--spawn", is_flag=True, default=False,
                      help="Spawn fresh process instead of attaching")(fn)
    fn = click.option("--proxy-host", default="", envvar="MITM_PROXY_HOST")(fn)
    fn = click.option("--proxy-port", default=8080, envvar="MITM_PROXY_PORT")(fn)
    return fn


@cli.command("ssl-bypass")
@click.argument("bundle_id")
@_common_options
@click.option("--duration", default=0, type=int,
              help="Seconds to keep bypass active (0 = indefinitely, Ctrl-C to stop)")
@click.pass_context
def ssl_bypass(
    ctx: click.Context,
    bundle_id: str,
    platform: str,
    device: Optional[str],
    spawn: bool,
    proxy_host: str,
    proxy_port: int,
    duration: int,
) -> None:
    """Bypass certificate pinning in a running app."""
    instr = RuntimeInstrumentor(
        platform=Platform(platform),
        device_id=device,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
    )
    session = instr.attach(bundle_id, spawn=spawn)
    if not session.is_active:
        click.secho("Failed to attach.", fg="red")
        sys.exit(1)

    ok = instr.bypass_ssl_pinning()
    if ok:
        click.secho(f"SSL pinning bypass injected for {bundle_id}", fg="green")
        if proxy_host:
            click.echo(f"Route device traffic through proxy: {proxy_host}:{proxy_port}")
    else:
        click.secho("SSL bypass injection failed.", fg="red")
        sys.exit(1)

    _wait(duration, "SSL bypass active")
    fired = instr.get_ssl_bypass_status()
    click.echo(f"\nHooks that fired: {fired}")
    instr.detach()


@cli.command("trace")
@click.argument("bundle_id")
@_common_options
@click.option("--categories", default="crypto,network,keychain,filesystem,biometrics",
              help="Comma-separated trace categories")
@click.option("--duration", default=30, type=int,
              help="How long to trace (seconds)")
@click.option("--output", "-o", default=None, type=click.Path(),
              help="Save events as JSON to this file")
@click.pass_context
def trace_cmd(
    ctx: click.Context,
    bundle_id: str,
    platform: str,
    device: Optional[str],
    spawn: bool,
    proxy_host: str,
    proxy_port: int,
    categories: str,
    duration: int,
    output: Optional[str],
) -> None:
    """Trace sensitive API calls at runtime."""
    cats = [_CAT_MAP[c.strip()] for c in categories.split(",") if c.strip() in _CAT_MAP]
    if not cats:
        click.secho("No valid categories specified.", fg="red")
        sys.exit(1)

    instr = RuntimeInstrumentor(Platform(platform), device_id=device)
    session = instr.attach(bundle_id, spawn=spawn)
    if not session.is_active:
        click.secho("Failed to attach.", fg="red")
        sys.exit(1)

    trace = instr.start_tracing(cats)
    click.secho(f"Tracing {cats} for {duration}s ...", fg="cyan")
    _wait(duration, "Tracing")
    instr.stop_tracing()

    click.echo(f"\nCaptured {len(trace.events)} events.")
    records = trace.to_json_records()

    if output:
        with open(output, "w") as f:
            json.dump(records, f, indent=2)
        click.secho(f"Saved to {output}", fg="green")
    else:
        for rec in records[:50]:
            click.echo(json.dumps(rec))
        if len(records) > 50:
            click.echo(f"... {len(records) - 50} more (use --output to save all)")

    instr.detach()


@cli.command("inject")
@click.argument("bundle_id")
@_common_options
@click.option("--behavior", required=True, help="Behavior name or path to .js file")
@click.option("--opts", default="{}", help="JSON options dict for the behavior")
@click.option("--duration", default=0, type=int)
@click.pass_context
def inject_cmd(
    ctx: click.Context,
    bundle_id: str,
    platform: str,
    device: Optional[str],
    spawn: bool,
    proxy_host: str,
    proxy_port: int,
    behavior: str,
    opts: str,
    duration: int,
) -> None:
    """Inject a security-test behavior into a running app."""
    import pathlib

    instr = RuntimeInstrumentor(Platform(platform), device_id=device)
    session = instr.attach(bundle_id, spawn=spawn)
    if not session.is_active:
        click.secho("Failed to attach.", fg="red")
        sys.exit(1)

    # Determine if behavior is a named built-in or a .js file path
    p = pathlib.Path(behavior)
    if p.suffix == ".js" and p.exists():
        script_content = p.read_text()
        ok = instr.inject_behavior(script_content)
    else:
        try:
            opts_dict = json.loads(opts)
        except json.JSONDecodeError:
            opts_dict = {}
        ok = instr.inject_behavior(behavior, opts=opts_dict)

    if ok:
        click.secho(f"Behavior '{behavior}' activated", fg="green")
    else:
        click.secho(f"Failed to activate '{behavior}'", fg="red")

    _wait(duration, f"Behavior '{behavior}' active")
    instr.detach()


@cli.command("scan")
@click.argument("bundle_id")
@_common_options
@click.option("--duration", default=60, type=int,
              help="Seconds to observe app behaviour before generating report")
@click.option("--output", "-o", default=None, type=click.Path())
@click.option("--ssl-bypass", "do_ssl", is_flag=True, default=False,
              help="Also bypass SSL pinning before tracing")
@click.pass_context
def scan_cmd(
    ctx: click.Context,
    bundle_id: str,
    platform: str,
    device: Optional[str],
    spawn: bool,
    proxy_host: str,
    proxy_port: int,
    duration: int,
    output: Optional[str],
    do_ssl: bool,
) -> None:
    """Automated vulnerability scan (trace + analyse)."""
    instr = RuntimeInstrumentor(
        Platform(platform), device_id=device,
        proxy_host=proxy_host, proxy_port=proxy_port,
    )
    session = instr.attach(bundle_id, spawn=spawn)
    if not session.is_active:
        click.secho("Failed to attach.", fg="red")
        sys.exit(1)

    if do_ssl:
        instr.bypass_ssl_pinning()

    instr.start_tracing(list(TraceCategory))
    click.secho(f"Observing {bundle_id} for {duration}s ...", fg="cyan")
    _wait(duration, "Scanning")
    instr.stop_tracing()

    report = instr.scan_vulnerabilities()
    instr.detach()

    _print_report(report, output)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _wait(seconds: int, label: str) -> None:
    if seconds <= 0:
        click.echo(f"{label} — press Ctrl-C to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        try:
            for remaining in range(seconds, 0, -1):
                click.echo(f"\r{label} — {remaining}s remaining...", nl=False)
                time.sleep(1)
            click.echo()
        except KeyboardInterrupt:
            click.echo()


def _print_report(report, output_path: Optional[str]) -> None:
    from .models import Severity

    COLOURS = {
        Severity.CRITICAL: "red", Severity.HIGH: "yellow",
        Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "green",
    }

    if output_path:
        data = {
            "report_id": report.report_id,
            "app": report.app.bundle_id,
            "generated_at": report.generated_at.isoformat(),
            "scan_duration_seconds": report.scan_duration_seconds,
            "vulnerabilities": [
                {
                    "id": v.vuln_id, "title": v.title,
                    "severity": v.severity.value, "category": v.category,
                    "cwe": v.cwe_id, "description": v.description,
                    "evidence": v.evidence, "remediation": v.remediation,
                }
                for v in report.vulnerabilities
            ],
        }
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        click.secho(f"Report saved to {output_path}", fg="green")
        return

    click.secho("\n" + "=" * 60, bold=True)
    click.secho("  AppHook Vulnerability Report", bold=True)
    click.secho("=" * 60, bold=True)
    click.echo(report.summary())
    click.echo()

    for vuln in report.vulnerabilities:
        colour = COLOURS[vuln.severity]
        click.secho(f"[{vuln.severity.value.upper():8}] {vuln.title}", fg=colour, bold=True)
        click.echo(f"  Control:     {vuln.category}")
        if vuln.cwe_id:
            click.echo(f"  CWE:         {vuln.cwe_id}")
        click.echo(f"  Description: {vuln.description[:140]}")
        for ev in vuln.evidence[:3]:
            click.echo(f"  Evidence:    {ev[:100]}")
        click.echo(f"  Remediation: {vuln.remediation[:140]}")
        click.echo()


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
