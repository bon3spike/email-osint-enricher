"""CLI interface for Email OSINT Enricher."""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from email_osint_enricher import __version__
from email_osint_enricher.config import load_config
from email_osint_enricher.email_utils import (
    classify_email,
    get_domain,
    has_mx_record,
    is_google_workspace,
    mask_email,
    normalize_email,
)
from email_osint_enricher.input_loader import load_input
from email_osint_enricher.logging_utils import setup_logging
from email_osint_enricher.pipeline import EnrichmentPipeline
from email_osint_enricher.providers import PROVIDER_REGISTRY, PROVIDER_META
from email_osint_enricher.schemas import InputRow

ALL_PROVIDERS = ",".join(PROVIDER_REGISTRY.keys())

app = typer.Typer(
    name="email-osint-enricher",
    help="Email OSINT enrichment tool — 11 providers, scored output.",
    add_completion=False,
)
console = Console()


def version_callback(value: bool):
    if value:
        console.print(f"email-osint-enricher v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True,
        help="Show version and exit.",
    ),
):
    """Email OSINT Enricher — enrich email lists with public OSINT signals."""
    pass


# ── list-providers ───────────────────────────────────────────────────────────

@app.command("list-providers")
def list_providers(
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
):
    """Show all available providers and their status."""
    cfg = load_config(config) if config else None

    table = Table(title="Available Providers", show_lines=True)
    table.add_column("Provider", style="cyan", no_wrap=True)
    table.add_column("Default", justify="center")
    table.add_column("Installed", justify="center")
    table.add_column("API Key", justify="center")
    table.add_column("Configured", justify="center")
    table.add_column("Status", style="bold")

    for name in PROVIDER_REGISTRY:
        meta = PROVIDER_META.get(name, {})
        default_enabled = meta.get("default_enabled", False)
        requires_api = meta.get("requires_api_key", False)
        binary = meta.get("binary")
        api_key_env = meta.get("api_key_env", "")

        # Check installed
        installed = True
        if binary:
            installed = shutil.which(binary) is not None

        # Check API key configured
        api_configured = "—"
        if api_key_env:
            api_configured = "✓" if os.getenv(api_key_env) else "✗"

        # Check config
        configured = "—"
        if cfg and name in cfg.providers:
            pc = cfg.providers[name]
            configured = "✓" if pc.enabled else "off"

        # Status
        if installed and (not requires_api or os.getenv(api_key_env, "")):
            status = "[green]ready[/green]"
        elif not installed and binary:
            status = "[yellow]not installed[/yellow]"
        elif requires_api and not os.getenv(api_key_env, ""):
            status = "[yellow]no API key[/yellow]"
        else:
            status = "[green]ready[/green]"

        table.add_row(
            name,
            "✓" if default_enabled else "—",
            "✓" if installed else "✗",
            ("req" if requires_api else ("opt" if api_key_env else "—")),
            configured,
            status,
        )

    console.print(table)


# ── single ───────────────────────────────────────────────────────────────────

@app.command()
def single(
    email: str = typer.Option(..., "--email", "-e", help="Email address to enrich"),
    out: str = typer.Option("output", "--out", "-o", help="Output directory"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
    providers: Optional[str] = typer.Option(
        None, "--providers", "-p",
        help=f"Comma-separated providers to enable: {ALL_PROVIDERS}",
    ),
    disable_providers: Optional[str] = typer.Option(
        None, "--disable-providers",
        help="Comma-separated providers to disable (overrides config/defaults)",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Dry run — no actual provider calls"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP/SOCKS proxy URL"),
):
    """Enrich a single email address."""
    cfg = load_config(config)
    log_dir = Path(out) / "logs"
    setup_logging(cfg.logging.level, log_dir)

    domain = get_domain(email)
    mx_ok = has_mx_record(domain) if domain else False
    gws = is_google_workspace(domain) if domain else False

    console.print(Panel(
        f"[bold]Email OSINT Enricher[/bold] v{__version__}\n"
        f"Mode: single email\n"
        f"Email: {mask_email(email) if cfg.logging.mask_emails else email}\n"
        f"Domain: {domain}\n"
        f"Type: {classify_email(email).value}\n"
        f"Normalized: {normalize_email(email)}\n"
        f"MX records: {'✓' if mx_ok else '✗'}\n"
        f"Google Workspace: {'✓' if gws else '—'}\n"
        f"Dry run: {dry_run}",
        title="🔍 Enrichment",
    ))

    providers_list = providers.split(",") if providers else None
    disable_list = disable_providers.split(",") if disable_providers else None
    row = InputRow(email=email, input_row_id=0)

    pipeline = EnrichmentPipeline(
        config=cfg,
        output_dir=out,
        providers_filter=providers_list,
        disabled_providers=disable_list,
        dry_run=dry_run,
        proxy=proxy,
    )

    result = asyncio.run(pipeline.process_single(row))

    results = [result]
    summary = pipeline._build_summary(results, result.processed_at, result.processed_at)
    paths = pipeline.write_output(results, summary)

    _print_result_table([result])
    console.print(f"\n[green]Output files:[/green]")
    for name, path in paths.items():
        console.print(f"  {name}: {path}")


# ── batch ────────────────────────────────────────────────────────────────────

@app.command()
def batch(
    input: str = typer.Option(..., "--input", "-i", help="Input CSV or XLSX file"),
    email_column: str = typer.Option("email", "--email-column", "-e", help="Email column name"),
    sheet: Optional[str] = typer.Option(None, "--sheet", "-s", help="Excel sheet name"),
    out: str = typer.Option("output", "--out", "-o", help="Output directory"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
    providers: Optional[str] = typer.Option(
        None, "--providers", "-p",
        help=f"Comma-separated providers to enable: {ALL_PROVIDERS}",
    ),
    disable_providers: Optional[str] = typer.Option(
        None, "--disable-providers",
        help="Comma-separated providers to disable",
    ),
    concurrency: Optional[int] = typer.Option(
        None, "--concurrency", "-j",
        help="Number of emails to process in parallel (default: from config, usually 3)",
    ),
    delay: Optional[float] = typer.Option(
        None, "--delay",
        help="Delay in seconds between emails (default: from config, usually 1.5)",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Dry run — validate input only"),
    resume: bool = typer.Option(False, "--resume", help="Resume interrupted batch"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP/SOCKS proxy URL"),
):
    """Enrich a batch of emails from CSV or XLSX."""
    cfg = load_config(config)
    # Override batch settings from CLI flags
    if concurrency is not None:
        cfg.batch.concurrency = concurrency
    if delay is not None:
        cfg.batch.delay_seconds = delay
    log_dir = Path(out) / "logs"
    setup_logging(cfg.logging.level, log_dir)

    rows = load_input(input, email_column=email_column, sheet=sheet)

    console.print(Panel(
        f"[bold]Email OSINT Enricher[/bold] v{__version__}\n"
        f"Mode: batch\n"
        f"Input: {input}\n"
        f"Emails loaded: {len(rows)}\n"
        f"Providers: {providers or 'all enabled'}\n"
        f"Disabled: {disable_providers or 'none'}\n"
        f"Resume: {resume}\n"
        f"Proxy: {proxy or 'none'}\n"
        f"Dry run: {dry_run}",
        title="🔍 Batch Enrichment",
    ))

    providers_list = providers.split(",") if providers else None
    disable_list = disable_providers.split(",") if disable_providers else None

    pipeline = EnrichmentPipeline(
        config=cfg,
        output_dir=out,
        providers_filter=providers_list,
        disabled_providers=disable_list,
        dry_run=dry_run,
        resume=resume,
        proxy=proxy,
    )

    results, summary = asyncio.run(pipeline.process_batch(rows))
    paths = pipeline.write_output(results, summary)

    _print_summary(summary)
    _print_result_table(results[:20])

    console.print(f"\n[green]Output files:[/green]")
    for name, path in paths.items():
        console.print(f"  {name}: {path}")


# ── Output helpers ───────────────────────────────────────────────────────────

def _print_result_table(results):
    """Print a rich table of results."""
    table = Table(title="Enrichment Results", show_lines=True)
    table.add_column("Email", style="cyan", max_width=30)
    table.add_column("Type", style="dim")
    table.add_column("Status", style="bold")
    table.add_column("Holehe", style="blue")
    table.add_column("Profiles", style="magenta")
    table.add_column("Cyber/Rep", style="cyan")
    table.add_column("Phone", style="yellow")
    table.add_column("Final", justify="right")
    table.add_column("Tier", style="bold")

    for r in results:
        status_color = {
            "success": "green", "partial": "yellow",
            "failed": "red", "skipped": "dim",
        }.get(r.status, "white")

        tier_color = {
            "Strong": "green", "Medium": "yellow",
            "Weak": "red", "No Signal": "dim",
        }.get(r.outreach_enrichment_tier, "white")

        # Holehe
        holehe_info = ""
        if r.holehe_checked:
            holehe_info = f"{'✓' if r.holehe_success else '✗'}"
            if r.holehe_registered_services_count > 0:
                holehe_info += f" {r.holehe_registered_services_count}svc"

        # Blackbird / Maigret / Sherlock / Socialscan (combined profiles)
        parts = []
        if r.blackbird_checked and r.blackbird_success:
            bb_total = r.blackbird_email_profiles_count + r.blackbird_username_profiles_count
            parts.append(f"BB:{bb_total}")
        if r.maigret_checked and r.maigret_success:
            parts.append(f"M:{r.maigret_profiles_count}")
        if r.sherlock_checked and r.sherlock_success:
            parts.append(f"S:{r.sherlock_profiles_count}")
        if r.socialscan_checked and r.socialscan_success:
            parts.append(f"SS:{r.socialscan_registered_count}")
        if r.gravatar_checked and r.gravatar_has_profile:
            parts.append("GR:✓")
        profile_info = " ".join(parts) if parts else "—"

        # Cyber & Reputation (HudsonRock + EmailRep)
        cyber_parts = []
        if r.hudsonrock_checked and r.hudsonrock_success:
            if r.hudsonrock_is_compromised:
                cyber_parts.append(f"HR:⚠{r.hudsonrock_stealers_count}")
            else:
                cyber_parts.append("HR:✓")
        if r.emailrep_checked:
            tag = "✓" if r.emailrep_success else "✗"
            if r.emailrep_reputation:
                tag += f" {r.emailrep_reputation[:4]}"
            cyber_parts.append(f"ER:{tag}")
        cyber_info = " ".join(cyber_parts) if cyber_parts else "—"

        # Phone
        phone_info = ""
        if r.phone_extractor_checked:
            if r.phone_candidate_best:
                phone_info = f"✓ {r.phone_candidate_best[:12]}"
            elif r.phone_candidates_count > 0:
                phone_info = f"? {r.phone_candidates_count}"
            else:
                phone_info = "—"

        table.add_row(
            mask_email(r.email),
            r.email_type,
            f"[{status_color}]{r.status}[/{status_color}]",
            holehe_info,
            profile_info,
            cyber_info,
            phone_info,
            str(r.final_enrichment_score),
            f"[{tier_color}]{r.outreach_enrichment_tier}[/{tier_color}]",
        )

    console.print(table)


def _print_summary(summary):
    """Print run summary."""

    def _prov_stat(label: str, name: str) -> str:
        calls = getattr(summary, f"{name}_calls", 0)
        successes = getattr(summary, f"{name}_successes", 0)
        return f"{label}: {successes}/{calls}"

    provider_lines = [
        " | ".join([
            _prov_stat("Holehe", "holehe"),
            _prov_stat("Blackbird", "blackbird"),
            _prov_stat("Maigret", "maigret"),
        ]),
        " | ".join([
            _prov_stat("Sherlock", "sherlock"),
            _prov_stat("Phone", "phone_extractor"),
            _prov_stat("EmailRep", "emailrep"),
        ]),
        " | ".join([
            _prov_stat("Mosint", "mosint"),
            _prov_stat("EmailCrawlr", "emailcrawlr"),
            _prov_stat("HudsonRock", "hudsonrock"),
        ]),
        " | ".join([
            _prov_stat("Gravatar", "gravatar"),
            _prov_stat("Socialscan", "socialscan"),
        ]),
    ]

    console.print(Panel(
        f"Total: {summary.total_emails} | "
        f"[green]Success: {summary.success}[/green] | "
        f"[yellow]Partial: {summary.partial}[/yellow] | "
        f"[red]Failed: {summary.failed}[/red] | "
        f"Skipped: {summary.skipped}\n"
        + "\n".join(provider_lines) + "\n"
        f"Profiles discovered: {summary.total_profiles_discovered} | "
        f"Phone candidates: {summary.total_phone_candidates}\n"
        f"Avg Footprint: {summary.avg_footprint_score:.1f} | "
        f"Avg Identity: {summary.avg_identity_score:.1f} | "
        f"Avg Final: {summary.avg_final_score:.1f}\n"
        f"Tiers: {summary.tier_distribution}",
        title="📊 Run Summary",
    ))


if __name__ == "__main__":
    app()
