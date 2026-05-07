"""CLI interface for Email OSINT Enricher."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from email_osint_enricher import __version__
from email_osint_enricher.config import load_config
from email_osint_enricher.email_utils import classify_email, get_domain, mask_email, normalize_email
from email_osint_enricher.input_loader import load_input
from email_osint_enricher.logging_utils import setup_logging
from email_osint_enricher.pipeline import EnrichmentPipeline
from email_osint_enricher.schemas import InputRow

app = typer.Typer(
    name="email-osint-enricher",
    help="Email OSINT enrichment tool using GHunt and Holehe.",
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


@app.command()
def single(
    email: str = typer.Option(..., "--email", "-e", help="Email address to enrich"),
    out: str = typer.Option("output", "--out", "-o", help="Output directory"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
    providers: Optional[str] = typer.Option(
        None, "--providers", "-p",
        help="Comma-separated providers to use: ghunt,holehe",
    ),
    force_ghunt: bool = typer.Option(False, "--force-ghunt", help="Run GHunt even for non-Gmail"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Dry run — no actual provider calls"),
):
    """Enrich a single email address."""
    cfg = load_config(config)
    log_dir = Path(out) / "logs"
    setup_logging(cfg.logging.level, log_dir)

    console.print(Panel(
        f"[bold]Email OSINT Enricher[/bold] v{__version__}\n"
        f"Mode: single email\n"
        f"Email: {mask_email(email) if cfg.logging.mask_emails else email}\n"
        f"Domain: {get_domain(email)}\n"
        f"Type: {classify_email(email).value}\n"
        f"Normalized: {normalize_email(email)}\n"
        f"Dry run: {dry_run}",
        title="🔍 Enrichment",
    ))

    providers_list = providers.split(",") if providers else None
    row = InputRow(email=email, input_row_id=0)

    pipeline = EnrichmentPipeline(
        config=cfg,
        output_dir=out,
        providers_filter=providers_list,
        force_ghunt=force_ghunt,
        dry_run=dry_run,
    )

    result = asyncio.run(pipeline.process_single(row))

    # Write output
    results = [result]
    summary = pipeline._build_summary(results, result.processed_at, result.processed_at)
    paths = pipeline.write_output(results, summary)

    # Display result
    _print_result_table([result])
    console.print(f"\n[green]Output files:[/green]")
    for name, path in paths.items():
        console.print(f"  {name}: {path}")


@app.command()
def batch(
    input: str = typer.Option(..., "--input", "-i", help="Input CSV or XLSX file"),
    email_column: str = typer.Option("email", "--email-column", "-e", help="Email column name"),
    sheet: Optional[str] = typer.Option(None, "--sheet", "-s", help="Excel sheet name"),
    out: str = typer.Option("output", "--out", "-o", help="Output directory"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
    providers: Optional[str] = typer.Option(
        None, "--providers", "-p",
        help="Comma-separated providers: ghunt,holehe",
    ),
    force_ghunt: bool = typer.Option(False, "--force-ghunt", help="Run GHunt even for non-Gmail"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Dry run — validate input only"),
):
    """Enrich a batch of emails from CSV or XLSX."""
    cfg = load_config(config)
    log_dir = Path(out) / "logs"
    logger = setup_logging(cfg.logging.level, log_dir)

    # Load input
    rows = load_input(input, email_column=email_column, sheet=sheet)

    console.print(Panel(
        f"[bold]Email OSINT Enricher[/bold] v{__version__}\n"
        f"Mode: batch\n"
        f"Input: {input}\n"
        f"Emails loaded: {len(rows)}\n"
        f"Providers: {providers or 'all enabled'}\n"
        f"Dry run: {dry_run}",
        title="🔍 Batch Enrichment",
    ))

    providers_list = providers.split(",") if providers else None

    pipeline = EnrichmentPipeline(
        config=cfg,
        output_dir=out,
        providers_filter=providers_list,
        force_ghunt=force_ghunt,
        dry_run=dry_run,
    )

    results, summary = asyncio.run(pipeline.process_batch(rows))

    # Write output
    paths = pipeline.write_output(results, summary)

    # Print summary
    _print_summary(summary)
    _print_result_table(results[:20])  # First 20 rows

    console.print(f"\n[green]Output files:[/green]")
    for name, path in paths.items():
        console.print(f"  {name}: {path}")


def _print_result_table(results):
    """Print a rich table of results."""
    table = Table(title="Enrichment Results", show_lines=True)
    table.add_column("Email", style="cyan", max_width=30)
    table.add_column("Type", style="dim")
    table.add_column("Status", style="bold")
    table.add_column("GHunt", style="green")
    table.add_column("Holehe", style="blue")
    table.add_column("Footprint", justify="right")
    table.add_column("Identity", justify="right")
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

        ghunt_info = ""
        if r.ghunt_checked:
            ghunt_info = f"{'✓' if r.ghunt_success else '✗'}"
            if r.ghunt_display_name:
                ghunt_info += f" {r.ghunt_display_name[:15]}"

        holehe_info = ""
        if r.holehe_checked:
            holehe_info = f"{'✓' if r.holehe_success else '✗'}"
            if r.holehe_registered_services_count > 0:
                holehe_info += f" {r.holehe_registered_services_count} svc"

        table.add_row(
            mask_email(r.email),
            r.email_type,
            f"[{status_color}]{r.status}[/{status_color}]",
            ghunt_info,
            holehe_info,
            str(r.email_footprint_score),
            str(r.identity_confidence_score),
            f"[{tier_color}]{r.outreach_enrichment_tier}[/{tier_color}]",
        )

    console.print(table)


def _print_summary(summary):
    """Print run summary."""
    console.print(Panel(
        f"Total: {summary.total_emails} | "
        f"[green]Success: {summary.success}[/green] | "
        f"[yellow]Partial: {summary.partial}[/yellow] | "
        f"[red]Failed: {summary.failed}[/red] | "
        f"Skipped: {summary.skipped}\n"
        f"GHunt: {summary.ghunt_successes}/{summary.ghunt_calls} | "
        f"Holehe: {summary.holehe_successes}/{summary.holehe_calls}\n"
        f"Avg Footprint: {summary.avg_footprint_score} | "
        f"Avg Identity: {summary.avg_identity_score}\n"
        f"Tiers: {summary.tier_distribution}",
        title="📊 Run Summary",
    ))


if __name__ == "__main__":
    app()
