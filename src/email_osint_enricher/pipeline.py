"""Core enrichment pipeline — orchestrates providers, scoring, and output."""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
from pathlib import Path
from typing import Optional

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from email_osint_enricher.config import load_config
from email_osint_enricher.email_utils import (
    classify_email,
    get_domain,
    is_google_email,
    mask_email,
    normalize_email,
)
from email_osint_enricher.output_writer import write_results
from email_osint_enricher.providers.ghunt_provider import GHuntProvider
from email_osint_enricher.providers.holehe_provider import HoleheProvider
from email_osint_enricher.schemas import (
    AppConfig,
    EnrichmentResult,
    GHuntResult,
    HoleheResult,
    InputRow,
    ProcessingStatus,
    RunSummary,
)
from email_osint_enricher.scoring import classify_holehe_services, score_result

logger = logging.getLogger("enricher")


class EnrichmentPipeline:
    """Main pipeline: takes InputRows, runs providers, scores, writes output."""

    def __init__(
        self,
        config: Optional[AppConfig] = None,
        output_dir: str = "output",
        providers_filter: Optional[list[str]] = None,
        force_ghunt: bool = False,
        dry_run: bool = False,
    ):
        self.config = config or load_config()
        self.output_dir = Path(output_dir)
        self.dry_run = dry_run
        self.force_ghunt = force_ghunt

        # Determine active providers
        self.active_providers: set[str] = set()
        if providers_filter:
            for p in providers_filter:
                p = p.lower().strip()
                if p in ("ghunt", "holehe"):
                    self.active_providers.add(p)
        else:
            if self.config.providers.get("ghunt", None) and self.config.providers["ghunt"].enabled:
                self.active_providers.add("ghunt")
            if self.config.providers.get("holehe", None) and self.config.providers["holehe"].enabled:
                self.active_providers.add("holehe")

        # Force from config
        ghunt_cfg = self.config.providers.get("ghunt")
        if ghunt_cfg and ghunt_cfg.force:
            self.force_ghunt = True

        # Init providers
        self.ghunt = GHuntProvider(
            timeout=self.config.providers.get("ghunt", AppConfig().providers["ghunt"]).timeout_seconds,
            raw_output_dir=self.output_dir / "raw" / "ghunt" if self.config.output.save_raw_json else None,
        )
        self.holehe = HoleheProvider(
            timeout=self.config.providers.get("holehe", AppConfig().providers["holehe"]).timeout_seconds,
            raw_output_dir=self.output_dir / "raw" / "holehe" if self.config.output.save_raw_json else None,
        )

        self.semaphore = asyncio.Semaphore(self.config.batch.concurrency)
        self.delay = self.config.batch.delay_seconds
        self.max_retries = self.config.batch.max_retries
        self.mask = self.config.logging.mask_emails

    async def process_single(self, row: InputRow) -> EnrichmentResult:
        """Process a single email through the pipeline."""
        email = row.email
        email_display = mask_email(email) if self.mask else email

        result = EnrichmentResult(
            email=email,
            email_normalized=normalize_email(email),
            email_domain=get_domain(email),
            email_type=classify_email(email).value,
            input_row_id=row.input_row_id,
            applicantId=row.applicantId,
            externalId=row.externalId,
            applicantName=row.applicantName,
            applicantCountry=row.applicantCountry,
            claim_value=row.claim_value,
            lead_score=row.lead_score,
            tier=row.tier,
        )

        if self.dry_run:
            result.status = ProcessingStatus.skipped.value
            result.error_message = "dry-run mode"
            logger.info(f"[DRY-RUN] Would process: {email_display}")
            # Still compute scoring with empty providers
            ghunt_res = GHuntResult()
            holehe_res = HoleheResult()
            result = score_result(result, ghunt_res, holehe_res, row)
            return result

        ghunt_res = GHuntResult()
        holehe_res = HoleheResult()
        errors: list[str] = []

        # GHunt
        if "ghunt" in self.active_providers:
            should_run = is_google_email(email, force=self.force_ghunt)
            if should_run:
                logger.info(f"Running GHunt for {email_display}")
                ghunt_res = await self._run_with_retry(
                    self.ghunt.enrich, email, "ghunt"
                )
            else:
                logger.debug(f"Skipping GHunt for non-Google email {email_display}")

        # Holehe
        if "holehe" in self.active_providers:
            logger.info(f"Running Holehe for {email_display}")
            holehe_res = await self._run_with_retry(
                self.holehe.enrich, email, "holehe"
            )
            # Classify services
            if holehe_res.success and holehe_res.registered_services_list:
                social, prof = classify_holehe_services(holehe_res.registered_services_list)
                holehe_res.social_services_count = social
                holehe_res.professional_services_count = prof

        # Map provider results to enrichment result
        result.ghunt_checked = ghunt_res.checked
        result.ghunt_success = ghunt_res.success
        result.ghunt_display_name = ghunt_res.display_name
        result.ghunt_gaia_id = ghunt_res.gaia_id
        result.ghunt_profile_photo_found = ghunt_res.profile_photo_found
        result.ghunt_profile_photo_url = ghunt_res.profile_photo_url
        result.ghunt_google_maps_reviews_found = ghunt_res.google_maps_reviews_found
        result.ghunt_youtube_found = ghunt_res.youtube_found
        result.ghunt_calendar_public_found = ghunt_res.calendar_public_found
        result.ghunt_drive_public_found = ghunt_res.drive_public_found
        result.ghunt_raw_json_path = ghunt_res.raw_json_path
        result.ghunt_confidence_score = ghunt_res.confidence_score

        result.holehe_checked = holehe_res.checked
        result.holehe_success = holehe_res.success
        result.holehe_registered_services_count = holehe_res.registered_services_count
        result.holehe_registered_services_list = (
            ", ".join(holehe_res.registered_services_list)
            if isinstance(holehe_res.registered_services_list, list)
            else str(holehe_res.registered_services_list)
        )
        result.holehe_social_services_count = holehe_res.social_services_count
        result.holehe_professional_services_count = holehe_res.professional_services_count
        result.holehe_recovery_hints_count = holehe_res.recovery_hints_count
        result.holehe_raw_json_path = holehe_res.raw_json_path
        result.holehe_confidence_score = holehe_res.confidence_score

        # Determine status
        any_checked = ghunt_res.checked or holehe_res.checked
        any_success = ghunt_res.success or holehe_res.success
        all_success = (
            (ghunt_res.success if ghunt_res.checked else True)
            and (holehe_res.success if holehe_res.checked else True)
        )

        if not any_checked:
            result.status = ProcessingStatus.skipped.value
        elif all_success:
            result.status = ProcessingStatus.success.value
        elif any_success:
            result.status = ProcessingStatus.partial.value
        else:
            result.status = ProcessingStatus.failed.value

        # Score
        result = score_result(result, ghunt_res, holehe_res, row)

        return result

    async def _run_with_retry(self, coro_fn, email: str, provider: str):
        """Run a provider coroutine with retries and exponential backoff."""
        last_exc = None
        for attempt in range(1, self.max_retries + 1):
            try:
                async with self.semaphore:
                    return await coro_fn(email)
            except Exception as e:
                last_exc = e
                wait = 2 ** attempt
                logger.warning(
                    f"{provider} attempt {attempt}/{self.max_retries} failed: {e}. "
                    f"Retrying in {wait}s..."
                )
                await asyncio.sleep(wait)

        # Final attempt without catching
        try:
            async with self.semaphore:
                return await coro_fn(email)
        except Exception as e:
            logger.error(f"{provider} all retries exhausted: {e}")
            # Return empty result based on provider
            if provider == "ghunt":
                return GHuntResult(checked=True, success=False)
            else:
                return HoleheResult(checked=True, success=False)

    async def process_batch(self, rows: list[InputRow]) -> tuple[list[EnrichmentResult], RunSummary]:
        """Process a batch of emails with progress bar and rate limiting."""
        started_at = dt.datetime.utcnow().isoformat()
        results: list[EnrichmentResult] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[cyan]{task.completed}/{task.total}"),
        ) as progress:
            task = progress.add_task("Enriching emails", total=len(rows))

            for row in rows:
                result = await self.process_single(row)
                results.append(result)
                progress.update(task, advance=1)

                # Rate limit delay between emails
                if self.delay > 0 and not self.dry_run:
                    await asyncio.sleep(self.delay)

        finished_at = dt.datetime.utcnow().isoformat()

        # Build summary
        summary = self._build_summary(results, started_at, finished_at)

        return results, summary

    def _build_summary(
        self,
        results: list[EnrichmentResult],
        started_at: str,
        finished_at: str,
    ) -> RunSummary:
        """Build run summary from results."""
        summary = RunSummary(
            started_at=started_at,
            finished_at=finished_at,
            total_emails=len(results),
            config_used=self.config.model_dump(),
        )

        tier_dist: dict[str, int] = {}
        footprint_scores: list[int] = []
        identity_scores: list[int] = []

        for r in results:
            summary.processed += 1
            if r.status == ProcessingStatus.success.value:
                summary.success += 1
            elif r.status == ProcessingStatus.partial.value:
                summary.partial += 1
            elif r.status == ProcessingStatus.failed.value:
                summary.failed += 1
            elif r.status == ProcessingStatus.skipped.value:
                summary.skipped += 1

            if r.ghunt_checked:
                summary.ghunt_calls += 1
            if r.ghunt_success:
                summary.ghunt_successes += 1
            if r.holehe_checked:
                summary.holehe_calls += 1
            if r.holehe_success:
                summary.holehe_successes += 1

            tier_dist[r.outreach_enrichment_tier] = tier_dist.get(r.outreach_enrichment_tier, 0) + 1
            footprint_scores.append(r.email_footprint_score)
            identity_scores.append(r.identity_confidence_score)

        summary.tier_distribution = tier_dist
        if footprint_scores:
            summary.avg_footprint_score = round(sum(footprint_scores) / len(footprint_scores), 2)
        if identity_scores:
            summary.avg_identity_score = round(sum(identity_scores) / len(identity_scores), 2)

        return summary

    def write_output(
        self,
        results: list[EnrichmentResult],
        summary: RunSummary,
    ) -> dict[str, str]:
        """Write results to disk."""
        errors = [r for r in results if r.status in (ProcessingStatus.failed.value,)]
        return write_results(
            results=results,
            errors=errors,
            summary=summary,
            output_dir=self.output_dir,
            config=self.config.output,
        )
