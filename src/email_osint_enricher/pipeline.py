"""Core enrichment pipeline — orchestrates providers, scoring, and output."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
from pathlib import Path
from typing import Optional

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from email_osint_enricher.config import load_config
from email_osint_enricher.email_utils import (
    classify_email,
    get_domain,
    has_mx_record,
    is_google_email,
    is_google_workspace,
    mask_email,
    normalize_email,
    precheck_domains,
)
from email_osint_enricher.output_writer import write_results
from email_osint_enricher.providers.ghunt_provider import GHuntProvider
from email_osint_enricher.providers.holehe_provider import HoleheProvider
from email_osint_enricher.schemas import (
    AppConfig,
    EmailType,
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
        resume: bool = False,
        proxy: Optional[str] = None,
    ):
        self.config = config or load_config()
        self.output_dir = Path(output_dir)
        self.dry_run = dry_run
        self.force_ghunt = force_ghunt
        self.resume = resume
        self.proxy = proxy

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
            proxy=self.proxy,
        )

        self.semaphore = asyncio.Semaphore(self.config.batch.concurrency)
        self.delay = self.config.batch.delay_seconds
        self.max_retries = self.config.batch.max_retries
        self.mask = self.config.logging.mask_emails

        # Resume state
        self._completed_emails: set[str] = set()
        if self.resume:
            self._load_resume_state()

    def _load_resume_state(self):
        """Load already-processed emails from previous run's JSONL."""
        jsonl_path = self.output_dir / "enriched_results.jsonl"
        if jsonl_path.exists():
            count = 0
            with open(jsonl_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        email = data.get("email_normalized") or data.get("email", "")
                        status = data.get("status", "")
                        if status in ("success", "partial") and email:
                            self._completed_emails.add(email)
                            count += 1
                    except json.JSONDecodeError:
                        continue
            if count:
                logger.info(f"Resume mode: loaded {count} previously completed emails")

    async def process_single(self, row: InputRow) -> EnrichmentResult:
        """Process a single email through the pipeline."""
        email = row.email
        email_display = mask_email(email) if self.mask else email
        normalized = normalize_email(email)
        domain = get_domain(email)

        # DNS / MX precheck for domain classification
        domain_has_mx = has_mx_record(domain) if domain else False
        is_gws = is_google_workspace(domain) if domain else False

        # Classify with MX awareness
        email_type = classify_email(email)
        if is_gws and email_type == EmailType.corporate:
            email_type = EmailType.google_workspace

        result = EnrichmentResult(
            email=email,
            email_normalized=normalized,
            email_domain=domain,
            email_type=email_type.value,
            input_row_id=row.input_row_id,
            applicantId=row.applicantId,
            externalId=row.externalId,
            applicantName=row.applicantName,
            applicantCountry=row.applicantCountry,
            claim_value=row.claim_value,
            lead_score=row.lead_score,
            tier=row.tier,
        )

        # Check resume
        if self.resume and normalized in self._completed_emails:
            result.status = ProcessingStatus.skipped.value
            result.error_message = "already processed (resume mode)"
            logger.debug(f"Skipping already-processed: {email_display}")
            ghunt_res = GHuntResult()
            holehe_res = HoleheResult()
            result = score_result(result, ghunt_res, holehe_res, row)
            return result

        # Check MX — skip emails with no MX (undeliverable domain)
        if domain and not domain_has_mx:
            result.status = ProcessingStatus.skipped.value
            result.error_message = f"Domain {domain} has no MX records — likely undeliverable"
            logger.info(f"Skipping {email_display}: no MX records for {domain}")
            ghunt_res = GHuntResult()
            holehe_res = HoleheResult()
            result = score_result(result, ghunt_res, holehe_res, row)
            return result

        if self.dry_run:
            result.status = ProcessingStatus.skipped.value
            result.error_message = "dry-run mode"
            extra_info = []
            if domain_has_mx:
                extra_info.append("MX:✓")
            if is_gws:
                extra_info.append("GWS:✓")
            logger.info(f"[DRY-RUN] Would process: {email_display} ({email_type.value}) {' '.join(extra_info)}")
            ghunt_res = GHuntResult()
            holehe_res = HoleheResult()
            result = score_result(result, ghunt_res, holehe_res, row)
            return result

        ghunt_res = GHuntResult()
        holehe_res = HoleheResult()

        # GHunt
        if "ghunt" in self.active_providers:
            should_run = is_google_email(email, force=self.force_ghunt) or is_gws
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
            if provider == "ghunt":
                return GHuntResult(checked=True, success=False)
            else:
                return HoleheResult(checked=True, success=False)

    async def process_batch(self, rows: list[InputRow]) -> tuple[list[EnrichmentResult], RunSummary]:
        """Process a batch of emails with progress bar and rate limiting."""
        started_at = dt.datetime.now(dt.timezone.utc).isoformat()
        results: list[EnrichmentResult] = []

        # ── Deduplication ────────────────────────────────────────────────
        seen_normalized: set[str] = set()
        unique_rows: list[InputRow] = []
        duplicate_count = 0

        for row in rows:
            norm = normalize_email(row.email)
            if norm in seen_normalized:
                duplicate_count += 1
                # Still add a result but mark as skipped duplicate
                result = EnrichmentResult(
                    email=row.email,
                    email_normalized=norm,
                    email_domain=get_domain(row.email),
                    email_type=classify_email(row.email).value,
                    input_row_id=row.input_row_id,
                    status=ProcessingStatus.skipped.value,
                    error_message="duplicate email (normalized)",
                    applicantId=row.applicantId,
                    externalId=row.externalId,
                    applicantName=row.applicantName,
                    applicantCountry=row.applicantCountry,
                    claim_value=row.claim_value,
                    lead_score=row.lead_score,
                    tier=row.tier,
                )
                results.append(result)
                continue
            seen_normalized.add(norm)
            unique_rows.append(row)

        if duplicate_count:
            logger.info(f"Deduplicated: {duplicate_count} duplicate emails removed, {len(unique_rows)} unique to process")

        # ── Domain precheck (MX + Google Workspace detection) ────────────
        if not self.dry_run:
            logger.info("Pre-checking domains (MX records, Google Workspace detection)...")
            all_emails = [r.email for r in unique_rows]
            domain_info = precheck_domains(all_emails)
            mx_ok = sum(1 for d in domain_info.values() if d["has_mx"])
            gws_count = sum(1 for d in domain_info.values() if d["is_google_workspace"])
            logger.info(
                f"Domain precheck: {len(domain_info)} unique domains, "
                f"{mx_ok} with MX, {gws_count} Google Workspace"
            )

        # ── Process unique emails ────────────────────────────────────────
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[cyan]{task.completed}/{task.total}"),
        ) as progress:
            task = progress.add_task("Enriching emails", total=len(unique_rows))

            # Incremental JSONL writing for crash recovery
            jsonl_path = self.output_dir / "enriched_results_partial.jsonl"
            self.output_dir.mkdir(parents=True, exist_ok=True)

            with open(jsonl_path, "a", encoding="utf-8") as jsonl_f:
                for row in unique_rows:
                    try:
                        result = await self.process_single(row)
                    except Exception as e:
                        logger.error(f"Unhandled error for row {row.input_row_id}: {e}")
                        result = EnrichmentResult(
                            email=row.email,
                            email_normalized=normalize_email(row.email),
                            email_domain=get_domain(row.email),
                            email_type=classify_email(row.email).value,
                            input_row_id=row.input_row_id,
                            status=ProcessingStatus.failed.value,
                            error_message=str(e),
                        )

                    results.append(result)

                    # Write incrementally for crash recovery
                    try:
                        jsonl_f.write(result.model_dump_json() + "\n")
                        jsonl_f.flush()
                    except Exception:
                        pass

                    progress.update(task, advance=1)

                    # Rate limit delay between emails
                    if self.delay > 0 and not self.dry_run:
                        await asyncio.sleep(self.delay)

        finished_at = dt.datetime.now(dt.timezone.utc).isoformat()

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
        paths = write_results(
            results=results,
            errors=errors,
            summary=summary,
            output_dir=self.output_dir,
            config=self.config.output,
        )

        # Remove partial JSONL if final write succeeded
        partial = self.output_dir / "enriched_results_partial.jsonl"
        if partial.exists():
            partial.unlink(missing_ok=True)

        return paths
