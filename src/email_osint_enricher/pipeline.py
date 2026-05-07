"""Core enrichment pipeline — orchestrates providers, scoring, and output.

Порядок выполнения провайдеров (8 штук):
  1. Holehe    — email → registered accounts
  2. Blackbird — email + username → profiles (600+ платформ)
  3. Maigret   — deep username OSINT (dossier)
  4. Sherlock  — fast username fallback (400+ платформ)
  5. EmailRep  — email reputation/risk (API)
  6. Mosint    — email OSINT (Go subprocess)
  7. EmailCrawlr — email intelligence (API)
  8. phone_extractor — публичные телефоны из найденных профилей (always last)
"""

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
from email_osint_enricher.providers import PROVIDER_REGISTRY
from email_osint_enricher.providers.base import ProviderContext
from email_osint_enricher.providers.holehe_provider import HoleheProvider
from email_osint_enricher.providers.blackbird_provider import BlackbirdProvider
from email_osint_enricher.providers.maigret_provider import MaigretProvider
from email_osint_enricher.providers.sherlock_provider import SherlockProvider
from email_osint_enricher.providers.phone_extractor import PhoneExtractorProvider
from email_osint_enricher.providers.emailrep_provider import EmailRepProvider
from email_osint_enricher.providers.mosint_provider import MosintProvider
from email_osint_enricher.providers.emailcrawlr_provider import EmailCrawlrProvider
from email_osint_enricher.schemas import (
    AppConfig,
    EmailType,
    EnrichmentResult,
    HoleheResult,
    BlackbirdResult,
    MaigretResult,
    SherlockResult,
    PhoneExtractorResult,
    EmailRepResult,
    MosintResult,
    EmailCrawlrResult,
    InputRow,
    ProcessingStatus,
    RunSummary,
)
from email_osint_enricher.scoring import classify_holehe_services, score_result
from email_osint_enricher.username_utils import generate_username_candidates

logger = logging.getLogger("enricher")


class EnrichmentPipeline:
    """Main pipeline: takes InputRows, runs providers, scores, writes output."""

    def __init__(
        self,
        config: Optional[AppConfig] = None,
        output_dir: str = "output",
        providers_filter: Optional[list[str]] = None,
        disabled_providers: Optional[list[str]] = None,
        dry_run: bool = False,
        resume: bool = False,
        proxy: Optional[str] = None,
    ):
        self.config = config or load_config()
        self.output_dir = Path(output_dir)
        self.dry_run = dry_run
        self.resume = resume
        self.proxy = proxy

        # Determine active providers
        self.active_providers: set[str] = set()
        all_provider_names = list(PROVIDER_REGISTRY.keys())
        disabled = set(p.lower().strip() for p in (disabled_providers or []))

        if providers_filter:
            for p in providers_filter:
                p = p.lower().strip()
                if p in all_provider_names and p not in disabled:
                    self.active_providers.add(p)
        else:
            for name in all_provider_names:
                if name in disabled:
                    continue
                cfg = self.config.providers.get(name)
                if cfg and cfg.enabled:
                    self.active_providers.add(name)

        # Init providers
        self._providers = self._init_providers()

        self.semaphore = asyncio.Semaphore(self.config.batch.concurrency)
        self.delay = self.config.batch.delay_seconds
        self.max_retries = self.config.batch.max_retries
        self.mask = self.config.logging.mask_emails

        # Resume state
        self._completed_emails: set[str] = set()
        if self.resume:
            self._load_resume_state()

    def _init_providers(self) -> dict:
        """Инициализировать все активные провайдеры."""
        providers = {}

        for name in self.active_providers:
            cfg = self.config.providers.get(name, AppConfig().providers.get(name))
            timeout = cfg.timeout_seconds if cfg else 120
            raw_dir = self.output_dir / "raw" / name if self.config.output.save_raw_json else None

            if name == "holehe":
                providers[name] = HoleheProvider(timeout=timeout, raw_output_dir=raw_dir, proxy=self.proxy)
            elif name == "blackbird":
                providers[name] = BlackbirdProvider(timeout=timeout, raw_output_dir=raw_dir)
            elif name == "maigret":
                providers[name] = MaigretProvider(timeout=timeout, raw_output_dir=raw_dir)
            elif name == "sherlock":
                providers[name] = SherlockProvider(timeout=timeout, raw_output_dir=raw_dir)
            elif name == "phone_extractor":
                providers[name] = PhoneExtractorProvider(
                    timeout=timeout, raw_output_dir=raw_dir, proxy=self.proxy,
                )
            elif name == "emailrep":
                providers[name] = EmailRepProvider(timeout=timeout, raw_output_dir=raw_dir)
            elif name == "mosint":
                providers[name] = MosintProvider(timeout=timeout, raw_output_dir=raw_dir)

            elif name == "emailcrawlr":
                providers[name] = EmailCrawlrProvider(timeout=timeout, raw_output_dir=raw_dir)

        return providers

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
        """Process a single email through the full pipeline."""
        email = row.email
        email_display = mask_email(email) if self.mask else email
        normalized = normalize_email(email)
        domain = get_domain(email)

        # DNS / MX precheck
        domain_has_mx = has_mx_record(domain) if domain else False
        is_gws = is_google_workspace(domain) if domain else False

        email_type = classify_email(email)
        if is_gws and email_type == EmailType.corporate:
            email_type = EmailType.google_workspace

        # ── Build EnrichmentResult ───────────────────────────────────────
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

        # Empty results for scoring
        holehe_res = HoleheResult()
        blackbird_res = BlackbirdResult()
        maigret_res = MaigretResult()
        sherlock_res = SherlockResult()
        phone_res = PhoneExtractorResult()
        emailrep_res = EmailRepResult()
        mosint_res = MosintResult()
        emailcrawlr_res = EmailCrawlrResult()

        # ── Resume check ────────────────────────────────────────────────
        if self.resume and normalized in self._completed_emails:
            result.status = ProcessingStatus.skipped.value
            result.error_message = "already processed (resume mode)"
            logger.debug(f"Skipping already-processed: {email_display}")
            result = score_result(result, holehe_res, row)
            return result

        # ── MX check ────────────────────────────────────────────────────
        if domain and not domain_has_mx:
            result.status = ProcessingStatus.skipped.value
            result.error_message = f"Domain {domain} has no MX records"
            logger.info(f"Skipping {email_display}: no MX records for {domain}")
            result = score_result(result, holehe_res, row)
            return result

        # ── Dry-run ─────────────────────────────────────────────────────
        if self.dry_run:
            result.status = ProcessingStatus.skipped.value
            result.error_message = "dry-run mode"
            result = score_result(result, holehe_res, row)
            return result

        # ── Generate username candidates ─────────────────────────────────
        usernames = generate_username_candidates(email, row.applicantName)
        result.username_candidates = ", ".join(usernames)

        # ── Build ProviderContext ────────────────────────────────────────
        context = ProviderContext(
            email=email,
            email_normalized=normalized,
            email_domain=domain,
            email_type=email_type.value,
            applicant_name=row.applicantName,
            applicant_country=row.applicantCountry,
            applicant_id=row.applicantId,
            username_candidates=usernames,
            is_google_email=is_google_email(email, force=False),
            is_google_workspace=is_gws,
            corporate_domain=domain if email_type == EmailType.corporate else None,
            proxy=self.proxy,
        )

        # ── Run providers in parallel ────────────────────────────────────
        # All main providers run concurrently; phone_extractor runs last
        # (it needs profiles_found from other providers).

        async def _run_holehe():
            nonlocal holehe_res
            if "holehe" not in self._providers:
                return
            prov = self._providers["holehe"]
            if not await prov.should_run(context):
                return
            logger.info(f"Running Holehe for {email_display}")
            holehe_res = await self._run_with_retry(prov.run, context, "holehe")
            if holehe_res.success and holehe_res.registered_services_list:
                social, prof = classify_holehe_services(holehe_res.registered_services_list)
                holehe_res.social_services_count = social
                holehe_res.professional_services_count = prof

        async def _run_blackbird():
            nonlocal blackbird_res
            if "blackbird" not in self._providers:
                return
            prov = self._providers["blackbird"]
            if not await prov.should_run(context):
                return
            logger.info(f"Running Blackbird for {email_display}")
            blackbird_res = await self._run_with_retry(prov.run, context, "blackbird")

        async def _run_maigret():
            nonlocal maigret_res
            if "maigret" not in self._providers:
                return
            prov = self._providers["maigret"]
            if not await prov.should_run(context):
                return
            logger.info(f"Running Maigret for {email_display}")
            maigret_res = await self._run_with_retry(prov.run, context, "maigret")

        async def _run_sherlock():
            nonlocal sherlock_res
            if "sherlock" not in self._providers:
                return
            prov = self._providers["sherlock"]
            if not await prov.should_run(context):
                return
            logger.info(f"Running Sherlock for {email_display}")
            sherlock_res = await self._run_with_retry(prov.run, context, "sherlock")

        async def _run_emailrep():
            nonlocal emailrep_res
            if "emailrep" not in self._providers:
                return
            prov = self._providers["emailrep"]
            if not await prov.should_run(context):
                return
            logger.info(f"Running EmailRep for {email_display}")
            emailrep_res = await self._run_with_retry(prov.run, context, "emailrep")

        async def _run_mosint():
            nonlocal mosint_res
            if "mosint" not in self._providers:
                return
            prov = self._providers["mosint"]
            if not await prov.should_run(context):
                return
            logger.info(f"Running Mosint for {email_display}")
            mosint_res = await self._run_with_retry(prov.run, context, "mosint")

        async def _run_emailcrawlr():
            nonlocal emailcrawlr_res
            if "emailcrawlr" not in self._providers:
                return
            prov = self._providers["emailcrawlr"]
            if not await prov.should_run(context):
                return
            logger.info(f"Running EmailCrawlr for {email_display}")
            emailcrawlr_res = await self._run_with_retry(prov.run, context, "emailcrawlr")

        # Run all main providers in parallel
        await asyncio.gather(
            _run_holehe(),
            _run_blackbird(),
            _run_maigret(),
            _run_sherlock(),
            _run_emailrep(),
            _run_mosint(),
            _run_emailcrawlr(),
        )

        # Collect profiles from completed providers for phone extractor
        for res in [blackbird_res, maigret_res, sherlock_res]:
            if res.profiles_list:
                context.profiles_found.extend(res.profiles_list)

        # Phone extractor runs last — needs profiles_found from all others
        if "phone_extractor" in self._providers:
            prov = self._providers["phone_extractor"]
            if await prov.should_run(context):
                logger.info(f"Running Phone Extractor for {email_display} ({len(context.profiles_found)} URLs)")
                phone_res = await self._run_with_retry(prov.run, context, "phone_extractor")

        # ── Map provider results to EnrichmentResult ─────────────────────

        # Holehe
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
        result.holehe_other_services_count = holehe_res.other_services_count
        result.holehe_raw_json_path = holehe_res.raw_json_path
        result.holehe_confidence_score = holehe_res.confidence_score
        result.holehe_error = holehe_res.error

        # Blackbird
        result.blackbird_checked = blackbird_res.checked
        result.blackbird_success = blackbird_res.success
        result.blackbird_email_profiles_count = blackbird_res.email_profiles_count
        result.blackbird_username_profiles_count = blackbird_res.username_profiles_count
        result.blackbird_profiles_list = ", ".join(blackbird_res.profiles_list[:20])
        result.blackbird_report_path = blackbird_res.report_path
        result.blackbird_raw_json_path = blackbird_res.raw_json_path
        result.blackbird_confidence_score = blackbird_res.confidence_score
        result.blackbird_error = blackbird_res.error

        # Maigret
        result.maigret_checked = maigret_res.checked
        result.maigret_success = maigret_res.success
        result.maigret_username_candidates = ", ".join(maigret_res.username_candidates)
        result.maigret_profiles_count = maigret_res.profiles_count
        result.maigret_profiles_list = ", ".join(maigret_res.profiles_list[:20])
        result.maigret_report_path = maigret_res.report_path
        result.maigret_raw_json_path = maigret_res.raw_json_path
        result.maigret_confidence_score = maigret_res.confidence_score
        result.maigret_error = maigret_res.error

        # Sherlock
        result.sherlock_checked = sherlock_res.checked
        result.sherlock_success = sherlock_res.success
        result.sherlock_profiles_count = sherlock_res.profiles_count
        result.sherlock_profiles_list = ", ".join(sherlock_res.profiles_list[:20])
        result.sherlock_raw_json_path = sherlock_res.raw_json_path
        result.sherlock_confidence_score = sherlock_res.confidence_score
        result.sherlock_error = sherlock_res.error

        # EmailRep
        result.emailrep_checked = emailrep_res.checked
        result.emailrep_success = emailrep_res.success
        result.emailrep_reputation = emailrep_res.reputation
        result.emailrep_suspicious = emailrep_res.suspicious
        result.emailrep_references = emailrep_res.references
        result.emailrep_details_summary = emailrep_res.details_summary
        result.emailrep_risk_score = emailrep_res.risk_score
        result.emailrep_raw_json_path = emailrep_res.raw_json_path
        result.emailrep_error = emailrep_res.error

        # Mosint
        result.mosint_checked = mosint_res.checked
        result.mosint_success = mosint_res.success
        result.mosint_services_used = mosint_res.services_used
        result.mosint_findings_count = mosint_res.findings_count
        result.mosint_social_signal = mosint_res.social_signal
        result.mosint_breach_signal = mosint_res.breach_signal
        result.mosint_domain_signal = mosint_res.domain_signal
        result.mosint_raw_json_path = mosint_res.raw_json_path
        result.mosint_confidence_score = mosint_res.confidence_score
        result.mosint_error = mosint_res.error

        # EmailCrawlr
        result.emailcrawlr_checked = emailcrawlr_res.checked
        result.emailcrawlr_success = emailcrawlr_res.success
        result.emailcrawlr_social_accounts_count = emailcrawlr_res.social_accounts_count
        result.emailcrawlr_social_accounts_list = ", ".join(emailcrawlr_res.social_accounts_list)
        result.emailcrawlr_deliverability = emailcrawlr_res.deliverability
        result.emailcrawlr_domain_emails_count = emailcrawlr_res.domain_emails_count
        result.emailcrawlr_raw_json_path = emailcrawlr_res.raw_json_path
        result.emailcrawlr_confidence_score = emailcrawlr_res.confidence_score
        result.emailcrawlr_error = emailcrawlr_res.error

        # Phone extractor
        result.phone_extractor_checked = phone_res.checked
        result.phone_candidates_found = phone_res.phone_candidates_found
        result.phone_candidates_count = phone_res.phone_candidates_count
        result.phone_candidates_list = ", ".join(
            c.phone_number for c in phone_res.phone_candidates_list[:10]
        )
        result.phone_candidate_best = phone_res.phone_candidate_best
        result.phone_candidate_source_url = phone_res.phone_candidate_source_url
        result.phone_candidate_source_provider = phone_res.phone_candidate_source_provider
        result.phone_candidate_context = phone_res.phone_candidate_context
        result.phone_candidate_confidence_score = phone_res.phone_candidate_confidence_score
        result.phone_extraction_error = phone_res.phone_extraction_error

        # ── Determine status ─────────────────────────────────────────────
        all_results = [
            holehe_res, blackbird_res, maigret_res,
            sherlock_res, phone_res,
            emailrep_res, mosint_res,
            emailcrawlr_res,
        ]
        checked = [r for r in all_results if r.checked]
        successes = [r for r in checked if r.success]

        if not checked:
            result.status = ProcessingStatus.skipped.value
        elif len(successes) == len(checked):
            result.status = ProcessingStatus.success.value
        elif successes:
            result.status = ProcessingStatus.partial.value
        else:
            result.status = ProcessingStatus.failed.value

        # ── Score ────────────────────────────────────────────────────────
        result = score_result(
            result, holehe_res, row,
            blackbird=blackbird_res if blackbird_res.checked else None,
            maigret=maigret_res if maigret_res.checked else None,
            sherlock=sherlock_res if sherlock_res.checked else None,
            phone=phone_res if phone_res.checked else None,
            emailrep=emailrep_res if emailrep_res.checked else None,
            mosint=mosint_res if mosint_res.checked else None,
            emailcrawlr=emailcrawlr_res if emailcrawlr_res.checked else None,
        )

        return result

    async def _run_with_retry(self, coro_fn, context, provider: str):
        """Run a provider coroutine with retries and exponential backoff."""
        from email_osint_enricher.schemas import (
            EmailRepResult, MosintResult,
            EmailCrawlrResult,
        )

        last_exc = None
        for attempt in range(1, self.max_retries + 1):
            try:
                async with self.semaphore:
                    return await coro_fn(context)
            except Exception as e:
                last_exc = e
                wait = 2 ** attempt
                logger.warning(
                    f"{provider} attempt {attempt}/{self.max_retries} failed: {e}. "
                    f"Retrying in {wait}s..."
                )
                await asyncio.sleep(wait)

        # Final attempt
        try:
            async with self.semaphore:
                return await coro_fn(context)
        except Exception as e:
            logger.error(f"{provider} all retries exhausted: {e}")
            empty_results = {
                "holehe": HoleheResult(checked=True, success=False, error=str(e)),
                "blackbird": BlackbirdResult(checked=True, success=False, error=str(e)),
                "maigret": MaigretResult(checked=True, success=False, error=str(e)),
                "sherlock": SherlockResult(checked=True, success=False, error=str(e)),
                "phone_extractor": PhoneExtractorResult(checked=True, success=False, phone_extraction_error=str(e)),
                "emailrep": EmailRepResult(checked=True, success=False, error=str(e)),
                "mosint": MosintResult(checked=True, success=False, error=str(e)),
                "emailcrawlr": EmailCrawlrResult(checked=True, success=False, error=str(e)),
            }
            return empty_results.get(provider, HoleheResult(checked=True, success=False))

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
            logger.info(f"Deduplicated: {duplicate_count} duplicates removed, {len(unique_rows)} unique")

        # ── Domain precheck ──────────────────────────────────────────────
        if not self.dry_run:
            logger.info("Pre-checking domains...")
            all_emails = [r.email for r in unique_rows]
            domain_info = precheck_domains(all_emails)
            mx_ok = sum(1 for d in domain_info.values() if d["has_mx"])
            gws_count = sum(1 for d in domain_info.values() if d["is_google_workspace"])
            logger.info(
                f"Domain precheck: {len(domain_info)} domains, "
                f"{mx_ok} with MX, {gws_count} Google Workspace"
            )

        # ── Process unique emails ────────────────────────────────────────
        active_names = ", ".join(sorted(self.active_providers)) or "none"
        logger.info(f"Active providers: {active_names}")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[cyan]{task.completed}/{task.total}"),
        ) as progress:
            task = progress.add_task("Enriching emails", total=len(unique_rows))

            jsonl_path = self.output_dir / "enriched_results_partial.jsonl"
            self.output_dir.mkdir(parents=True, exist_ok=True)

            # Use semaphore for concurrent email processing
            email_semaphore = asyncio.Semaphore(self.config.batch.concurrency)
            results_lock = asyncio.Lock()

            async def _process_one(row: InputRow):
                async with email_semaphore:
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

                    async with results_lock:
                        results.append(result)
                        try:
                            jsonl_f.write(result.model_dump_json() + "\n")
                            jsonl_f.flush()
                        except Exception:
                            pass
                        progress.update(task, advance=1)

                    if self.delay > 0 and not self.dry_run:
                        await asyncio.sleep(self.delay)

            with open(jsonl_path, "a", encoding="utf-8") as jsonl_f:
                # Process all emails concurrently (limited by semaphore)
                await asyncio.gather(*[_process_one(row) for row in unique_rows])

        finished_at = dt.datetime.now(dt.timezone.utc).isoformat()
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
        final_scores: list[int] = []

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

            # Per-provider stats
            if r.holehe_checked:
                summary.holehe_calls += 1
            if r.holehe_success:
                summary.holehe_successes += 1
            if r.blackbird_checked:
                summary.blackbird_calls += 1
            if r.blackbird_success:
                summary.blackbird_successes += 1
            if r.maigret_checked:
                summary.maigret_calls += 1
            if r.maigret_success:
                summary.maigret_successes += 1
            if r.sherlock_checked:
                summary.sherlock_calls += 1
            if r.sherlock_success:
                summary.sherlock_successes += 1
            if r.phone_extractor_checked:
                summary.phone_extractor_calls += 1
            if r.phone_candidates_found:
                summary.phone_extractor_successes += 1
            if r.emailrep_checked:
                summary.emailrep_calls += 1
            if r.emailrep_success:
                summary.emailrep_successes += 1
            if r.mosint_checked:
                summary.mosint_calls += 1
            if r.mosint_success:
                summary.mosint_successes += 1
            if r.emailcrawlr_checked:
                summary.emailcrawlr_calls += 1
            if r.emailcrawlr_success:
                summary.emailcrawlr_successes += 1

            summary.total_profiles_discovered += r.total_profiles_found
            summary.total_phone_candidates += r.phone_candidates_count

            tier_dist[r.outreach_enrichment_tier] = tier_dist.get(r.outreach_enrichment_tier, 0) + 1
            footprint_scores.append(r.email_footprint_score)
            identity_scores.append(r.identity_confidence_score)
            final_scores.append(r.final_enrichment_score)

        summary.tier_distribution = tier_dist
        if footprint_scores:
            summary.avg_footprint_score = round(sum(footprint_scores) / len(footprint_scores), 2)
        if identity_scores:
            summary.avg_identity_score = round(sum(identity_scores) / len(identity_scores), 2)
        if final_scores:
            summary.avg_final_score = round(sum(final_scores) / len(final_scores), 2)

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

        partial = self.output_dir / "enriched_results_partial.jsonl"
        if partial.exists():
            partial.unlink(missing_ok=True)

        return paths
