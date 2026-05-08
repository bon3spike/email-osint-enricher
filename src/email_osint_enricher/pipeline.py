"""Core enrichment pipeline — orchestrates providers, scoring, and output.

v0.5.0 — Refactored: generic provider runner, shared HTTP session,
parallel DNS precheck, DRY result mapping.

Provider execution order (11, all parallel except phone_extractor):
  1-10. All main providers via asyncio.gather()
  11. phone_extractor — runs last (needs profile URLs from others)
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
from pathlib import Path
from typing import Any, Optional

import httpx
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
    precheck_domains_async,
)
from email_osint_enricher.output_writer import write_results
from email_osint_enricher.providers import PROVIDER_REGISTRY
from email_osint_enricher.providers.base import BaseProvider, ProviderContext
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
    HudsonRockResult,
    GravatarResult,
    SocialscanResult,
    InputRow,
    ProcessingStatus,
    RunSummary,
)
from email_osint_enricher.scoring import classify_holehe_services, score_result
from email_osint_enricher.username_utils import generate_username_candidates

logger = logging.getLogger("enricher")

# ── Result type registry (provider_name → default empty result class) ────────
_EMPTY_RESULT_MAP: dict[str, type] = {
    "holehe": HoleheResult,
    "blackbird": BlackbirdResult,
    "maigret": MaigretResult,
    "sherlock": SherlockResult,
    "phone_extractor": PhoneExtractorResult,
    "emailrep": EmailRepResult,
    "mosint": MosintResult,
    "emailcrawlr": EmailCrawlrResult,
    "hudsonrock": HudsonRockResult,
    "gravatar": GravatarResult,
    "socialscan": SocialscanResult,
}

# Providers that produce profile URLs for phone extraction
_PROFILE_PROVIDERS = {"blackbird", "maigret", "sherlock"}

# Providers that should NOT run in the main parallel batch (run after)
_DEFERRED_PROVIDERS = {"phone_extractor"}


def _map_provider_result(result: EnrichmentResult, name: str, res: Any) -> None:
    """Map a provider result object onto the flat EnrichmentResult fields.

    Uses normalize_result() dict from the result to set `result.{prefix}_{field}`.
    For list fields, joins with ', '.
    """
    data = res.model_dump()
    prefix = name

    for field_name, value in data.items():
        target = f"{prefix}_{field_name}"
        if hasattr(result, target):
            # Convert lists to comma-separated strings for flat output
            if isinstance(value, list):
                if value and hasattr(value[0], "phone_number"):
                    # PhoneCandidate objects
                    value = ", ".join(c.phone_number if hasattr(c, "phone_number") else str(c) for c in value[:10])
                else:
                    value = ", ".join(str(v) for v in value[:20])
            setattr(result, target, value)


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
        self._providers: dict[str, BaseProvider] = self._init_providers()

        self.semaphore = asyncio.Semaphore(self.config.batch.concurrency)
        self.delay = self.config.batch.delay_seconds
        self.max_retries = self.config.batch.max_retries
        self.mask = self.config.logging.mask_emails

        # Shared HTTP client (created lazily, closed after batch)
        self._http_client: Optional[httpx.AsyncClient] = None

        # Resume state
        self._completed_emails: set[str] = set()
        if self.resume:
            self._load_resume_state()

    def _init_providers(self) -> dict[str, BaseProvider]:
        """Initialize all active providers."""
        providers: dict[str, BaseProvider] = {}
        default_cfg = AppConfig()

        for name in self.active_providers:
            cls = PROVIDER_REGISTRY.get(name)
            if not cls:
                logger.warning(f"Unknown provider: {name}")
                continue

            cfg = self.config.providers.get(name, default_cfg.providers.get(name))
            timeout = cfg.timeout_seconds if cfg else 120
            raw_dir = self.output_dir / "raw" / name if self.config.output.save_raw_json else None

            # All providers accept timeout + raw_output_dir via BaseProvider.__init__
            # Some accept extra kwargs (proxy, etc.)
            kwargs: dict[str, Any] = {"timeout": timeout, "raw_output_dir": raw_dir}
            if name in ("holehe", "phone_extractor"):
                kwargs["proxy"] = self.proxy

            try:
                providers[name] = cls(**kwargs)
            except Exception as e:
                logger.error(f"Failed to init provider {name}: {e}")

        return providers

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create shared HTTP client with connection pooling."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=30,
                limits=httpx.Limits(
                    max_connections=20,
                    max_keepalive_connections=10,
                ),
                headers={
                    "User-Agent": "email-osint-enricher/0.5",
                    "Accept": "application/json",
                },
            )
        return self._http_client

    async def _close_http_client(self) -> None:
        """Close the shared HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

    def _load_resume_state(self) -> None:
        """Load already-processed emails from previous run's JSONL."""
        jsonl_path = self.output_dir / "enriched_results.jsonl"
        if not jsonl_path.exists():
            return

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

    # ── Single email processing ──────────────────────────────────────────

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

        # Provider results registry (filled during execution)
        provider_results: dict[str, Any] = {
            name: cls() for name, cls in _EMPTY_RESULT_MAP.items()
        }

        # ── Early exits ─────────────────────────────────────────────────
        holehe_res_empty = HoleheResult()

        if self.resume and normalized in self._completed_emails:
            result.status = ProcessingStatus.skipped
            result.error_message = "already processed (resume mode)"
            logger.debug(f"Skipping already-processed: {email_display}")
            return score_result(result, holehe_res_empty, row)

        if domain and not domain_has_mx:
            result.status = ProcessingStatus.skipped
            result.error_message = f"Domain {domain} has no MX records"
            logger.info(f"Skipping {email_display}: no MX records for {domain}")
            return score_result(result, holehe_res_empty, row)

        if self.dry_run:
            result.status = ProcessingStatus.skipped
            result.error_message = "dry-run mode"
            return score_result(result, holehe_res_empty, row)

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

        # ── Run main providers in parallel ───────────────────────────────
        async def _run_provider(name: str) -> None:
            if name not in self._providers:
                return
            prov = self._providers[name]
            if not await prov.should_run(context):
                return
            logger.info(f"Running {name.title()} for {email_display}")
            res = await self._run_with_retry(prov.run, context, name)

            # Post-processing hooks
            if name == "holehe" and res.success and res.registered_services_list:
                social, prof = classify_holehe_services(res.registered_services_list)
                res.social_services_count = social
                res.professional_services_count = prof

            provider_results[name] = res

        # Run all except phone_extractor in parallel
        main_providers = [n for n in self._providers if n not in _DEFERRED_PROVIDERS]
        await asyncio.gather(*[_run_provider(n) for n in main_providers])

        # Collect profile URLs for phone extractor
        for pname in _PROFILE_PROVIDERS:
            res = provider_results.get(pname)
            if res and hasattr(res, "profiles_list") and res.profiles_list:
                context.profiles_found.extend(res.profiles_list)

        # Run phone_extractor last (needs profiles from others)
        if "phone_extractor" in self._providers:
            prov = self._providers["phone_extractor"]
            if await prov.should_run(context):
                logger.info(f"Running Phone Extractor for {email_display} ({len(context.profiles_found)} URLs)")
                provider_results["phone_extractor"] = await self._run_with_retry(
                    prov.run, context, "phone_extractor"
                )

        # ── Map all provider results → EnrichmentResult ──────────────────
        for name, res in provider_results.items():
            if not res.checked or name == "phone_extractor":
                continue
            _map_provider_result(result, name, res)

        # Fix phone_extractor field naming (uses different prefix pattern)
        pe = provider_results["phone_extractor"]
        if pe.checked:
            result.phone_extractor_checked = pe.checked
            result.phone_candidates_found = pe.phone_candidates_found
            result.phone_candidates_count = pe.phone_candidates_count
            result.phone_candidates_list = ", ".join(
                c.phone_number for c in pe.phone_candidates_list[:10]
            ) if hasattr(pe, "phone_candidates_list") else ""
            result.phone_candidate_best = pe.phone_candidate_best
            result.phone_candidate_source_url = pe.phone_candidate_source_url
            result.phone_candidate_source_provider = pe.phone_candidate_source_provider
            result.phone_candidate_context = pe.phone_candidate_context
            result.phone_candidate_confidence_score = pe.phone_candidate_confidence_score
            result.phone_extraction_error = pe.phone_extraction_error

        # ── Determine status ─────────────────────────────────────────────
        checked = [r for r in provider_results.values() if r.checked]
        successes = [r for r in checked if r.success]

        if not checked:
            result.status = ProcessingStatus.skipped
        elif len(successes) == len(checked):
            result.status = ProcessingStatus.success
        elif successes:
            result.status = ProcessingStatus.partial
        else:
            result.status = ProcessingStatus.failed

        # ── Score ────────────────────────────────────────────────────────
        holehe_res = provider_results["holehe"]
        # Map provider_results keys to score_result parameter names
        # (phone_extractor → phone; all others match)
        _SCORE_PARAM_MAP = {"phone_extractor": "phone"}
        score_kwargs = {
            _SCORE_PARAM_MAP.get(name, name): (res if res.checked else None)
            for name, res in provider_results.items()
            if name != "holehe"
        }
        result = score_result(result, holehe_res, row, **score_kwargs)

        return result

    async def _run_with_retry(self, coro_fn, context, provider: str):
        """Run a provider coroutine with retries and exponential backoff.

        Note: concurrency is controlled at the email level (email_semaphore
        in process_batch), not per-provider, to avoid double-semaphore
        contention that stalls the pipeline.
        """
        last_exc = None
        for attempt in range(1, self.max_retries + 1):
            try:
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
            return await coro_fn(context)
        except Exception as e:
            logger.error(f"{provider} all retries exhausted: {e}")
            result_cls = _EMPTY_RESULT_MAP.get(provider, HoleheResult)
            err_result = result_cls(checked=True, success=False)
            if hasattr(err_result, "error"):
                err_result.error = str(e)
            elif hasattr(err_result, "phone_extraction_error"):
                err_result.phone_extraction_error = str(e)
            return err_result

    # ── Batch processing ─────────────────────────────────────────────────

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
                    status=ProcessingStatus.skipped,
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

        # ── Domain precheck (parallel) ───────────────────────────────────
        if not self.dry_run:
            logger.info("Pre-checking domains (parallel)...")
            all_emails = [r.email for r in unique_rows]
            domain_info = await precheck_domains_async(all_emails)
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

            email_semaphore = asyncio.Semaphore(self.config.batch.concurrency)
            results_lock = asyncio.Lock()

            async def _process_one(row: InputRow) -> None:
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
                            status=ProcessingStatus.failed,
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

            try:
                with open(jsonl_path, "a", encoding="utf-8") as jsonl_f:
                    await asyncio.gather(*[_process_one(row) for row in unique_rows])
            finally:
                await self._close_http_client()

        finished_at = dt.datetime.now(dt.timezone.utc).isoformat()
        summary = self._build_summary(results, started_at, finished_at)

        return results, summary

    # ── Summary builder ──────────────────────────────────────────────────

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

        # Provider stats: collect dynamically to avoid listing each one
        provider_calls: dict[str, int] = {}
        provider_successes: dict[str, int] = {}

        for r in results:
            summary.processed += 1
            status_val = r.status if isinstance(r.status, str) else r.status.value
            if status_val == "success":
                summary.success += 1
            elif status_val == "partial":
                summary.partial += 1
            elif status_val == "failed":
                summary.failed += 1
            elif status_val == "skipped":
                summary.skipped += 1

            # Per-provider stats (generic)
            for pname in _EMPTY_RESULT_MAP:
                checked_attr = f"{pname}_checked"
                success_attr = f"{pname}_success"
                # phone_extractor uses different field names
                if pname == "phone_extractor":
                    checked_attr = "phone_extractor_checked"
                    success_attr = "phone_candidates_found"

                if getattr(r, checked_attr, False):
                    provider_calls[pname] = provider_calls.get(pname, 0) + 1
                if getattr(r, success_attr, False):
                    provider_successes[pname] = provider_successes.get(pname, 0) + 1

            summary.total_profiles_discovered += r.total_profiles_found
            summary.total_phone_candidates += r.phone_candidates_count

            tier_dist[r.outreach_enrichment_tier] = tier_dist.get(r.outreach_enrichment_tier, 0) + 1
            footprint_scores.append(r.email_footprint_score)
            identity_scores.append(r.identity_confidence_score)
            final_scores.append(r.final_enrichment_score)

        # Map to summary fields
        for pname in _EMPTY_RESULT_MAP:
            calls_attr = f"{pname}_calls"
            succ_attr = f"{pname}_successes"
            if hasattr(summary, calls_attr):
                setattr(summary, calls_attr, provider_calls.get(pname, 0))
            if hasattr(summary, succ_attr):
                setattr(summary, succ_attr, provider_successes.get(pname, 0))

        summary.tier_distribution = tier_dist
        if footprint_scores:
            summary.avg_footprint_score = round(sum(footprint_scores) / len(footprint_scores), 2)
        if identity_scores:
            summary.avg_identity_score = round(sum(identity_scores) / len(identity_scores), 2)
        if final_scores:
            summary.avg_final_score = round(sum(final_scores) / len(final_scores), 2)

        return summary

    # ── Output writer ────────────────────────────────────────────────────

    def write_output(
        self,
        results: list[EnrichmentResult],
        summary: RunSummary,
    ) -> dict[str, str]:
        """Write results to disk."""
        errors = [r for r in results if r.status in (ProcessingStatus.failed,)]
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
