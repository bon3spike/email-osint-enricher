"""Pydantic models for configuration, input rows, and enrichment results."""

from __future__ import annotations

import datetime as _dt
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────

class EmailType(str, Enum):
    gmail = "gmail"
    google_workspace = "google_workspace"
    corporate = "corporate"
    free_provider = "free_provider"
    unknown = "unknown"


class ProcessingStatus(str, Enum):
    success = "success"
    partial = "partial"
    failed = "failed"
    skipped = "skipped"


class EnrichmentTier(str, Enum):
    strong = "Strong"
    medium = "Medium"
    weak = "Weak"
    no_signal = "No Signal"


# ── Configuration ────────────────────────────────────────────────────────────

class ProviderConfig(BaseModel):
    enabled: bool = True
    timeout_seconds: int = 120
    force: bool = False


class BatchConfig(BaseModel):
    concurrency: int = 3
    delay_seconds: float = 1.5
    max_retries: int = 2


class OutputConfig(BaseModel):
    save_raw_json: bool = True
    write_xlsx: bool = True
    write_csv: bool = True
    write_jsonl: bool = True


class LoggingConfig(BaseModel):
    level: str = "INFO"
    mask_emails: bool = True


class AppConfig(BaseModel):
    providers: dict[str, ProviderConfig] = Field(default_factory=lambda: {
        "holehe": ProviderConfig(),
        "blackbird": ProviderConfig(enabled=True),
        "maigret": ProviderConfig(enabled=True),
        "sherlock": ProviderConfig(enabled=False),
        "phone_extractor": ProviderConfig(enabled=True),
        "emailrep": ProviderConfig(enabled=True, timeout_seconds=60),
        "mosint": ProviderConfig(enabled=False, timeout_seconds=180),
        "emailcrawlr": ProviderConfig(enabled=False, timeout_seconds=60),
        "hudsonrock": ProviderConfig(enabled=True, timeout_seconds=30),
        "gravatar": ProviderConfig(enabled=True, timeout_seconds=15),
        "socialscan": ProviderConfig(enabled=False, timeout_seconds=60),
    })
    batch: BatchConfig = Field(default_factory=BatchConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


# ── Input row ────────────────────────────────────────────────────────────────

class InputRow(BaseModel):
    """One row from the source CSV / XLSX."""
    email: str
    input_row_id: int = 0
    applicantId: Optional[str] = None
    externalId: Optional[str] = None
    applicantName: Optional[str] = None
    applicantCountry: Optional[str] = None
    claim_value: Optional[float] = None
    lead_score: Optional[float] = None
    tier: Optional[str] = None
    phone: Optional[str] = None
    extra: dict[str, Any] = Field(default_factory=dict)


# ── Provider results ─────────────────────────────────────────────────────────

class HoleheResult(BaseModel):
    checked: bool = False
    success: bool = False
    registered_services_count: int = 0
    registered_services_list: list[str] = Field(default_factory=list)
    social_services_count: int = 0
    professional_services_count: int = 0
    other_services_count: int = 0
    recovery_hints_count: int = 0
    raw_json_path: Optional[str] = None
    confidence_score: float = 0.0
    error: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class BlackbirdResult(BaseModel):
    checked: bool = False
    success: bool = False
    email_profiles_count: int = 0
    username_profiles_count: int = 0
    profiles_list: list[str] = Field(default_factory=list)
    report_path: Optional[str] = None
    raw_json_path: Optional[str] = None
    confidence_score: float = 0.0
    error: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class MaigretResult(BaseModel):
    checked: bool = False
    success: bool = False
    username_candidates: list[str] = Field(default_factory=list)
    profiles_count: int = 0
    profiles_list: list[str] = Field(default_factory=list)
    report_path: Optional[str] = None
    raw_json_path: Optional[str] = None
    confidence_score: float = 0.0
    error: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class SherlockResult(BaseModel):
    checked: bool = False
    success: bool = False
    profiles_count: int = 0
    profiles_list: list[str] = Field(default_factory=list)
    raw_json_path: Optional[str] = None
    confidence_score: float = 0.0
    error: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class PhoneCandidate(BaseModel):
    phone_number: str
    source_url: str = ""
    source_provider: str = ""
    extraction_method: str = ""
    confidence_score: int = 0
    context_snippet: Optional[str] = None


class PhoneExtractorResult(BaseModel):
    checked: bool = False
    success: bool = False
    phone_candidates_found: bool = False
    phone_candidates_count: int = 0
    phone_candidates_list: list[PhoneCandidate] = Field(default_factory=list)
    phone_candidate_best: Optional[str] = None
    phone_candidate_source_url: Optional[str] = None
    phone_candidate_source_provider: Optional[str] = None
    phone_candidate_context: Optional[str] = None
    phone_candidate_confidence_score: int = 0
    phone_extraction_error: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


# ── New provider results (v0.2) ─────────────────────────────────────────────

class EmailRepResult(BaseModel):
    checked: bool = False
    success: bool = False
    reputation: str = ""  # "high", "medium", "low", "none"
    suspicious: bool = False
    references: int = 0
    details_summary: str = ""
    risk_score: float = 0.0  # 0..1
    raw_json_path: Optional[str] = None
    error: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class MosintResult(BaseModel):
    checked: bool = False
    success: bool = False
    services_used: str = ""
    findings_count: int = 0
    social_signal: bool = False
    breach_signal: bool = False
    domain_signal: bool = False
    raw_json_path: Optional[str] = None
    confidence_score: float = 0.0
    error: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)






# ── New provider results (v0.4) ─────────────────────────────────────────────

class HudsonRockResult(BaseModel):
    checked: bool = False
    success: bool = False
    is_compromised: bool = False
    stealers_count: int = 0
    total_corporate_services: int = 0
    total_user_services: int = 0
    latest_compromise_date: str = ""
    compromised_dates: str = ""
    operating_systems: str = ""
    confidence_score: float = 0.0
    raw_json_path: Optional[str] = None
    error: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class GravatarResult(BaseModel):
    checked: bool = False
    success: bool = False
    has_profile: bool = False
    display_name: str = ""
    full_name: str = ""
    avatar_url: str = ""
    profile_url: str = ""
    about_me: str = ""
    location: str = ""
    linked_accounts: list[str] = Field(default_factory=list)
    linked_accounts_count: int = 0
    profile_urls: list[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    raw_json_path: Optional[str] = None
    error: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class SocialscanResult(BaseModel):
    checked: bool = False
    success: bool = False
    registered_platforms: list[str] = Field(default_factory=list)
    registered_count: int = 0
    not_registered_platforms: list[str] = Field(default_factory=list)
    not_registered_count: int = 0
    error_platforms: list[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    raw_json_path: Optional[str] = None
    error: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class EmailCrawlrResult(BaseModel):
    checked: bool = False
    success: bool = False
    social_accounts_count: int = 0
    social_accounts_list: list[str] = Field(default_factory=list)
    deliverability: str = ""
    domain_emails_count: int = 0
    raw_json_path: Optional[str] = None
    confidence_score: float = 0.0
    error: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


# ── Profile (for merge_profiles) ────────────────────────────────────────────

class ProfileEntry(BaseModel):
    """Unified profile found across providers."""
    url: str
    platform: str = ""
    source_provider: str = ""
    matched_by: str = ""  # email|username|name|domain
    confidence: int = 0


# ── Enrichment result ────────────────────────────────────────────────────────

class EnrichmentResult(BaseModel):
    """Full enrichment output for one email."""

    # Base
    email: str
    email_normalized: str = ""
    email_domain: str = ""
    email_type: EmailType = EmailType.unknown
    input_row_id: int = 0
    processed_at: str = Field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())
    status: ProcessingStatus = ProcessingStatus.skipped
    error_message: Optional[str] = None

    # Input passthrough
    applicantId: Optional[str] = None
    externalId: Optional[str] = None
    applicantName: Optional[str] = None
    applicantCountry: Optional[str] = None
    claim_value: Optional[float] = None
    lead_score: Optional[float] = None
    tier: Optional[str] = None

    # Username candidates
    username_candidates: str = ""

    # ── Holehe ───────────────────────────────────────────────────────────
    holehe_checked: bool = False
    holehe_success: bool = False
    holehe_registered_services_count: int = 0
    holehe_registered_services_list: str = ""
    holehe_social_services_count: int = 0
    holehe_professional_services_count: int = 0
    holehe_other_services_count: int = 0
    holehe_raw_json_path: Optional[str] = None
    holehe_confidence_score: float = 0.0
    holehe_error: Optional[str] = None

    # ── Blackbird ────────────────────────────────────────────────────────
    blackbird_checked: bool = False
    blackbird_success: bool = False
    blackbird_email_profiles_count: int = 0
    blackbird_username_profiles_count: int = 0
    blackbird_profiles_list: str = ""
    blackbird_report_path: Optional[str] = None
    blackbird_raw_json_path: Optional[str] = None
    blackbird_confidence_score: float = 0.0
    blackbird_error: Optional[str] = None

    # ── Maigret ──────────────────────────────────────────────────────────
    maigret_checked: bool = False
    maigret_success: bool = False
    maigret_username_candidates: str = ""
    maigret_profiles_count: int = 0
    maigret_profiles_list: str = ""
    maigret_report_path: Optional[str] = None
    maigret_raw_json_path: Optional[str] = None
    maigret_confidence_score: float = 0.0
    maigret_error: Optional[str] = None

    # ── Sherlock ─────────────────────────────────────────────────────────
    sherlock_checked: bool = False
    sherlock_success: bool = False
    sherlock_profiles_count: int = 0
    sherlock_profiles_list: str = ""
    sherlock_raw_json_path: Optional[str] = None
    sherlock_confidence_score: float = 0.0
    sherlock_error: Optional[str] = None

    # ── Phone Extractor ──────────────────────────────────────────────────
    phone_extractor_checked: bool = False
    phone_candidates_found: bool = False
    phone_candidates_count: int = 0
    phone_candidates_list: str = ""
    phone_candidate_best: Optional[str] = None
    phone_candidate_source_url: Optional[str] = None
    phone_candidate_source_provider: Optional[str] = None
    phone_candidate_context: Optional[str] = None
    phone_candidate_confidence_score: int = 0
    phone_extraction_error: Optional[str] = None

    # ── EmailRep ─────────────────────────────────────────────────────────
    emailrep_checked: bool = False
    emailrep_success: bool = False
    emailrep_reputation: str = ""
    emailrep_suspicious: bool = False
    emailrep_references: int = 0
    emailrep_details_summary: str = ""
    emailrep_risk_score: float = 0.0
    emailrep_raw_json_path: Optional[str] = None
    emailrep_error: Optional[str] = None

    # ── Mosint ───────────────────────────────────────────────────────────
    mosint_checked: bool = False
    mosint_success: bool = False
    mosint_services_used: str = ""
    mosint_findings_count: int = 0
    mosint_social_signal: bool = False
    mosint_breach_signal: bool = False
    mosint_domain_signal: bool = False
    mosint_raw_json_path: Optional[str] = None
    mosint_confidence_score: float = 0.0
    mosint_error: Optional[str] = None

    # ── EmailCrawlr ──────────────────────────────────────────────────────
    emailcrawlr_checked: bool = False
    emailcrawlr_success: bool = False
    emailcrawlr_social_accounts_count: int = 0
    emailcrawlr_social_accounts_list: str = ""
    emailcrawlr_deliverability: str = ""
    emailcrawlr_domain_emails_count: int = 0
    emailcrawlr_raw_json_path: Optional[str] = None
    emailcrawlr_confidence_score: float = 0.0
    emailcrawlr_error: Optional[str] = None

    # ── HudsonRock ────────────────────────────────────────────────────────
    hudsonrock_checked: bool = False
    hudsonrock_success: bool = False
    hudsonrock_is_compromised: bool = False
    hudsonrock_stealers_count: int = 0
    hudsonrock_total_corporate_services: int = 0
    hudsonrock_total_user_services: int = 0
    hudsonrock_latest_compromise_date: str = ""
    hudsonrock_compromised_dates: str = ""
    hudsonrock_operating_systems: str = ""
    hudsonrock_confidence_score: float = 0.0
    hudsonrock_raw_json_path: Optional[str] = None
    hudsonrock_error: Optional[str] = None

    # ── Gravatar ─────────────────────────────────────────────────────────
    gravatar_checked: bool = False
    gravatar_success: bool = False
    gravatar_has_profile: bool = False
    gravatar_display_name: str = ""
    gravatar_full_name: str = ""
    gravatar_avatar_url: str = ""
    gravatar_profile_url: str = ""
    gravatar_about_me: str = ""
    gravatar_location: str = ""
    gravatar_linked_accounts_count: int = 0
    gravatar_linked_accounts: str = ""
    gravatar_confidence_score: float = 0.0
    gravatar_raw_json_path: Optional[str] = None
    gravatar_error: Optional[str] = None

    # ── Socialscan ───────────────────────────────────────────────────────
    socialscan_checked: bool = False
    socialscan_success: bool = False
    socialscan_registered_count: int = 0
    socialscan_registered_platforms: str = ""
    socialscan_not_registered_count: int = 0
    socialscan_confidence_score: float = 0.0
    socialscan_raw_json_path: Optional[str] = None
    socialscan_error: Optional[str] = None

    # ── Scoring ──────────────────────────────────────────────────────────
    email_footprint_score: int = 0
    identity_confidence_score: int = 0
    social_presence_score: int = 0
    email_reputation_score: int = 0
    deliverability_score: int = 0
    provider_consensus_score: int = 0
    conflict_risk_score: int = 0
    final_enrichment_score: int = 0
    outreach_enrichment_tier: str = EnrichmentTier.no_signal.value
    manual_review_needed: bool = False
    enrichment_notes: str = ""
    recommended_next_action: str = ""

    # Meta
    source_provider: str = ""
    total_profiles_found: int = 0
    merged_profiles_count: int = 0


# ── Run summary ──────────────────────────────────────────────────────────────

class RunSummary(BaseModel):
    started_at: str = ""
    finished_at: str = ""
    total_emails: int = 0
    processed: int = 0
    success: int = 0
    partial: int = 0
    failed: int = 0
    skipped: int = 0
    # Per-provider stats
    holehe_calls: int = 0
    holehe_successes: int = 0
    blackbird_calls: int = 0
    blackbird_successes: int = 0
    maigret_calls: int = 0
    maigret_successes: int = 0
    sherlock_calls: int = 0
    sherlock_successes: int = 0
    phone_extractor_calls: int = 0
    phone_extractor_successes: int = 0
    emailrep_calls: int = 0
    emailrep_successes: int = 0
    mosint_calls: int = 0
    mosint_successes: int = 0
    emailcrawlr_calls: int = 0
    emailcrawlr_successes: int = 0
    hudsonrock_calls: int = 0
    hudsonrock_successes: int = 0
    gravatar_calls: int = 0
    gravatar_successes: int = 0
    socialscan_calls: int = 0
    socialscan_successes: int = 0
    # Aggregates
    avg_footprint_score: float = 0.0
    avg_identity_score: float = 0.0
    avg_final_score: float = 0.0
    total_profiles_discovered: int = 0
    total_phone_candidates: int = 0
    tier_distribution: dict[str, int] = Field(default_factory=dict)
    config_used: dict[str, Any] = Field(default_factory=dict)
