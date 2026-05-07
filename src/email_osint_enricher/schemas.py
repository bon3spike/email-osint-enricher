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
        "ghunt": ProviderConfig(),
        "holehe": ProviderConfig(),
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
    extra: dict[str, Any] = Field(default_factory=dict)


# ── Provider results ─────────────────────────────────────────────────────────

class GHuntResult(BaseModel):
    checked: bool = False
    success: bool = False
    display_name: Optional[str] = None
    gaia_id: Optional[str] = None
    profile_photo_found: bool = False
    profile_photo_url: Optional[str] = None
    google_maps_reviews_found: bool = False
    youtube_found: bool = False
    calendar_public_found: bool = False
    drive_public_found: bool = False
    raw_json_path: Optional[str] = None
    confidence_score: float = 0.0
    raw: dict[str, Any] = Field(default_factory=dict)


class HoleheResult(BaseModel):
    checked: bool = False
    success: bool = False
    registered_services_count: int = 0
    registered_services_list: list[str] = Field(default_factory=list)
    social_services_count: int = 0
    professional_services_count: int = 0
    recovery_hints_count: int = 0
    raw_json_path: Optional[str] = None
    confidence_score: float = 0.0
    raw: dict[str, Any] = Field(default_factory=dict)


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

    # GHunt
    ghunt_checked: bool = False
    ghunt_success: bool = False
    ghunt_display_name: Optional[str] = None
    ghunt_gaia_id: Optional[str] = None
    ghunt_profile_photo_found: bool = False
    ghunt_profile_photo_url: Optional[str] = None
    ghunt_google_maps_reviews_found: bool = False
    ghunt_youtube_found: bool = False
    ghunt_calendar_public_found: bool = False
    ghunt_drive_public_found: bool = False
    ghunt_raw_json_path: Optional[str] = None
    ghunt_confidence_score: float = 0.0

    # Holehe
    holehe_checked: bool = False
    holehe_success: bool = False
    holehe_registered_services_count: int = 0
    holehe_registered_services_list: str = ""  # comma-separated for CSV compat
    holehe_social_services_count: int = 0
    holehe_professional_services_count: int = 0
    holehe_recovery_hints_count: int = 0
    holehe_raw_json_path: Optional[str] = None
    holehe_confidence_score: float = 0.0

    # Scoring
    email_footprint_score: int = 0
    identity_confidence_score: int = 0
    outreach_enrichment_tier: str = EnrichmentTier.no_signal.value
    manual_review_needed: bool = False
    enrichment_notes: str = ""
    recommended_next_action: str = ""

    # Meta
    source_provider: str = ""


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
    ghunt_calls: int = 0
    ghunt_successes: int = 0
    holehe_calls: int = 0
    holehe_successes: int = 0
    avg_footprint_score: float = 0.0
    avg_identity_score: float = 0.0
    tier_distribution: dict[str, int] = Field(default_factory=dict)
    config_used: dict[str, Any] = Field(default_factory=dict)
