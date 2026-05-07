"""Write enrichment results to CSV, XLSX, JSONL, and summary JSON."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pandas as pd

from email_osint_enricher.schemas import EnrichmentResult, RunSummary, OutputConfig

logger = logging.getLogger("enricher")

# Fields to include in output (ordered)
OUTPUT_FIELDS = [
    # Base
    "email", "email_normalized", "email_domain", "email_type",
    "input_row_id", "processed_at", "status", "error_message",
    # Input passthrough
    "applicantId", "externalId", "applicantName", "applicantCountry",
    "claim_value", "lead_score", "tier",
    # GHunt
    "ghunt_checked", "ghunt_success", "ghunt_display_name", "ghunt_gaia_id",
    "ghunt_profile_photo_found", "ghunt_profile_photo_url",
    "ghunt_google_maps_reviews_found", "ghunt_youtube_found",
    "ghunt_calendar_public_found", "ghunt_drive_public_found",
    "ghunt_raw_json_path", "ghunt_confidence_score",
    # Holehe
    "holehe_checked", "holehe_success",
    "holehe_registered_services_count", "holehe_registered_services_list",
    "holehe_social_services_count", "holehe_professional_services_count",
    "holehe_recovery_hints_count", "holehe_raw_json_path",
    "holehe_confidence_score",
    # Scoring
    "email_footprint_score", "identity_confidence_score",
    "outreach_enrichment_tier", "manual_review_needed",
    "enrichment_notes", "recommended_next_action",
    # Meta
    "source_provider",
]


def write_results(
    results: list[EnrichmentResult],
    errors: list[EnrichmentResult],
    summary: RunSummary,
    output_dir: str | Path,
    config: OutputConfig,
) -> dict[str, str]:
    """Write all output files and return paths."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    paths: dict[str, str] = {}

    # Convert results to dicts
    records = [_result_to_dict(r) for r in results]

    if records:
        df = pd.DataFrame(records)
        # Reorder columns
        cols = [c for c in OUTPUT_FIELDS if c in df.columns]
        extra_cols = [c for c in df.columns if c not in OUTPUT_FIELDS]
        df = df[cols + extra_cols]

        if config.write_csv:
            csv_path = output_dir / "enriched_results.csv"
            df.to_csv(csv_path, index=False, encoding="utf-8-sig")
            paths["csv"] = str(csv_path)
            logger.info(f"Written: {csv_path}")

        if config.write_xlsx:
            xlsx_path = output_dir / "enriched_results.xlsx"
            df.to_excel(xlsx_path, index=False, engine="openpyxl")
            paths["xlsx"] = str(xlsx_path)
            logger.info(f"Written: {xlsx_path}")

        if config.write_jsonl:
            jsonl_path = output_dir / "enriched_results.jsonl"
            with open(jsonl_path, "w", encoding="utf-8") as f:
                for r in results:
                    f.write(r.model_dump_json() + "\n")
            paths["jsonl"] = str(jsonl_path)
            logger.info(f"Written: {jsonl_path}")
    else:
        logger.warning("No results to write")

    # Errors CSV
    if errors:
        err_records = [_result_to_dict(r) for r in errors]
        err_df = pd.DataFrame(err_records)
        err_path = output_dir / "errors.csv"
        err_df.to_csv(err_path, index=False, encoding="utf-8-sig")
        paths["errors"] = str(err_path)
        logger.info(f"Written: {err_path}")

    # Run summary
    summary_path = output_dir / "run_summary.json"
    summary_path.write_text(
        summary.model_dump_json(indent=2),
        encoding="utf-8",
    )
    paths["summary"] = str(summary_path)
    logger.info(f"Written: {summary_path}")

    return paths


def _result_to_dict(r: EnrichmentResult) -> dict:
    """Convert EnrichmentResult to a flat dict for DataFrame."""
    d = r.model_dump()
    # Remove nested raw fields not needed in output
    return d
