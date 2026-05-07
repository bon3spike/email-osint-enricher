"""Load input CSV / XLSX files into a list of InputRow."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import pandas as pd

from email_osint_enricher.email_utils import is_valid_email
from email_osint_enricher.schemas import InputRow

logger = logging.getLogger("enricher")

# Known optional columns that map to InputRow fields
_KNOWN_COLS = {
    "applicantid", "externalid", "applicantname",
    "applicantcountry", "claim_value", "lead_score", "tier",
}


def load_input(
    file_path: str,
    email_column: str = "email",
    sheet: Optional[str] = None,
) -> list[InputRow]:
    """Read CSV or XLSX and return validated InputRow list."""
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")

    ext = p.suffix.lower()
    if ext == ".csv":
        df = pd.read_csv(p, dtype=str, keep_default_na=False)
    elif ext in (".xlsx", ".xls"):
        kwargs = {"dtype": str, "keep_default_na": False}
        if sheet:
            kwargs["sheet_name"] = sheet
        df = pd.read_excel(p, **kwargs)
    else:
        raise ValueError(f"Unsupported file format: {ext}. Use .csv or .xlsx")

    # Normalize column names for matching
    col_map = {c: c for c in df.columns}
    col_lower = {c.lower().strip(): c for c in df.columns}

    # Find email column
    email_col_actual = None
    for candidate in [email_column, email_column.lower(), "email"]:
        if candidate in col_lower:
            email_col_actual = col_lower[candidate]
            break
    if email_col_actual is None:
        raise ValueError(
            f"Email column '{email_column}' not found. "
            f"Available columns: {list(df.columns)}"
        )

    rows: list[InputRow] = []
    skipped = 0

    for idx, raw_row in df.iterrows():
        email_val = str(raw_row[email_col_actual]).strip()
        if not email_val or not is_valid_email(email_val):
            skipped += 1
            logger.warning(f"Row {idx}: invalid or empty email, skipping")
            continue

        # Build kwargs for InputRow
        kwargs: dict = {"email": email_val, "input_row_id": int(idx)}

        # Map known optional columns
        for col_name_lower, col_name_orig in col_lower.items():
            if col_name_lower in _KNOWN_COLS and col_name_orig != email_col_actual:
                field_name = col_name_lower
                # Normalize to match pydantic field names
                if field_name == "applicantid":
                    field_name = "applicantId"
                elif field_name == "externalid":
                    field_name = "externalId"
                elif field_name == "applicantname":
                    field_name = "applicantName"
                elif field_name == "applicantcountry":
                    field_name = "applicantCountry"

                val = str(raw_row[col_name_orig]).strip()
                if val:
                    if field_name in ("claim_value", "lead_score"):
                        try:
                            kwargs[field_name] = float(val)
                        except ValueError:
                            pass
                    else:
                        kwargs[field_name] = val

        rows.append(InputRow(**kwargs))

    logger.info(f"Loaded {len(rows)} valid emails from {p.name} (skipped {skipped})")
    return rows
