# Email OSINT Enricher

Local OSINT enrichment tool for email lists. Takes a CSV/XLSX with email addresses and produces enriched output with public OSINT signals — digital footprint, identity confidence, and outreach scoring.

Built on top of two open-source OSINT frameworks:
- **[GHunt](https://github.com/mxrch/GHunt)** — Google account OSINT (Gmail / Google Workspace enrichment)
- **[Holehe](https://github.com/megadose/holehe)** — Email-to-registered-accounts OSINT (120+ services)

## ⚠️ Legal & Compliance Warning

**This tool is for lawful OSINT research only.**

- Only queries publicly available data through GHunt and Holehe APIs
- Does NOT perform hacking, password resets, credential stuffing, or scraping private data
- Does NOT send notifications to target email addresses (Holehe uses password reset _check_ endpoints that don't trigger notifications)
- The user is fully responsible for compliance with applicable laws (GDPR, CCPA, CFAA, etc.)
- Rate limit responsibly — excessive querying may violate provider ToS
- Do not use this tool for harassment, stalking, unauthorized surveillance, or any illegal purpose

## What It Does

1. **Reads** a CSV or XLSX file with an `email` column
2. **Normalizes** emails (Gmail dot/plus normalization, domain classification)
3. **Enriches** via GHunt (Google profiles, photos, YouTube, Maps, Calendar, Drive signals)
4. **Enriches** via Holehe (registered accounts on 120+ services: social, professional, etc.)
5. **Scores** each email: `email_footprint_score`, `identity_confidence_score`, `outreach_enrichment_tier`
6. **Outputs** enriched CSV, XLSX, JSONL, run summary JSON, and errors CSV

## What GHunt Does

GHunt is a Google OSINT framework. For a given Gmail/Google Workspace email it can find:
- Display name and GAIA ID
- Profile photo
- YouTube channel
- Google Maps reviews
- Public Google Calendar
- Public Google Drive files
- Fully async, JSON export

**Requires authentication**: You must run `ghunt login` once to provide browser cookies. See [GHunt docs](https://github.com/mxrch/GHunt).

## What Holehe Does

Holehe checks if an email is registered on 120+ websites by using password reset / account recovery endpoints:
- Twitter, Instagram, Facebook, Reddit, Discord, Spotify, etc.
- GitHub, GitLab, StackOverflow, LinkedIn-like services
- Does NOT notify the target email
- Works on Python 3

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USER/email-osint-enricher.git
cd email-osint-enricher

# Install with all dependencies
pip install -e ".[all,dev]"

# Or install without OSINT providers (for testing/development)
pip install -e ".[dev]"

# Or install individual providers
pip install -e ".[ghunt]"
pip install -e ".[holehe]"
```

### GHunt Authentication

GHunt requires Google cookies for authentication:

```bash
# Run the GHunt login flow
ghunt login

# This will guide you through providing browser cookies
# Credentials are stored locally in ~/.ghunt/
```

### Configuration

```bash
# Copy example config
cp config.yaml.example config.yaml

# Edit as needed
nano config.yaml
```

## Usage

### Single Email

```bash
# Enrich a single email
python -m email_osint_enricher single --email test@gmail.com --out output/

# Dry run (no actual API calls)
python -m email_osint_enricher single --email test@gmail.com --dry-run

# Only Holehe
python -m email_osint_enricher single --email test@gmail.com --providers holehe
```

### Batch CSV

```bash
# Process a CSV file
python -m email_osint_enricher batch --input leads.csv --email-column email --out output/

# Custom email column name
python -m email_osint_enricher batch --input leads.csv --email-column applicantEmail --out output/

# Dry run — validate input, show what would be processed
python -m email_osint_enricher batch --input leads.csv --email-column email --dry-run
```

### Batch XLSX

```bash
# Process an Excel file
python -m email_osint_enricher batch --input leads.xlsx --email-column applicantEmail --out output/

# Specific sheet
python -m email_osint_enricher batch --input leads.xlsx --email-column email --sheet "Applicants Clean" --out output/
```

### Provider Selection

```bash
# Only Holehe (works for all emails)
python -m email_osint_enricher batch --input leads.csv --email-column email --providers holehe

# Only GHunt (automatically skips non-Gmail unless --force-ghunt)
python -m email_osint_enricher batch --input leads.csv --email-column email --providers ghunt

# Force GHunt for non-Gmail emails (e.g., Google Workspace domains)
python -m email_osint_enricher batch --input leads.csv --email-column email --providers ghunt --force-ghunt
```

## Input Format

CSV or XLSX with these columns:

| Column | Required | Description |
|--------|----------|-------------|
| `email` | ✅ | Email address |
| `applicantId` | ❌ | Internal ID |
| `externalId` | ❌ | External reference |
| `applicantName` | ❌ | Known name (used for identity matching) |
| `applicantCountry` | ❌ | Known country (used for identity matching) |
| `claim_value` | ❌ | Claim amount |
| `lead_score` | ❌ | Existing lead score |
| `tier` | ❌ | Existing tier classification |

## Output Schema

### enriched_results.csv / .xlsx / .jsonl

**Base fields:**
- `email` — Original email
- `email_normalized` — Normalized (Gmail dots/plus removed)
- `email_domain` — Domain part
- `email_type` — `gmail` / `google_workspace` / `corporate` / `free_provider` / `unknown`
- `input_row_id` — Row index from input file
- `processed_at` — ISO timestamp
- `status` — `success` / `partial` / `failed` / `skipped`
- `error_message` — Error details if any

**GHunt fields:**
- `ghunt_checked` — Whether GHunt was attempted
- `ghunt_success` — Whether GHunt returned data
- `ghunt_display_name` — Google account display name
- `ghunt_gaia_id` — Google GAIA ID
- `ghunt_profile_photo_found` / `ghunt_profile_photo_url`
- `ghunt_google_maps_reviews_found` / `ghunt_youtube_found` / `ghunt_calendar_public_found` / `ghunt_drive_public_found`
- `ghunt_raw_json_path` — Path to raw JSON output
- `ghunt_confidence_score` — Provider confidence (0–1)

**Holehe fields:**
- `holehe_checked` / `holehe_success`
- `holehe_registered_services_count` — Number of services where email is registered
- `holehe_registered_services_list` — Comma-separated service names
- `holehe_social_services_count` — Social media services
- `holehe_professional_services_count` — Professional/dev services
- `holehe_recovery_hints_count` — Recovery info hints
- `holehe_raw_json_path` — Path to raw JSON output
- `holehe_confidence_score` — Provider confidence (0–1)

**Scoring fields:**
- `email_footprint_score` — 0–100 digital footprint score
- `identity_confidence_score` — 0–100 identity confidence
- `outreach_enrichment_tier` — `Strong` / `Medium` / `Weak` / `No Signal`
- `manual_review_needed` — true/false
- `enrichment_notes` — Summary of findings
- `recommended_next_action` — Suggested next step

### run_summary.json

Aggregated statistics: totals, success/failure counts, provider stats, average scores, tier distribution.

### errors.csv

Rows that failed enrichment with error details.

## Scoring Formula

### email_footprint_score (0–100)

| Signal | Points |
|--------|--------|
| GHunt: Google profile / display name found | +25 |
| GHunt: profile photo found | +15 |
| GHunt: YouTube / Maps / Calendar / Drive artifacts | +10 |
| Holehe: 5+ registered services | +25 |
| Holehe: 2–4 registered services | +15 |
| Holehe: social media services found | +10 |
| Holehe: professional/dev services found | +10 |

Capped at 100.

### identity_confidence_score (0–100)

| Signal | Points |
|--------|--------|
| Display name found (GHunt) | +30 |
| Google account data found | +20 |
| 3+ registered services (Holehe) | +20 |
| Corporate email domain | +10 |
| Name matches applicantName | +10 |
| Country signal matches applicantCountry | +10 |
| Name/country conflict with applicant data | −20 |

Capped at 0–100.

### outreach_enrichment_tier

| Tier | Condition |
|------|-----------|
| **Strong** | identity_confidence ≥ 70 OR footprint ≥ 70 |
| **Medium** | best score 40–69 |
| **Weak** | best score 15–39 |
| **No Signal** | best score < 15 |

### recommended_next_action

| Tier | Action |
|------|--------|
| Strong | Use enriched identity for personalized outreach |
| Medium | Manual verification before outreach |
| Weak | Try additional enrichment provider |
| No Signal | Do not prioritize unless claim value is high |

## Configuration

See `config.yaml.example`:

```yaml
providers:
  ghunt:
    enabled: true
    timeout_seconds: 120
    force: false
  holehe:
    enabled: true
    timeout_seconds: 120

batch:
  concurrency: 3
  delay_seconds: 1.5
  max_retries: 2

output:
  save_raw_json: true
  write_xlsx: true
  write_csv: true
  write_jsonl: true

logging:
  level: INFO
  mask_emails: true
```

## Project Structure

```
email_osint_enricher/
├── README.md
├── pyproject.toml
├── config.yaml.example
├── .env.example
├── src/
│   └── email_osint_enricher/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py              # Typer CLI (single / batch commands)
│       ├── config.py           # YAML + env config loading
│       ├── schemas.py          # Pydantic models
│       ├── input_loader.py     # CSV / XLSX reader
│       ├── output_writer.py    # CSV / XLSX / JSONL writer
│       ├── email_utils.py      # Normalization, classification, masking
│       ├── scoring.py          # Footprint + identity scoring
│       ├── pipeline.py         # Main enrichment pipeline
│       ├── logging_utils.py    # Rich logging setup
│       └── providers/
│           ├── __init__.py
│           ├── ghunt_provider.py   # GHunt wrapper (library + CLI fallback)
│           └── holehe_provider.py  # Holehe wrapper (library + CLI fallback)
├── tests/
│   ├── test_email_utils.py
│   ├── test_scoring.py
│   └── test_input_loader.py
└── examples/
    └── sample_input.csv
```

## Provider Behavior

- **GHunt** runs only for `@gmail.com` / `@googlemail.com` emails (or detected Google Workspace). Use `--force-ghunt` to override.
- **Holehe** runs for all emails.
- If one provider fails, the row is marked `partial` — it does not stop the batch.
- Raw JSON outputs are saved in `output/raw/ghunt/` and `output/raw/holehe/`.

## Limitations

- GHunt requires valid Google cookies — they expire and need re-authentication
- Holehe results depend on service availability — some checks may be rate-limited
- This tool does NOT verify email deliverability (use a dedicated email verification service for that)
- Google Workspace detection is heuristic — some corporate domains may not be identified
- Country matching is limited to what providers return
- The tool does NOT perform automated outreach

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
