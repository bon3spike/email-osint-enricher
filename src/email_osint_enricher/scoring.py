"""Scoring logic for email enrichment results."""

from __future__ import annotations

from email_osint_enricher.schemas import (
    EnrichmentResult,
    EnrichmentTier,
    EmailType,
    GHuntResult,
    HoleheResult,
    InputRow,
)

# Social services (holehe module names that indicate social media)
SOCIAL_SERVICES = {
    "twitter", "instagram", "facebook", "tiktok", "snapchat", "pinterest",
    "tumblr", "reddit", "discord", "telegram", "vk", "flickr", "imgur",
    "spotify", "deezer", "lastfm", "myspace", "quora", "medium",
}

# Professional / dev services
PROFESSIONAL_SERVICES = {
    "github", "gitlab", "bitbucket", "stackoverflow", "linkedin",
    "behance", "dribbble", "figma", "notion", "trello", "slack",
    "docker", "npmjs", "pypi", "hackernews", "producthunt",
    "aboutme", "angel", "crunchbase",
}


def classify_holehe_services(
    services: list[str],
) -> tuple[int, int]:
    """Return (social_count, professional_count) from holehe service list."""
    social = 0
    professional = 0
    for svc in services:
        svc_lower = svc.lower().strip()
        if svc_lower in SOCIAL_SERVICES:
            social += 1
        if svc_lower in PROFESSIONAL_SERVICES:
            professional += 1
    return social, professional


def compute_footprint_score(
    ghunt: GHuntResult,
    holehe: HoleheResult,
) -> int:
    """Compute email_footprint_score (0–100)."""
    score = 0

    # GHunt signals
    if ghunt.success and ghunt.display_name:
        score += 25
    if ghunt.profile_photo_found:
        score += 15
    # Public artifacts: YouTube, Maps, Calendar, Drive
    artifacts = [
        ghunt.youtube_found,
        ghunt.google_maps_reviews_found,
        ghunt.calendar_public_found,
        ghunt.drive_public_found,
    ]
    if any(artifacts):
        score += 10

    # Holehe signals
    if holehe.registered_services_count >= 5:
        score += 25
    elif holehe.registered_services_count >= 2:
        score += 15

    if holehe.social_services_count > 0:
        score += 10
    if holehe.professional_services_count > 0:
        score += 10

    return min(score, 100)


def compute_identity_confidence(
    ghunt: GHuntResult,
    holehe: HoleheResult,
    row: InputRow,
    email_type: EmailType,
) -> int:
    """Compute identity_confidence_score (0–100)."""
    score = 0

    # Display name found
    if ghunt.display_name:
        score += 30

    # Google account data found (gaia_id present)
    if ghunt.success and ghunt.gaia_id:
        score += 20

    # 3+ registered services
    if holehe.registered_services_count >= 3:
        score += 20

    # Corporate email domain
    if email_type == EmailType.corporate:
        score += 10

    # Name matching
    if row.applicantName and ghunt.display_name:
        if _names_match(ghunt.display_name, row.applicantName):
            score += 10
        else:
            score -= 20

    # Country matching — would need additional data from providers
    # For now, skip country signal unless we have it

    return max(0, min(score, 100))


def _names_match(found_name: str, expected_name: str) -> bool:
    """Fuzzy name comparison: check if significant overlap exists."""
    found_parts = set(found_name.lower().split())
    expected_parts = set(expected_name.lower().split())
    if not found_parts or not expected_parts:
        return False
    # At least one significant word in common
    overlap = found_parts & expected_parts
    return len(overlap) >= 1


def determine_tier(
    footprint_score: int,
    identity_score: int,
) -> EnrichmentTier:
    """Determine outreach enrichment tier."""
    best = max(footprint_score, identity_score)
    if best >= 70:
        return EnrichmentTier.strong
    if best >= 40:
        return EnrichmentTier.medium
    if best >= 15:
        return EnrichmentTier.weak
    return EnrichmentTier.no_signal


def get_recommended_action(tier: EnrichmentTier) -> str:
    """Return recommended next action based on tier."""
    actions = {
        EnrichmentTier.strong: "Use enriched identity for personalized outreach",
        EnrichmentTier.medium: "Manual verification before outreach",
        EnrichmentTier.weak: "Try additional enrichment provider",
        EnrichmentTier.no_signal: "Do not prioritize unless claim value is high",
    }
    return actions[tier]


def score_result(
    result: EnrichmentResult,
    ghunt: GHuntResult,
    holehe: HoleheResult,
    row: InputRow,
) -> EnrichmentResult:
    """Apply all scoring to an EnrichmentResult in-place and return it."""
    result.email_footprint_score = compute_footprint_score(ghunt, holehe)
    result.identity_confidence_score = compute_identity_confidence(
        ghunt, holehe, row, EmailType(result.email_type)
    )

    tier = determine_tier(
        result.email_footprint_score,
        result.identity_confidence_score,
    )
    result.outreach_enrichment_tier = tier.value
    result.recommended_next_action = get_recommended_action(tier)

    # Manual review needed if partial data or medium confidence
    result.manual_review_needed = (
        result.status == "partial"
        or tier == EnrichmentTier.medium
        or (result.identity_confidence_score >= 30 and result.identity_confidence_score < 70)
    )

    # Build enrichment notes
    notes = []
    if ghunt.success:
        notes.append(f"GHunt: name={ghunt.display_name or 'N/A'}")
    if holehe.success:
        notes.append(f"Holehe: {holehe.registered_services_count} services")
    if result.error_message:
        notes.append(f"Error: {result.error_message}")
    result.enrichment_notes = "; ".join(notes)

    # Source provider
    providers = []
    if ghunt.checked:
        providers.append("ghunt")
    if holehe.checked:
        providers.append("holehe")
    result.source_provider = ",".join(providers)

    return result
