"""Scoring logic for email enrichment results.

Учитывает все 11 провайдеров. Включает:
  - email_footprint_score
  - identity_confidence_score
  - social_presence_score
  - email_reputation_score
  - deliverability_score
  - provider_consensus_score
  - conflict_risk_score
  - final_enrichment_score (weighted composite)
"""

from __future__ import annotations

from urllib.parse import urlparse

from email_osint_enricher.schemas import (
    EnrichmentResult,
    EnrichmentTier,
    EmailType,
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
    ProfileEntry,
)

# ── Service classifications ──────────────────────────────────────────────────

SOCIAL_SERVICES = {
    "twitter", "instagram", "facebook", "tiktok", "snapchat", "pinterest",
    "tumblr", "reddit", "discord", "telegram", "vk", "flickr", "imgur",
    "spotify", "deezer", "lastfm", "myspace", "quora", "medium",
}

PROFESSIONAL_SERVICES = {
    "github", "gitlab", "bitbucket", "stackoverflow", "linkedin",
    "behance", "dribbble", "figma", "notion", "trello", "slack",
    "docker", "npmjs", "pypi", "hackernews", "producthunt",
    "aboutme", "angel", "crunchbase",
}


def classify_holehe_services(services: list[str]) -> tuple[int, int]:
    """Return (social_count, professional_count)."""
    social = sum(1 for s in services if s.lower().strip() in SOCIAL_SERVICES)
    prof = sum(1 for s in services if s.lower().strip() in PROFESSIONAL_SERVICES)
    return social, prof


# ── Profile merging ──────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    """Normalize URL for dedup: lowercase, strip trailing slash/params."""
    url = url.strip().lower().rstrip("/")
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/")
    except Exception:
        return url


def merge_profiles(
    blackbird: BlackbirdResult | None = None,
    maigret: MaigretResult | None = None,
    sherlock: SherlockResult | None = None,
    emailcrawlr: EmailCrawlrResult | None = None,
) -> list[ProfileEntry]:
    """Merge profiles from all providers, deduplicate by normalized URL."""
    seen: dict[str, ProfileEntry] = {}

    def _add(url: str, provider: str, matched_by: str = "email", confidence: int = 50):
        norm = _normalize_url(url)
        if not norm or len(norm) < 10:
            return
        if norm in seen:
            # Boost confidence if seen from multiple providers
            seen[norm].confidence = min(seen[norm].confidence + 15, 100)
            if provider not in seen[norm].source_provider:
                seen[norm].source_provider += f",{provider}"
        else:
            # Extract platform from URL
            platform = ""
            try:
                host = urlparse(url).netloc.lower()
                platform = host.replace("www.", "").split(".")[0]
            except Exception:
                pass
            seen[norm] = ProfileEntry(
                url=url.strip(),
                platform=platform,
                source_provider=provider,
                matched_by=matched_by,
                confidence=confidence,
            )

    if blackbird and blackbird.success:
        for url in blackbird.profiles_list:
            _add(url, "blackbird", "email")

    if maigret and maigret.success:
        for url in maigret.profiles_list:
            _add(url, "maigret", "username")

    if sherlock and sherlock.success:
        for url in sherlock.profiles_list:
            _add(url, "sherlock", "username")

    if emailcrawlr and emailcrawlr.success:
        for url in emailcrawlr.social_accounts_list:
            _add(url, "emailcrawlr", "email", 55)

    return sorted(seen.values(), key=lambda p: -p.confidence)


# ── Sub-scores ───────────────────────────────────────────────────────────────

def compute_footprint_score(
    holehe: HoleheResult,
    blackbird: BlackbirdResult | None = None,
    maigret: MaigretResult | None = None,
    sherlock: SherlockResult | None = None,
    phone: PhoneExtractorResult | None = None,
    mosint: MosintResult | None = None,
    hudsonrock: HudsonRockResult | None = None,
    gravatar: GravatarResult | None = None,
    socialscan: SocialscanResult | None = None,
) -> int:
    score = 0

    if holehe.registered_services_count >= 5:
        score += 20
    elif holehe.registered_services_count >= 2:
        score += 12
    if holehe.social_services_count > 0:
        score += 15
    if holehe.professional_services_count > 0:
        score += 15

    if blackbird and blackbird.success:
        total = blackbird.email_profiles_count + blackbird.username_profiles_count
        if total >= 5:
            score += 20
        elif total >= 2:
            score += 12
        elif total >= 1:
            score += 5

    if maigret and maigret.success and maigret.profiles_count >= 3:
        score += 15
    elif maigret and maigret.success and maigret.profiles_count >= 1:
        score += 8

    if sherlock and sherlock.success and sherlock.profiles_count >= 3:
        score += 10

    if phone and phone.phone_candidates_found and phone.phone_candidate_confidence_score >= 50:
        score += 5

    if mosint and mosint.success and mosint.findings_count >= 2:
        score += 5

    # HudsonRock: compromised email = it's been actively used (strong footprint signal)
    if hudsonrock and hudsonrock.success and hudsonrock.is_compromised:
        if hudsonrock.stealers_count >= 3:
            score += 10
        elif hudsonrock.stealers_count >= 1:
            score += 6

    # Gravatar: has profile = active identity
    if gravatar and gravatar.success and gravatar.has_profile:
        score += 8
        if gravatar.linked_accounts_count >= 2:
            score += 5

    # Socialscan: registered platforms
    if socialscan and socialscan.success:
        if socialscan.registered_count >= 5:
            score += 10
        elif socialscan.registered_count >= 2:
            score += 6

    return min(score, 100)


def compute_identity_confidence(
    holehe: HoleheResult,
    row: InputRow,
    email_type: EmailType,
    blackbird: BlackbirdResult | None = None,
    maigret: MaigretResult | None = None,
    sherlock: SherlockResult | None = None,
    phone: PhoneExtractorResult | None = None,
    gravatar: GravatarResult | None = None,
) -> int:
    score = 0

    if holehe.registered_services_count >= 3:
        score += 20
    elif holehe.registered_services_count >= 1:
        score += 8

    if blackbird and blackbird.success and blackbird.email_profiles_count >= 2:
        score += 15
    elif blackbird and blackbird.success and blackbird.email_profiles_count >= 1:
        score += 8

    username_profiles = 0
    if maigret and maigret.success:
        username_profiles += maigret.profiles_count
    if sherlock and sherlock.success:
        username_profiles += sherlock.profiles_count
    if username_profiles >= 5:
        score += 15
    elif username_profiles >= 2:
        score += 8

    if email_type == EmailType.corporate:
        score += 10

    if phone and phone.phone_candidate_best and phone.phone_candidate_confidence_score >= 50:
        score += 10

    # Gravatar: real name / profile details strongly boost identity confidence
    if gravatar and gravatar.success and gravatar.has_profile:
        if gravatar.full_name:
            score += 12
            # Name match with applicantName
            if row.applicantName and _names_match(gravatar.full_name, row.applicantName):
                score += 10
        elif gravatar.display_name:
            score += 6
        if gravatar.location:
            score += 5

    return max(0, min(score, 100))


def compute_social_presence_score(
    holehe: HoleheResult,
    blackbird: BlackbirdResult | None = None,
    maigret: MaigretResult | None = None,
    sherlock: SherlockResult | None = None,
    emailcrawlr: EmailCrawlrResult | None = None,
    mosint: MosintResult | None = None,
    gravatar: GravatarResult | None = None,
    socialscan: SocialscanResult | None = None,
) -> int:
    """Aggregated social/online presence score (0-100)."""
    score = 0

    if holehe.social_services_count >= 3:
        score += 30
    elif holehe.social_services_count >= 1:
        score += 15

    if holehe.professional_services_count >= 2:
        score += 15
    elif holehe.professional_services_count >= 1:
        score += 10

    total_profiles = 0
    if blackbird and blackbird.success:
        total_profiles += blackbird.email_profiles_count + blackbird.username_profiles_count
    if maigret and maigret.success:
        total_profiles += maigret.profiles_count
    if sherlock and sherlock.success:
        total_profiles += sherlock.profiles_count

    if total_profiles >= 10:
        score += 25
    elif total_profiles >= 5:
        score += 15
    elif total_profiles >= 2:
        score += 10

    if emailcrawlr and emailcrawlr.success and emailcrawlr.social_accounts_count >= 2:
        score += 10

    if mosint and mosint.success and mosint.social_signal:
        score += 5

    # Gravatar linked accounts = social presence
    if gravatar and gravatar.success and gravatar.has_profile:
        if gravatar.linked_accounts_count >= 3:
            score += 10
        elif gravatar.linked_accounts_count >= 1:
            score += 5

    # Socialscan: platforms where email is registered
    if socialscan and socialscan.success:
        if socialscan.registered_count >= 5:
            score += 10
        elif socialscan.registered_count >= 2:
            score += 5

    return min(score, 100)


def compute_email_reputation_score(
    emailrep: EmailRepResult | None = None,
    emailcrawlr: EmailCrawlrResult | None = None,
    hudsonrock: HudsonRockResult | None = None,
) -> int:
    """Email reputation score (0-100). Higher = better reputation."""
    score = 50  # neutral baseline

    if emailrep and emailrep.success:
        rep_map = {"high": 30, "medium": 10, "low": -10, "none": -20}
        score += rep_map.get(emailrep.reputation.lower(), 0)
        if emailrep.suspicious:
            score -= 25
        if emailrep.references >= 5:
            score += 10
        elif emailrep.references >= 1:
            score += 5

    if emailcrawlr and emailcrawlr.success:
        if emailcrawlr.deliverability in ("true", True, "yes"):
            score += 5

    # HudsonRock: compromised = lower reputation (security risk)
    if hudsonrock and hudsonrock.success and hudsonrock.is_compromised:
        if hudsonrock.stealers_count >= 3:
            score -= 15  # Heavily compromised
        elif hudsonrock.stealers_count >= 1:
            score -= 8   # Some compromise

    return max(0, min(score, 100))


def compute_deliverability_score(
    email_type: EmailType,
    has_mx: bool = True,
    emailrep: EmailRepResult | None = None,
    emailcrawlr: EmailCrawlrResult | None = None,
) -> int:
    """Deliverability score (0-100)."""
    score = 0

    if has_mx:
        score += 40

    if email_type in (EmailType.gmail, EmailType.google_workspace):
        score += 30
    elif email_type == EmailType.corporate:
        score += 20
    elif email_type == EmailType.free_provider:
        score += 25

    if emailrep and emailrep.success:
        if "deliverable: yes" in emailrep.details_summary.lower():
            score += 20
        if "domain_exists: yes" in emailrep.details_summary.lower():
            score += 10

    if emailcrawlr and emailcrawlr.success:
        if emailcrawlr.deliverability in ("true", True, "yes"):
            score += 20

    return min(score, 100)


def compute_provider_consensus_score(merged_profiles: list[ProfileEntry]) -> int:
    """Provider consensus score (0-100).
    +10 if same URL appears in 2+ providers
    +15 if same platform appears in 2+ providers
    """
    score = 0

    # URLs seen by multiple providers
    multi_provider_urls = sum(
        1 for p in merged_profiles if "," in p.source_provider
    )
    score += min(multi_provider_urls * 10, 40)

    # Same platform from different providers
    platform_providers: dict[str, set[str]] = {}
    for p in merged_profiles:
        if p.platform:
            if p.platform not in platform_providers:
                platform_providers[p.platform] = set()
            for prov in p.source_provider.split(","):
                platform_providers[p.platform].add(prov.strip())

    multi_platform = sum(1 for providers in platform_providers.values() if len(providers) >= 2)
    score += min(multi_platform * 15, 45)

    return min(score, 100)


def compute_conflict_risk_score(
    row: InputRow,
    merged_profiles: list[ProfileEntry] | None = None,
) -> int:
    """Conflict risk score (0-100). Higher = more conflict/risk."""
    score = 0

    # Too many weak/ambiguous profiles
    if merged_profiles:
        weak = sum(1 for p in merged_profiles if p.confidence < 40)
        if weak >= 5:
            score += 20
        elif weak >= 3:
            score += 10

    return min(score, 100)


def _names_match(found_name: str, expected_name: str) -> bool:
    found_parts = set(found_name.lower().split())
    expected_parts = set(expected_name.lower().split())
    if not found_parts or not expected_parts:
        return False
    overlap = found_parts & expected_parts
    return len(overlap) >= 1


def compute_final_enrichment_score(
    identity: int,
    footprint: int,
    social: int,
    reputation: int,
    deliverability: int,
    consensus: int,
    conflict: int,
    risk_score: float = 0.0,
) -> int:
    """Compute final weighted composite score (0-100).

    Formula:
      0.25 * identity + 0.20 * footprint + 0.15 * social
      + 0.15 * reputation + 0.10 * deliverability + 0.10 * consensus
      - 0.20 * (risk_score * 100) - 0.15 * conflict
    """
    raw = (
        0.25 * identity
        + 0.20 * footprint
        + 0.15 * social
        + 0.15 * reputation
        + 0.10 * deliverability
        + 0.10 * consensus
        - 0.20 * (risk_score * 100)
        - 0.15 * conflict
    )
    return max(0, min(int(round(raw)), 100))


def determine_tier(footprint: int, identity: int, final: int = 0) -> EnrichmentTier:
    best = max(footprint, identity, final)
    if best >= 70:
        return EnrichmentTier.strong
    if best >= 40:
        return EnrichmentTier.medium
    if best >= 15:
        return EnrichmentTier.weak
    return EnrichmentTier.no_signal


def get_recommended_action(tier: EnrichmentTier) -> str:
    actions = {
        EnrichmentTier.strong: "Use enriched identity for personalized outreach",
        EnrichmentTier.medium: "Manual verification before outreach",
        EnrichmentTier.weak: "Try additional enrichment provider",
        EnrichmentTier.no_signal: "Do not prioritize unless claim value is high",
    }
    return actions[tier]


# ── Main scorer ──────────────────────────────────────────────────────────────

def score_result(
    result: EnrichmentResult,
    holehe: HoleheResult,
    row: InputRow,
    blackbird: BlackbirdResult | None = None,
    maigret: MaigretResult | None = None,
    sherlock: SherlockResult | None = None,
    phone: PhoneExtractorResult | None = None,
    emailrep: EmailRepResult | None = None,
    mosint: MosintResult | None = None,
    emailcrawlr: EmailCrawlrResult | None = None,
    hudsonrock: HudsonRockResult | None = None,
    gravatar: GravatarResult | None = None,
    socialscan: SocialscanResult | None = None,
    has_mx: bool = True,
) -> EnrichmentResult:
    """Apply all scoring to an EnrichmentResult in-place and return it."""

    # Merge profiles
    merged = merge_profiles(
        blackbird=blackbird, maigret=maigret, sherlock=sherlock,
        emailcrawlr=emailcrawlr,
    )
    result.merged_profiles_count = len(merged)

    # Sub-scores
    result.email_footprint_score = compute_footprint_score(
        holehe, blackbird, maigret, sherlock, phone, mosint,
        hudsonrock, gravatar, socialscan,
    )
    result.identity_confidence_score = compute_identity_confidence(
        holehe, row, EmailType(result.email_type),
        blackbird, maigret, sherlock, phone, gravatar,
    )
    result.social_presence_score = compute_social_presence_score(
        holehe, blackbird, maigret, sherlock, emailcrawlr, mosint,
        gravatar, socialscan,
    )
    result.email_reputation_score = compute_email_reputation_score(
        emailrep, emailcrawlr, hudsonrock,
    )
    result.deliverability_score = compute_deliverability_score(
        EmailType(result.email_type), has_mx, emailrep, emailcrawlr,
    )
    result.provider_consensus_score = compute_provider_consensus_score(merged)
    result.conflict_risk_score = compute_conflict_risk_score(row, merged)

    # Risk from emailrep
    risk = emailrep.risk_score if emailrep and emailrep.success else 0.0

    result.final_enrichment_score = compute_final_enrichment_score(
        result.identity_confidence_score,
        result.email_footprint_score,
        result.social_presence_score,
        result.email_reputation_score,
        result.deliverability_score,
        result.provider_consensus_score,
        result.conflict_risk_score,
        risk,
    )

    tier = determine_tier(
        result.email_footprint_score,
        result.identity_confidence_score,
        result.final_enrichment_score,
    )
    result.outreach_enrichment_tier = tier.value
    result.recommended_next_action = get_recommended_action(tier)

    result.manual_review_needed = (
        str(result.status) == "partial" or result.status == "partial"
        or tier == EnrichmentTier.medium
        or result.conflict_risk_score >= 30
        or (result.identity_confidence_score >= 30 and result.identity_confidence_score < 70)
    )

    # Build notes
    notes = []
    if holehe.success:
        notes.append(f"Holehe: {holehe.registered_services_count} svc")
    if blackbird and blackbird.success:
        notes.append(f"BB: {blackbird.email_profiles_count + blackbird.username_profiles_count} profiles")
    if maigret and maigret.success:
        notes.append(f"Mai: {maigret.profiles_count}")
    if sherlock and sherlock.success:
        notes.append(f"Sher: {sherlock.profiles_count}")
    if emailrep and emailrep.success:
        notes.append(f"ER: {emailrep.reputation}")
    if mosint and mosint.success:
        notes.append(f"Mos: {mosint.findings_count}f")
    if emailcrawlr and emailcrawlr.success:
        notes.append(f"EC: {emailcrawlr.social_accounts_count}soc")
    if hudsonrock and hudsonrock.success:
        if hudsonrock.is_compromised:
            notes.append(f"HR: {hudsonrock.stealers_count} stealers")
        else:
            notes.append("HR: clean")
    if gravatar and gravatar.success and gravatar.has_profile:
        grav_parts = []
        if gravatar.full_name:
            grav_parts.append(gravatar.full_name)
        elif gravatar.display_name:
            grav_parts.append(gravatar.display_name)
        if gravatar.linked_accounts_count > 0:
            grav_parts.append(f"{gravatar.linked_accounts_count}acc")
        notes.append(f"Grav: {', '.join(grav_parts) if grav_parts else 'profile'}")
    if socialscan and socialscan.success and socialscan.registered_count > 0:
        notes.append(f"SS: {socialscan.registered_count}reg")
    if phone and phone.phone_candidates_found:
        notes.append(f"Ph: {phone.phone_candidate_best or 'found'}")
    if result.error_message:
        notes.append(f"Err: {result.error_message}")
    result.enrichment_notes = "; ".join(notes)

    # Total profiles
    total = 0
    if blackbird and blackbird.success:
        total += blackbird.email_profiles_count + blackbird.username_profiles_count
    if maigret and maigret.success:
        total += maigret.profiles_count
    if sherlock and sherlock.success:
        total += sherlock.profiles_count
    result.total_profiles_found = total

    # Source providers
    providers = []
    for name, checked in [
        ("holehe", holehe.checked),
        ("blackbird", blackbird.checked if blackbird else False),
        ("maigret", maigret.checked if maigret else False),
        ("sherlock", sherlock.checked if sherlock else False),
        ("emailrep", emailrep.checked if emailrep else False),
        ("mosint", mosint.checked if mosint else False),
        ("emailcrawlr", emailcrawlr.checked if emailcrawlr else False),
        ("hudsonrock", hudsonrock.checked if hudsonrock else False),
        ("gravatar", gravatar.checked if gravatar else False),
        ("socialscan", socialscan.checked if socialscan else False),
        ("phone_extractor", phone.checked if phone else False),
    ]:
        if checked:
            providers.append(name)
    result.source_provider = ",".join(providers)

    return result
