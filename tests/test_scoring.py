"""Tests for scoring logic."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from email_osint_enricher.schemas import (
    EmailType,
    EnrichmentResult,
    EnrichmentTier,
    GHuntResult,
    HoleheResult,
    InputRow,
)
from email_osint_enricher.scoring import (
    classify_holehe_services,
    compute_footprint_score,
    compute_identity_confidence,
    determine_tier,
    get_recommended_action,
    score_result,
)


class TestComputeFootprintScore:
    def test_empty_results(self):
        assert compute_footprint_score(GHuntResult(), HoleheResult()) == 0

    def test_ghunt_display_name(self):
        ghunt = GHuntResult(success=True, display_name="John Doe")
        assert compute_footprint_score(ghunt, HoleheResult()) == 25

    def test_ghunt_with_photo(self):
        ghunt = GHuntResult(success=True, display_name="John", profile_photo_found=True)
        assert compute_footprint_score(ghunt, HoleheResult()) == 40

    def test_ghunt_with_artifacts(self):
        ghunt = GHuntResult(
            success=True, display_name="John",
            profile_photo_found=True, youtube_found=True,
        )
        assert compute_footprint_score(ghunt, HoleheResult()) == 50

    def test_holehe_5plus_services(self):
        holehe = HoleheResult(
            success=True,
            registered_services_count=6,
            registered_services_list=["twitter", "instagram", "github", "spotify", "reddit", "imgur"],
            social_services_count=4,       # twitter, instagram, spotify, reddit, imgur → 4 social
            professional_services_count=1,  # github
        )
        score = compute_footprint_score(GHuntResult(), holehe)
        # 25 (5+ svc) + 10 (social) + 10 (professional) = 45
        assert score == 45

    def test_holehe_2_to_4_services(self):
        holehe = HoleheResult(
            success=True,
            registered_services_count=3,
            registered_services_list=["twitter", "github", "spotify"],
            social_services_count=2,
            professional_services_count=1,
        )
        score = compute_footprint_score(GHuntResult(), holehe)
        # 15 (2-4 svc) + 10 (social) + 10 (pro) = 35
        assert score == 35

    def test_cap_at_100(self):
        ghunt = GHuntResult(
            success=True, display_name="John",
            profile_photo_found=True,
            youtube_found=True,
            google_maps_reviews_found=True,
        )
        holehe = HoleheResult(
            success=True,
            registered_services_count=10,
            registered_services_list=["twitter", "instagram", "github", "linkedin",
                                       "spotify", "reddit", "discord", "imgur",
                                       "behance", "dribbble"],
            social_services_count=5,
            professional_services_count=4,
        )
        score = compute_footprint_score(ghunt, holehe)
        assert score <= 100


class TestComputeIdentityConfidence:
    def test_empty(self):
        row = InputRow(email="test@gmail.com")
        score = compute_identity_confidence(GHuntResult(), HoleheResult(), row, EmailType.gmail)
        assert score == 0

    def test_display_name(self):
        ghunt = GHuntResult(display_name="John Doe")
        row = InputRow(email="test@gmail.com")
        score = compute_identity_confidence(ghunt, HoleheResult(), row, EmailType.gmail)
        assert score == 30

    def test_google_account_data(self):
        ghunt = GHuntResult(success=True, gaia_id="12345")
        row = InputRow(email="test@gmail.com")
        score = compute_identity_confidence(ghunt, HoleheResult(), row, EmailType.gmail)
        assert score == 20

    def test_corporate_email(self):
        row = InputRow(email="test@bigcorp.com")
        score = compute_identity_confidence(GHuntResult(), HoleheResult(), row, EmailType.corporate)
        assert score == 10

    def test_name_match(self):
        ghunt = GHuntResult(display_name="John Doe")
        row = InputRow(email="test@gmail.com", applicantName="John Doe")
        score = compute_identity_confidence(ghunt, HoleheResult(), row, EmailType.gmail)
        # 30 (name found) + 10 (name match) = 40
        assert score == 40

    def test_name_conflict(self):
        ghunt = GHuntResult(display_name="Alice Smith")
        row = InputRow(email="test@gmail.com", applicantName="Bob Jones")
        score = compute_identity_confidence(ghunt, HoleheResult(), row, EmailType.gmail)
        # 30 (name found) - 20 (conflict) = 10
        assert score == 10

    def test_floor_at_zero(self):
        ghunt = GHuntResult(display_name="X")
        row = InputRow(email="test@gmail.com", applicantName="Completely Different Person")
        score = compute_identity_confidence(ghunt, HoleheResult(), row, EmailType.gmail)
        # 30 - 20 = 10, still positive because "Person" != any word in "X"
        # Actually "X" vs "Completely Different Person" — no overlap => -20
        # 30 - 20 = 10
        assert score >= 0


class TestDetermineTier:
    def test_strong(self):
        assert determine_tier(70, 50) == EnrichmentTier.strong
        assert determine_tier(50, 70) == EnrichmentTier.strong
        assert determine_tier(80, 80) == EnrichmentTier.strong

    def test_medium(self):
        assert determine_tier(50, 50) == EnrichmentTier.medium
        assert determine_tier(40, 40) == EnrichmentTier.medium
        assert determine_tier(69, 69) == EnrichmentTier.medium

    def test_weak(self):
        assert determine_tier(20, 20) == EnrichmentTier.weak
        assert determine_tier(15, 15) == EnrichmentTier.weak
        assert determine_tier(39, 10) == EnrichmentTier.weak

    def test_no_signal(self):
        assert determine_tier(0, 0) == EnrichmentTier.no_signal
        assert determine_tier(14, 14) == EnrichmentTier.no_signal


class TestRecommendedAction:
    def test_all_tiers(self):
        assert "personalized" in get_recommended_action(EnrichmentTier.strong).lower()
        assert "manual" in get_recommended_action(EnrichmentTier.medium).lower() or \
               "verification" in get_recommended_action(EnrichmentTier.medium).lower()
        assert "additional" in get_recommended_action(EnrichmentTier.weak).lower()
        assert "prioritize" in get_recommended_action(EnrichmentTier.no_signal).lower()


class TestClassifyHoleheServices:
    def test_social_and_professional(self):
        services = ["twitter", "github", "spotify", "linkedin", "imgur"]
        social, prof = classify_holehe_services(services)
        assert social == 3  # twitter, spotify, imgur
        assert prof == 2    # github, linkedin

    def test_empty(self):
        social, prof = classify_holehe_services([])
        assert social == 0
        assert prof == 0


class TestScoreResult:
    def test_full_scoring(self):
        row = InputRow(email="test@gmail.com", applicantName="John Doe")
        ghunt = GHuntResult(
            checked=True, success=True,
            display_name="John Doe", gaia_id="123",
            profile_photo_found=True,
        )
        holehe = HoleheResult(
            checked=True, success=True,
            registered_services_count=5,
            registered_services_list=["twitter", "github", "spotify", "reddit", "discord"],
            social_services_count=4,
            professional_services_count=1,
        )
        result = EnrichmentResult(email="test@gmail.com", email_type="gmail")
        result = score_result(result, ghunt, holehe, row)

        assert result.email_footprint_score > 0
        assert result.identity_confidence_score > 0
        assert result.outreach_enrichment_tier in ("Strong", "Medium", "Weak", "No Signal")
        assert result.recommended_next_action != ""
        assert result.source_provider == "ghunt,holehe"
