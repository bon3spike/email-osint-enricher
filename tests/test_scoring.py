"""Tests for scoring module."""

import pytest
from email_osint_enricher.scoring import (
    compute_footprint_score,
    compute_identity_confidence,
    compute_social_presence_score,
    compute_email_reputation_score,
    compute_deliverability_score,
    compute_provider_consensus_score,
    compute_conflict_risk_score,
    compute_final_enrichment_score,
    determine_tier,
    get_recommended_action,
    classify_holehe_services,
    merge_profiles,
    score_result,
)
from email_osint_enricher.schemas import (
    HoleheResult, BlackbirdResult, MaigretResult,
    SherlockResult, PhoneExtractorResult,
    EmailRepResult, MosintResult,
    EmailCrawlrResult,
    EnrichmentResult, EnrichmentTier, EmailType, InputRow,
    ProfileEntry,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _empty_holehe():
    return HoleheResult()

def _empty_row():
    return InputRow(email="test@example.com")


# ── Footprint score ─────────────────────────────────────────────────────────

class TestComputeFootprintScore:

    def test_empty_results(self):
        assert compute_footprint_score(_empty_holehe()) == 0

    def test_holehe_5plus_services(self):
        h = HoleheResult(success=True, registered_services_count=6)
        assert compute_footprint_score(h) == 20

    def test_holehe_2_to_4_services(self):
        h = HoleheResult(success=True, registered_services_count=3)
        assert compute_footprint_score(h) == 12

    def test_holehe_social(self):
        h = HoleheResult(success=True, registered_services_count=6, social_services_count=2)
        assert compute_footprint_score(h) >= 35

    def test_holehe_professional(self):
        h = HoleheResult(success=True, registered_services_count=6, professional_services_count=2)
        assert compute_footprint_score(h) >= 35

    def test_blackbird_profiles(self):
        bb = BlackbirdResult(success=True, email_profiles_count=3, username_profiles_count=3)
        s = compute_footprint_score(_empty_holehe(), blackbird=bb)
        assert s >= 20

    def test_maigret_profiles(self):
        m = MaigretResult(success=True, profiles_count=4)
        s = compute_footprint_score(_empty_holehe(), maigret=m)
        assert s >= 15

    def test_cap_at_100(self):
        h = HoleheResult(success=True, registered_services_count=10,
                         social_services_count=5, professional_services_count=3)
        bb = BlackbirdResult(success=True, email_profiles_count=10)
        m = MaigretResult(success=True, profiles_count=10)
        s = compute_footprint_score(h, blackbird=bb, maigret=m)
        assert s <= 100


# ── Identity confidence ─────────────────────────────────────────────────────

class TestComputeIdentityConfidence:

    def test_empty(self):
        assert compute_identity_confidence(_empty_holehe(),
                                           _empty_row(), EmailType.unknown) == 0

    def test_corporate_email(self):
        assert compute_identity_confidence(_empty_holehe(),
                                           _empty_row(), EmailType.corporate) == 10

    def test_blackbird_identity(self):
        bb = BlackbirdResult(success=True, email_profiles_count=3)
        s = compute_identity_confidence(_empty_holehe(),
                                        _empty_row(), EmailType.unknown, blackbird=bb)
        assert s >= 15

    def test_username_profiles_identity(self):
        m = MaigretResult(success=True, profiles_count=6)
        s = compute_identity_confidence(_empty_holehe(),
                                        _empty_row(), EmailType.unknown, maigret=m)
        assert s >= 15

    def test_holehe_services(self):
        h = HoleheResult(success=True, registered_services_count=5)
        s = compute_identity_confidence(h, _empty_row(), EmailType.unknown)
        assert s >= 20

    def test_phone_identity(self):
        ph = PhoneExtractorResult(
            checked=True, success=True,
            phone_candidates_found=True,
            phone_candidate_best="+1234567890",
            phone_candidate_confidence_score=80,
        )
        s = compute_identity_confidence(_empty_holehe(), _empty_row(), EmailType.unknown, phone=ph)
        assert s >= 10


# ── Social presence score ───────────────────────────────────────────────────

class TestComputeSocialPresenceScore:

    def test_empty(self):
        assert compute_social_presence_score(_empty_holehe()) == 0

    def test_holehe_social(self):
        h = HoleheResult(success=True, social_services_count=4)
        assert compute_social_presence_score(h) >= 30

    def test_with_profiles(self):
        h = HoleheResult(success=True, social_services_count=2)
        bb = BlackbirdResult(success=True, email_profiles_count=3, username_profiles_count=3)
        s = compute_social_presence_score(h, blackbird=bb)
        assert s >= 25


# ── Email reputation score ──────────────────────────────────────────────────

class TestComputeEmailReputationScore:

    def test_no_providers(self):
        assert compute_email_reputation_score() == 50  # neutral

    def test_high_reputation(self):
        er = EmailRepResult(success=True, reputation="high", references=5)
        s = compute_email_reputation_score(emailrep=er)
        assert s >= 90

    def test_suspicious(self):
        er = EmailRepResult(success=True, reputation="low", suspicious=True)
        s = compute_email_reputation_score(emailrep=er)
        assert s <= 25


# ── Deliverability score ────────────────────────────────────────────────────

class TestComputeDeliverabilityScore:

    def test_gmail(self):
        s = compute_deliverability_score(EmailType.gmail)
        assert s >= 70

    def test_unknown_no_mx(self):
        s = compute_deliverability_score(EmailType.unknown, has_mx=False)
        assert s == 0


# ── Provider consensus score ────────────────────────────────────────────────

class TestComputeProviderConsensusScore:

    def test_empty(self):
        assert compute_provider_consensus_score([]) == 0

    def test_multi_provider_url(self):
        profiles = [
            ProfileEntry(url="https://github.com/test", platform="github",
                         source_provider="blackbird,maigret", confidence=65),
        ]
        s = compute_provider_consensus_score(profiles)
        assert s >= 10

    def test_same_platform_different_providers(self):
        profiles = [
            ProfileEntry(url="https://github.com/test1", platform="github",
                         source_provider="blackbird", confidence=50),
            ProfileEntry(url="https://github.com/test2", platform="github",
                         source_provider="maigret", confidence=50),
        ]
        s = compute_provider_consensus_score(profiles)
        assert s >= 15


# ── Conflict risk score ─────────────────────────────────────────────────────

class TestComputeConflictRiskScore:

    def test_no_conflict(self):
        r = InputRow(email="test@x.com", applicantName="John Doe")
        assert compute_conflict_risk_score(r) == 0

    def test_weak_profiles(self):
        r = InputRow(email="test@x.com")
        profiles = [
            ProfileEntry(url=f"https://site{i}.com/user", platform=f"site{i}",
                         source_provider="blackbird", confidence=30)
            for i in range(5)
        ]
        assert compute_conflict_risk_score(r, profiles) >= 20


# ── Merge profiles ──────────────────────────────────────────────────────────

class TestMergeProfiles:

    def test_empty(self):
        assert merge_profiles() == []

    def test_dedup_same_url(self):
        bb = BlackbirdResult(success=True, profiles_list=[
            "https://github.com/test", "https://github.com/test/",
        ])
        profiles = merge_profiles(blackbird=bb)
        assert len(profiles) == 1

    def test_multi_provider_boost(self):
        bb = BlackbirdResult(success=True, profiles_list=["https://github.com/test"])
        m = MaigretResult(success=True, profiles_list=["https://github.com/test"])
        profiles = merge_profiles(blackbird=bb, maigret=m)
        assert len(profiles) == 1
        assert profiles[0].confidence > 50  # boosted

    def test_different_urls(self):
        bb = BlackbirdResult(success=True, profiles_list=[
            "https://github.com/test", "https://twitter.com/test",
        ])
        profiles = merge_profiles(blackbird=bb)
        assert len(profiles) == 2


# ── Final score ──────────────────────────────────────────────────────────────

class TestComputeFinalEnrichmentScore:

    def test_all_zeros(self):
        assert compute_final_enrichment_score(0, 0, 0, 0, 0, 0, 0, 0.0) == 0

    def test_perfect_scores(self):
        s = compute_final_enrichment_score(100, 100, 100, 100, 100, 100, 0, 0.0)
        assert s >= 90

    def test_high_conflict_reduces(self):
        s1 = compute_final_enrichment_score(70, 70, 70, 70, 70, 70, 0, 0.0)
        s2 = compute_final_enrichment_score(70, 70, 70, 70, 70, 70, 100, 0.0)
        assert s2 < s1


# ── Tier & action ────────────────────────────────────────────────────────────

class TestDetermineTier:

    def test_strong(self):
        assert determine_tier(75, 80) == EnrichmentTier.strong

    def test_medium(self):
        assert determine_tier(45, 50) == EnrichmentTier.medium

    def test_weak(self):
        assert determine_tier(20, 10) == EnrichmentTier.weak

    def test_no_signal(self):
        assert determine_tier(0, 0) == EnrichmentTier.no_signal


class TestRecommendedAction:

    def test_all_tiers(self):
        for tier in EnrichmentTier:
            action = get_recommended_action(tier)
            assert action and isinstance(action, str)


class TestClassifyHoleheServices:

    def test_social_and_professional(self):
        services = ["twitter", "instagram", "github", "linkedin", "randomsite"]
        s, p = classify_holehe_services(services)
        assert s == 2
        assert p == 2

    def test_empty(self):
        assert classify_holehe_services([]) == (0, 0)


# ── Full score_result ────────────────────────────────────────────────────────

class TestScoreResult:

    def test_full_scoring(self):
        r = EnrichmentResult(email="test@gmail.com", email_type=EmailType.gmail)
        h = HoleheResult(success=True, registered_services_count=5,
                         registered_services_list=["twitter", "github", "facebook"],
                         social_services_count=2, professional_services_count=1)
        row = InputRow(email="test@gmail.com")
        result = score_result(r, h, row)
        assert result.email_footprint_score > 0
        assert result.outreach_enrichment_tier != "No Signal"

    def test_scoring_with_all_providers(self):
        r = EnrichmentResult(email="test@gmail.com", email_type=EmailType.gmail)
        h = HoleheResult(success=True, registered_services_count=8,
                         social_services_count=4, professional_services_count=2)
        bb = BlackbirdResult(success=True, email_profiles_count=3, username_profiles_count=5,
                             profiles_list=["https://github.com/test", "https://twitter.com/test"])
        m = MaigretResult(success=True, profiles_count=10,
                          profiles_list=["https://github.com/test"])
        s = SherlockResult(success=True, profiles_count=5)
        er = EmailRepResult(success=True, reputation="high", references=5)
        mos = MosintResult(success=True, findings_count=3, social_signal=True)
        ec = EmailCrawlrResult(success=True, social_accounts_count=2,
                                deliverability="true")
        row = InputRow(email="test@gmail.com", applicantName="John Doe")

        result = score_result(
            r, h, row,
            blackbird=bb, maigret=m, sherlock=s,
            emailrep=er, mosint=mos,
            emailcrawlr=ec,
        )
        assert result.email_footprint_score >= 50
        assert result.social_presence_score >= 50
        assert result.email_reputation_score >= 80
        assert result.final_enrichment_score >= 50
        assert result.outreach_enrichment_tier == "Strong"
        assert result.merged_profiles_count >= 1
        assert "Holehe" in result.enrichment_notes

    def test_disabled_provider_no_score_impact(self):
        """Disabled/unchecked providers should not affect scoring."""
        r = EnrichmentResult(email="test@gmail.com", email_type=EmailType.gmail)
        h = HoleheResult(success=True, registered_services_count=3)
        row = InputRow(email="test@gmail.com")
        # Score with no optional providers
        result1 = score_result(r.model_copy(), h, row)
        # Score with unchecked providers (not run)
        mos = MosintResult(checked=False, success=False)
        result2 = score_result(r.model_copy(), h, row, mosint=mos)
        assert result1.email_footprint_score == result2.email_footprint_score
        assert result1.identity_confidence_score == result2.identity_confidence_score
