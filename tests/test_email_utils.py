"""Tests for email utility functions."""

import sys
from pathlib import Path

# Add src to path for direct pytest execution
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from email_osint_enricher.email_utils import (
    EmailType,
    classify_email,
    get_domain,
    is_google_email,
    is_valid_email,
    mask_email,
    normalize_email,
)


class TestIsValidEmail:
    def test_valid_emails(self):
        assert is_valid_email("test@gmail.com")
        assert is_valid_email("user.name+tag@example.com")
        assert is_valid_email("a@b.co")
        assert is_valid_email("  test@gmail.com  ")

    def test_invalid_emails(self):
        assert not is_valid_email("")
        assert not is_valid_email("not-an-email")
        assert not is_valid_email("@domain.com")
        assert not is_valid_email("user@")
        assert not is_valid_email("user@.com")


class TestNormalizeEmail:
    def test_lowercase(self):
        assert normalize_email("Test@Gmail.Com") == "test@gmail.com"

    def test_strip(self):
        assert normalize_email("  test@gmail.com  ") == "test@gmail.com"

    def test_gmail_dots_removed(self):
        assert normalize_email("j.o.h.n@gmail.com") == "john@gmail.com"

    def test_gmail_plus_alias_removed(self):
        assert normalize_email("john+ftx@gmail.com") == "john@gmail.com"

    def test_gmail_dots_and_plus(self):
        assert normalize_email("j.o.h.n+alias@gmail.com") == "john@gmail.com"

    def test_googlemail_same_as_gmail(self):
        assert normalize_email("test@googlemail.com") == "test@googlemail.com"
        # Dots removed for googlemail too
        assert normalize_email("t.e.s.t@googlemail.com") == "test@googlemail.com"

    def test_non_gmail_dots_preserved(self):
        assert normalize_email("first.last@company.com") == "first.last@company.com"

    def test_non_gmail_plus_preserved(self):
        assert normalize_email("user+tag@yahoo.com") == "user+tag@yahoo.com"


class TestGetDomain:
    def test_basic(self):
        assert get_domain("test@gmail.com") == "gmail.com"

    def test_case_insensitive(self):
        assert get_domain("Test@GMAIL.COM") == "gmail.com"

    def test_no_at(self):
        assert get_domain("noemail") == ""


class TestClassifyEmail:
    def test_gmail(self):
        assert classify_email("test@gmail.com") == EmailType.gmail

    def test_googlemail(self):
        assert classify_email("test@googlemail.com") == EmailType.gmail

    def test_free_provider(self):
        assert classify_email("test@yahoo.com") == EmailType.free_provider
        assert classify_email("test@protonmail.com") == EmailType.free_provider
        assert classify_email("test@hotmail.com") == EmailType.free_provider

    def test_corporate(self):
        assert classify_email("ceo@bigcorp.com") == EmailType.corporate

    def test_unknown_empty(self):
        assert classify_email("noatsign") == EmailType.unknown


class TestIsGoogleEmail:
    def test_gmail(self):
        assert is_google_email("test@gmail.com")

    def test_googlemail(self):
        assert is_google_email("test@googlemail.com")

    def test_corporate_not_google(self):
        assert not is_google_email("test@company.com")

    def test_force(self):
        assert is_google_email("test@company.com", force=True)


class TestMaskEmail:
    def test_basic(self):
        assert mask_email("john@gmail.com") == "j***@gmail.com"

    def test_single_char_local(self):
        assert mask_email("a@x.com") == "a***@x.com"

    def test_no_at(self):
        assert mask_email("noemail") == "***@***"

    def test_empty(self):
        assert mask_email("") == "***@***"
