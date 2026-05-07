"""Tests for username_utils module."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from email_osint_enricher.username_utils import generate_username_candidates


class TestGenerateUsernameCandidates:
    def test_simple_email(self):
        result = generate_username_candidates("john.doe@gmail.com")
        assert "john.doe" in result
        assert "johndoe" in result
        assert "john_doe" in result

    def test_email_with_plus(self):
        result = generate_username_candidates("john.doe+spam@gmail.com")
        assert "john.doe" in result

    def test_email_with_numbers(self):
        result = generate_username_candidates("johndoe123@gmail.com")
        assert "johndoe123" in result
        assert "johndoe" in result

    def test_with_applicant_name(self):
        result = generate_username_candidates("jdoe@bigcorp.com", "John Doe")
        assert "jdoe" in result
        # Name-based candidates
        assert any("john" in c.lower() for c in result)
        assert any("doe" in c.lower() for c in result)

    def test_dedup(self):
        result = generate_username_candidates("johndoe@gmail.com")
        assert len(result) == len(set(result))

    def test_empty_email(self):
        result = generate_username_candidates("")
        assert result == []

    def test_no_short_usernames(self):
        result = generate_username_candidates("ab@gmail.com")
        # "ab" is too short (<=2 chars) and should be excluded
        assert "ab" not in result

    def test_cyrillic_name(self):
        result = generate_username_candidates("ivan@mail.ru", "Иван Петров")
        assert "ivan" in result
