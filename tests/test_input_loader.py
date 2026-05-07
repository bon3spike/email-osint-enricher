"""Tests for input loader."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pandas as pd

from email_osint_enricher.input_loader import load_input


class TestLoadInput:
    def test_load_csv(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
            f.write("email,applicantName\n")
            f.write("test@gmail.com,John Doe\n")
            f.write("user@yahoo.com,Jane Smith\n")
            path = f.name

        rows = load_input(path)
        assert len(rows) == 2
        assert rows[0].email == "test@gmail.com"
        assert rows[0].applicantName == "John Doe"
        assert rows[1].email == "user@yahoo.com"
        Path(path).unlink()

    def test_skip_invalid_emails(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
            f.write("email\n")
            f.write("valid@gmail.com\n")
            f.write("not-an-email\n")
            f.write("\n")
            f.write("also-valid@yahoo.com\n")
            path = f.name

        rows = load_input(path)
        assert len(rows) == 2
        Path(path).unlink()

    def test_custom_email_column(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
            f.write("applicantEmail,name\n")
            f.write("test@gmail.com,Test\n")
            path = f.name

        rows = load_input(path, email_column="applicantEmail")
        assert len(rows) == 1
        assert rows[0].email == "test@gmail.com"
        Path(path).unlink()

    def test_xlsx_loading(self):
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            path = f.name

        df = pd.DataFrame({
            "email": ["test@gmail.com", "user@yahoo.com"],
            "applicantName": ["John", "Jane"],
            "claim_value": ["1000", "2000"],
        })
        df.to_excel(path, index=False)

        rows = load_input(path)
        assert len(rows) == 2
        assert rows[0].claim_value == 1000.0
        Path(path).unlink()

    def test_file_not_found(self):
        try:
            load_input("nonexistent.csv")
            assert False, "Should have raised FileNotFoundError"
        except FileNotFoundError:
            pass

    def test_missing_email_column(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
            f.write("name,value\n")
            f.write("test,100\n")
            path = f.name

        try:
            load_input(path, email_column="email")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass
        Path(path).unlink()
