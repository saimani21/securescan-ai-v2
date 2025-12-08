"""Basic tests for the Scanner class."""

from pathlib import Path

import pytest

from securescan.core.scanner import Scanner
from securescan.utils.config import Config


class TestScannerBasic:
    """Basic scanner functionality tests."""

    def test_scanner_initialization_default(self):
        """Scanner should initialize with default config."""
        scanner = Scanner()
        assert scanner is not None

    def test_scanner_initialization_with_config(self):
        """Scanner should accept a custom Config instance."""
        cfg = Config()
        scanner = Scanner(config=cfg)
        # We don't assume too much about internals, just that it stores config.
        assert hasattr(scanner, "config")
        assert scanner.config is cfg

    @pytest.fixture
    def simple_project(self, tmp_path: Path) -> Path:
        """
        Create a tiny project with a simple 'vulnerability'-like snippet.
        Adjust this later if your Semgrep rules need specific patterns.
        """
        vulnerable_file = tmp_path / "app.py"
        # Classic unsafe pattern most Semgrep rules know: eval(input())
        vulnerable_file.write_text("user = input()\nresult = eval(user)\n")
        return tmp_path

    def test_basic_scan_returns_result(self, simple_project: Path):
        """Scanner.scan should return a result object with findings list."""
        scanner = Scanner()

        result = scanner.scan(target=simple_project)

        # We don't know the exact type, but we expect some attributes.
        assert result is not None
        assert hasattr(result, "findings")
        assert isinstance(result.findings, list)
        assert hasattr(result, "total_findings")
        assert isinstance(result.total_findings, int)

    def test_scan_respects_severity_filter(self, simple_project: Path):
        """
        If Scanner supports severity filtering, ensure it doesn't crash.
        We only assert that it runs and returns a result object.
        """
        scanner = Scanner()

        result = scanner.scan(
            target=simple_project,
            severity_filter=["HIGH", "CRITICAL"],
        )

        assert result is not None
        assert hasattr(result, "findings")
        # If no findings, that's still okay; this test mainly checks that
        # severity_filter argument is accepted and processed without error.
