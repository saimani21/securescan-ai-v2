import pytest
from pathlib import Path

from securescan.core.scanner import Scanner
from securescan.utils.config import Config


def make_temp_project(tmp_path):
    f = tmp_path / "bad.py"
    f.write_text("eval(input())")
    return tmp_path


def test_scan_with_secrets_disabled(tmp_path):
    project = make_temp_project(tmp_path)
    cfg = Config()
    scanner = Scanner(config=cfg)

    result = scanner.scan(
        target=project,
        enable_secrets=False,   # NEW BRANCH
        enable_llm=False,
        enable_cve_enrichment=False,
    )

    assert result.success is True
    # there might still be Semgrep findings, but no secret-derived ones
    for f in result.findings:
        assert f.get("source") != "secrets"


def test_scan_invalid_target():
    scanner = Scanner()
    result = scanner.scan(
        target=Path("this_does_not_exist"),
        enable_llm=False,
        enable_cve_enrichment=False,
    )

    assert result.success is False
    assert "Target does not exist" in " ".join(result.errors)
