# tests/unit/test_semgrep_runner.py

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from securescan.core.semgrep_runner import SemgrepRunner
from securescan.utils.exceptions import ScanError


def _fake_semgrep_output():
    """
    Minimal Semgrep JSON output that matches the usual structure:

    {
      "results": [
        {
          "check_id": "test.rule",
          "path": "a.py",
          "start": {"line": 1, "col": 1},
          "end": {"line": 1, "col": 10},
          "extra": {"message": "...", "severity": "ERROR"}
        }
      ]
    }
    """
    return {
        "results": [
            {
                "check_id": "test.rule",
                "path": "a.py",
                "start": {"line": 1, "col": 1},
                "end": {"line": 1, "col": 10},
                "extra": {
                    "message": "Test message from Semgrep",
                    "severity": "ERROR",
                    "metadata": {"cwe": "CWE-79"},
                },
            }
        ]
    }


@patch("securescan.core.semgrep_runner.subprocess.run")
def test_semgrep_runner_parses_basic_result(mock_run, tmp_path):
    """
    When Semgrep returns a successful JSON output, SemgrepRunner.scan(...)
    should return at least one finding.
    """
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = json.dumps(_fake_semgrep_output())
    mock_proc.stderr = ""
    mock_run.return_value = mock_proc

    # Ensure there is at least one file so the runner doesn't error on empty target
    (tmp_path / "a.py").write_text("print('hi')")

    runner = SemgrepRunner()
    findings = runner.scan(tmp_path)

    # We don't assume exact schema; we just check we parsed at least one finding.
    assert findings, "Expected at least one Semgrep finding to be returned"


@patch("securescan.core.semgrep_runner.subprocess.run")
def test_semgrep_runner_raises_on_non_zero_exit(mock_run, tmp_path):
    """
    If Semgrep exits with a non-zero code (2 = error), SemgrepRunner.scan(...)
    should raise ScanError.
    """
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = ""
    mock_proc.stderr = "some error"
    mock_run.return_value = mock_proc

    (tmp_path / "a.py").write_text("print('hi')")

    runner = SemgrepRunner()

    with pytest.raises(ScanError):
        runner.scan(tmp_path)
