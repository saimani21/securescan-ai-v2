# tests/unit/test_secrets_detector.py

from pathlib import Path
from securescan.core.secrets_detector import SecretsDetector


def _write(tmp_path, name: str, content: str) -> Path:
    """Helper to write a temporary file."""
    file_path = tmp_path / name
    file_path.write_text(content)
    return file_path


def _has_finding_for_file(findings, expected_path: Path) -> bool:
    """
    Try to match a finding to a file path without assuming the exact schema.

    Works whether findings are dicts or small objects/dataclasses.
    """
    expected_str = str(expected_path)

    for f in findings:
        candidate = None

        # Dict-style finding
        if isinstance(f, dict):
            for key in ("file", "file_path", "path", "filename"):
                value = f.get(key)
                if value:
                    candidate = str(value)
                    break
        else:
            # Object-style finding
            for attr in ("file", "file_path", "path", "filename"):
                if hasattr(f, attr):
                    value = getattr(f, attr)
                    if value:
                        candidate = str(value)
                        break

        if candidate and candidate == expected_str:
            return True

    return False


def test_detects_aws_access_key(tmp_path):
    """SecretsDetector should flag an AWS-style access key."""
    content = "AWS_KEY = 'AKIA1234567890ABCD12'"
    file_path = _write(tmp_path, "aws_test.py", content)

    detector = SecretsDetector()
    findings = detector.scan_directory(tmp_path)

    # At least one secret should be found
    assert findings, "Expected at least one secret finding for AWS key"
    # And at least one finding should point to our file
    assert _has_finding_for_file(findings, file_path)


def test_detects_openai_key(tmp_path):
    """SecretsDetector should flag an OpenAI-style API key."""
    content = "OPENAI_API_KEY = 'sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
    file_path = _write(tmp_path, "openai_test.py", content)

    detector = SecretsDetector()
    findings = detector.scan_directory(tmp_path)

    assert findings, "Expected at least one secret finding for OpenAI key"
    assert _has_finding_for_file(findings, file_path)
