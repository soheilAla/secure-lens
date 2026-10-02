import pytest

from securelens.analyzers.env import EnvAnalyzer
from securelens.models.repository import FileTarget, RepositorySnapshot


def findings_for(content, path=".env"):
    snapshot = RepositorySnapshot(
        root="/fake", collected_files=[FileTarget(path=path, content=content)]
    )
    return EnvAnalyzer().analyze(snapshot)


def test_debug_true_variants():
    for value in ("true", "1", "yes", "on", '"true"'):
        findings = findings_for(f"DEBUG={value}\n")
        assert len(findings) == 1
        assert findings[0].severity.value == "medium"
        assert findings[0].line_start == 1


def test_debug_false_and_zero_ignored():
    assert findings_for("DEBUG=false\nDEBUG=0\n") == []


def test_credential_severity_grades():
    cases = [
        ("kX9$mQ2#vL7pZ4nRtW8!", "high"),
        ("Password123!", "medium"),
        ("aaaaaaaaaaaaaaaaaaaa", "low"),
    ]
    for line, expected in cases:
        findings = findings_for(f"DB_PASSWORD={line}\n")
        assert len(findings) == 1
        assert findings[0].severity.value == expected
        assert findings[0].category.value == "hardcoded_credential"


def test_credential_evidence_is_masked():
    findings = findings_for("DB_PASSWORD=Sup3rS3cret!X9\n")
    evidence = findings[0].evidence[0].content

    assert "Sup3rS3cret!X9" not in evidence
    assert evidence.startswith("DB_PASSWORD=")
    assert "***" in evidence


@pytest.mark.parametrize(
    "line",
    [
        "SECRET=${DB_PASS}\n",
        "SECRET=<your-secret-here>\n",
        "SMTP_TOKEN=\n",
        "API_KEY=abc\n",
        "FOO=kX9$mQ2#vL7pZ4nRtW8!\n",
    ],
)
def test_non_credentials_are_skipped(line):
    assert findings_for(line) == []


def test_export_prefix_and_quotes():
    assert len(findings_for('export DEBUG = "true"\n')) == 1


def test_comments_and_blanks_ignored():
    assert findings_for("# DEBUG=true\n\n   \n") == []


def test_line_numbers():
    findings = findings_for("A=1\nB=2\nDEBUG=true\n")

    assert findings[0].line_start == 3
    assert findings[0].line_end == 3


def test_only_env_files_are_scanned():
    assert findings_for("DEBUG=true\n", path="app.py") == []
