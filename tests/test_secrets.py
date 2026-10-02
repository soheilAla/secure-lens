import re

import pytest

from securelens.analyzers.secrets import SecretAnalyzer
from securelens.models.repository import FileTarget, RepositorySnapshot


@pytest.fixture(scope="module")
def analyzer() -> SecretAnalyzer:
    return SecretAnalyzer()


def matching_rules(analyzer: SecretAnalyzer, line: str) -> list[str]:
    return [p.id for p in analyzer.patterns if re.search(p.regex, line)]


def test_every_positive_sample_is_detected(analyzer: SecretAnalyzer):
    for pattern in analyzer.patterns:
        for sample in pattern.samples["positive"]:
            assert pattern.id in matching_rules(analyzer, sample), (
                f"{pattern.id} missed its own positive sample: {sample!r}"
            )


def test_no_negative_sample_is_a_false_positive(analyzer: SecretAnalyzer):
    for pattern in analyzer.patterns:
        for sample in pattern.samples["negative"]:
            assert pattern.id not in matching_rules(analyzer, sample), (
                f"{pattern.id} flags its own negative sample: {sample!r}"
            )


def test_findings_never_carry_the_raw_token(analyzer: SecretAnalyzer):
    token = "ghp_a1B2c3D4e5a1B2c3D4e5a1B2c3D4e5a1B2c3"
    snapshot = RepositorySnapshot(
        root="/fake",
        collected_files=[FileTarget(path="config.txt", content=f"GITHUB={token}\n")],
    )
    findings = analyzer.analyze(snapshot)

    assert findings, "expected a github-token finding"
    rendered = "".join(e.content for f in findings for e in f.evidence)
    assert token not in rendered
    assert "ghp_" in rendered
