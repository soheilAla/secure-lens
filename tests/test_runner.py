from securelens.analyzers.base import Analyzer
from securelens.collectors.repository import RepositoryCollector
from securelens.core.runner import ScanRunner
from securelens.models.assessment import Assessment
from securelens.models.enums import RiskCategory, Severity
from securelens.models.finding import Finding
from securelens.models.repository import FileTarget, RepositorySnapshot


class DummyAnalyzer(Analyzer):
    name = "dummy"

    def analyze(self, snapshot: RepositorySnapshot) -> list[Finding]:
        return [
            Finding(
                category=RiskCategory.HARDCODED_CREDENTIAL,
                title="Potential secret: API key",
                description="Test secret finding",
                severity=Severity.HIGH,
                file="app.py",
                line_start=1,
                line_end=1,
            )
        ]


class FakeCollector(RepositoryCollector):
    def collect(self, root: str) -> RepositorySnapshot:
        return RepositorySnapshot(
            root=root,
            collected_files=[FileTarget(path="app.py", content="API_KEY=123\n")],
            skipped_files=[],
        )


class FakeAssessor:
    name = "fake-jev"

    def assess(self, finding: Finding) -> Assessment:
        return Assessment(
            severity=Severity.CRITICAL,
            severity_score=3.9,
            severity_probabilities={"critical": 0.95},
            severity_confidence=0.9,
            category=finding.category,
            category_probabilities={"hardcoded_credential": 1.0},
            category_confidence=0.95,
            exploitable=True,
            exploitable_probability=0.92,
            source="fake-jev",
        )


class FailingAssessor:
    name = "failing-jev"

    def assess(self, finding: Finding) -> Assessment:
        raise ConnectionError("Service unreachable")


def test_runner_without_assessor():
    runner = ScanRunner(
        collector=FakeCollector(),
        analyzers=[DummyAnalyzer()],
        assessor=None,
    )
    report = runner.run("/fake")
    assert len(report.assessed_findings) == 1
    assert report.assessed_findings[0].assessment is None
    assert report.assessed_findings[0].final_severity == Severity.HIGH


def test_runner_with_assessor():
    runner = ScanRunner(
        collector=FakeCollector(),
        analyzers=[DummyAnalyzer()],
        assessor=FakeAssessor(),
    )
    report = runner.run("/fake")
    assert len(report.assessed_findings) == 1
    item = report.assessed_findings[0]
    assert item.assessment is not None
    assert item.assessment.fallback is False
    assert item.final_severity == Severity.CRITICAL
    assert item.assessment.exploitable is True


def test_runner_with_failing_assessor_falls_back():
    runner = ScanRunner(
        collector=FakeCollector(),
        analyzers=[DummyAnalyzer()],
        assessor=FailingAssessor(),
    )
    report = runner.run("/fake")
    assert len(report.assessed_findings) == 1
    item = report.assessed_findings[0]
    assert item.assessment is not None
    assert item.assessment.fallback is True
    assert item.final_severity == Severity.HIGH
    assert "Service unreachable" in item.assessment.reason
