from collections.abc import Sequence

from securelens.analyzers.base import Analyzer
from securelens.analyzers.dockerfile import DockerfileAnalyzer
from securelens.analyzers.env import EnvAnalyzer
from securelens.analyzers.git import GitRepositoryAnalyzer
from securelens.analyzers.secrets import SecretAnalyzer
from securelens.assess.base import Assessor
from securelens.collectors.repository import RepositoryCollector
from securelens.models.assessment import Assessment
from securelens.models.report import AssessedFinding, Report


def default_analyzers() -> list[Analyzer]:
    return [
        EnvAnalyzer(),
        SecretAnalyzer(),
        DockerfileAnalyzer(),
        GitRepositoryAnalyzer(),
    ]


class ScanRunner:
    def __init__(
        self,
        collector: RepositoryCollector,
        analyzers: Sequence[Analyzer] | None = None,
        assessor: Assessor | None = None,
    ):
        self.collector = collector
        self.analyzers = analyzers if analyzers is not None else default_analyzers()
        self.assessor = assessor

    def run(self, target: str) -> Report:
        snapshot = self.collector.collect(target)

        assessed: list[AssessedFinding] = []

        for analyzer in self.analyzers:
            for finding in analyzer.analyze(snapshot):
                assessment = None
                if self.assessor is not None:
                    try:
                        assessment = self.assessor.assess(finding)
                    except Exception as err:
                        assessment = Assessment(
                            severity=finding.severity,
                            severity_score=0.0,
                            severity_probabilities={},
                            severity_confidence=0.0,
                            category=finding.category,
                            category_probabilities={},
                            category_confidence=0.0,
                            exploitable=False,
                            exploitable_probability=0.0,
                            fallback=True,
                            reason=f"Assessment failed: {err}",
                            recommendation="Manual review required.",
                            source=getattr(self.assessor, "name", "unknown"),
                        )
                assessed.append(AssessedFinding(finding=finding, assessment=assessment))

        return Report(
            target=snapshot.root,
            files_collected=len(snapshot.collected_files),
            files_skipped=len(snapshot.skipped_files),
            assessed_findings=assessed,
        )
