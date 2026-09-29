from collections.abc import Sequence
from typing import Any

from securelens.collectors.repository import RepositoryCollector
from securelens.models.report import AssessedFinding, Report


class ScanRunner:
    def __init__(self, collector: RepositoryCollector, analyzers: Sequence[Any]):
        self.collector = collector
        self.analyzers = analyzers

    def run(self, target: str) -> Report:
        snapshot = self.collector.collect(target)

        assessed: list[AssessedFinding] = []

        for analyzer in self.analyzers:
            for finding in analyzer.analyze(snapshot):
                assessed.append(AssessedFinding(finding=finding))

        return Report(
            target=snapshot.root,
            files_scanned=len(snapshot.collected_files),
            files_skipped=len(snapshot.skipped_files),
            assessed_findings=assessed,
        )
