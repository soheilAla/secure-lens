import re
import tomllib
from importlib import resources

from pydantic import BaseModel

from securelens.masking import mask_secret
from securelens.models.enums import RiskCategory, Severity
from securelens.models.evidence import Evidence
from securelens.models.finding import Finding
from securelens.models.repository import RepositorySnapshot


class SecretPattern(BaseModel):
    id: str
    provider: str
    name: str
    regex: str
    severity: Severity = Severity.HIGH
    category: RiskCategory = RiskCategory.HARDCODED_CREDENTIAL
    samples: dict[str, list[str]] = {}


class SecretAnalyzer:
    name = "secret-scanner"

    def __init__(self):
        raw = resources.files("securelens.analyzers").joinpath(
            "data/secret_patterns.toml"
        )

        entries = [
            SecretPattern.model_validate(e)
            for e in tomllib.loads(raw.read_text("utf-8"))["rules"]
        ]

        self._compiled = [(e, re.compile(e.regex)) for e in entries]

    def scan_line(self, line: str) -> list[SecretPattern]:
        return [entry for entry, rx in self._compiled if rx.search(line)]

    def analyze(self, snapshot: RepositorySnapshot) -> list[Finding]:
        findings: list[Finding] = []
        for file in snapshot.collected_files:
            for line_number, line in enumerate(file.content.splitlines(), start=1):
                for entry, rx in self._compiled:
                    match = rx.search(line)
                    if match:
                        findings.append(
                            self._finding(
                                entry, file.path, line_number, line, match.span()
                            )
                        )
        return findings

    def _finding(
        self,
        entry: SecretPattern,
        path: str,
        line_number: int,
        line: str,
        span: tuple[int, int],
    ) -> Finding:
        masked = (
            line[: span[0]] + mask_secret(line[span[0] : span[1]]) + line[span[1] :]
        )

        return Finding(
            category=entry.category,
            title=f"Potential secret: {entry.name}",
            description=(
                f"A value matching the {entry.id!r} format ({entry.provider}) appears "
                f"in {path} at line {line_number}. Treat it as exposed and rotate it."
            ),
            severity=entry.severity,
            file=path,
            line_start=line_number,
            line_end=line_number,
            evidence=[
                Evidence(
                    file=path,
                    content=masked.strip(),
                    line_start=line_number,
                    line_end=line_number,
                )
            ],
        )
