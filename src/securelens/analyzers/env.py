from pathlib import PurePath

from securelens.models.enums import RiskCategory, Severity
from securelens.models.evidence import Evidence
from securelens.models.finding import Finding
from securelens.models.repository import RepositorySnapshot

ENV_FILENAMES = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.test",
    ".env.production",
    ".env.staging",
}

DEBUG_TRUE_VALUES = {"1", "true", "yes", "on"}


class EnvAnalyzer:
    def analyze(self, snapshot: RepositorySnapshot) -> list[Finding]:
        findings: list[Finding] = []

        for file in snapshot.collected_files:
            if PurePath(file.path).name not in ENV_FILENAMES:
                continue

            findings.extend(self._analyze_file(file.path, file.content))

        return findings

    def _analyze_file(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []

        for line_number, line in enumerate(content.splitlines(), start=1):
            parsed = self._parse_assignment(line)

            if parsed is None:
                continue

            key, value = parsed

            if key == "DEBUG" and value.lower() in DEBUG_TRUE_VALUES:
                findings.append(
                    Finding(
                        category=RiskCategory.CONFIGURATION,
                        title="Debug mode is enabled",
                        description=(
                            f"DEBUG={value} is set in {path} (line {line_number}). "
                            "Debug mode in production can expose stack traces and internal details."
                        ),
                        severity=Severity.MEDIUM,
                        file=path,
                        line_start=line_number,
                        line_end=line_number,
                        evidence=[
                            Evidence(
                                file=path,
                                content=line.strip(),
                                line_start=line_number,
                                line_end=line_number,
                            )
                        ],
                    )
                )

        return findings

    @staticmethod
    def _parse_assignment(line: str) -> tuple[str, str] | None:
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            return None

        if line.startswith("export "):
            line = line.removeprefix("export").lstrip()

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if not key:
            return None

        if (
            len(value) >= 2
            and value.startswith(("'", '"'))
            and value.endswith(value[0])
        ):
            value = value[1:-1]

        return key, value
