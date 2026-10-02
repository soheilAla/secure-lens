import re
from pathlib import PurePath

from securelens.entropy import shannon_entropy
from securelens.masking import mask_secret
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
HIGH_ENTROPY = 3.5
MEDIUM_ENTROPY = 2.5

SECRET_KEY_PATTERN = re.compile(
    r"(password|passwd|pwd|secret|token|api_key|apikey|private_key|access_key)",
    re.IGNORECASE,
)

TEMPLATE_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (r"\$\{[^}]+\}", r"<[^<>]+>", r"\{\{?[^{}]+\}?\}")
)


class EnvAnalyzer:
    name = "env-rules"

    def analyze(self, snapshot: RepositorySnapshot) -> list[Finding]:
        findings: list[Finding] = []

        for file in snapshot.collected_files:
            if PurePath(file.path).name not in ENV_FILENAMES:
                continue

            for line_number, line in enumerate(file.content.splitlines(), start=1):
                parsed = self._parse_assignment(line)

                if parsed is None:
                    continue

                key, value = parsed

                if key.lower() == "debug" and value.lower() in DEBUG_TRUE_VALUES:
                    findings.append(
                        self._debug_finding(file.path, line_number, key, value)
                    )

                if (
                    SECRET_KEY_PATTERN.search(key)
                    and len(value) >= 8
                    and not self._is_template_value(value)
                ):
                    findings.append(
                        self._secret_finding(file.path, line_number, key, value)
                    )

        return findings

    def _debug_finding(
        self, path: str, line_number: int, key: str, value: str
    ) -> Finding:
        return Finding(
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
                    content=f"{key}={value}",
                    line_start=line_number,
                    line_end=line_number,
                )
            ],
        )

    def _secret_finding(
        self, path: str, line_number: int, key: str, value: str
    ) -> Finding:
        return Finding(
            category=RiskCategory.HARDCODED_CREDENTIAL,
            title=f"Potential hardcoded secret: {key}",
            description=(
                f"{key} in {path} (line {line_number}) "
                "looks like a hardcoded credential. "
                "If this file is committed or shared, the value must be rotated."
            ),
            severity=self._credential_severity(value),
            file=path,
            line_start=line_number,
            line_end=line_number,
            evidence=[
                Evidence(
                    file=path,
                    content=f"{key}={mask_secret(value)}",
                    line_start=line_number,
                    line_end=line_number,
                )
            ],
        )

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

    @staticmethod
    def _is_template_value(value: str) -> bool:
        v = value.strip()
        return any(pattern.fullmatch(v) for pattern in TEMPLATE_PATTERNS)

    @staticmethod
    def _credential_severity(value: str) -> Severity:
        if len(value) >= 16 and shannon_entropy(value) >= HIGH_ENTROPY:
            return Severity.HIGH

        if len(value) >= 8 and shannon_entropy(value) >= MEDIUM_ENTROPY:
            return Severity.MEDIUM

        return Severity.LOW
