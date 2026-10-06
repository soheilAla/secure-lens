from __future__ import annotations

from pathlib import PurePath
from typing import Any

from typesafe_sdk import Noul, Question, Score, TypeSafeClient

from securelens.models.assessment import Assessment
from securelens.models.enums import RiskCategory, Severity
from securelens.models.finding import Finding

SEVERITY_LEVELS: dict[Severity, int] = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class JevAssessor:
    name = "jev"

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self._model = model
        if base_url:
            base_url = base_url.rstrip("/")
            for suffix in ("/v1/systemone", "/v1/decisions", "/v1", "/systemone"):
                if base_url.endswith(suffix):
                    base_url = base_url[: -len(suffix)].rstrip("/")
        self._client = TypeSafeClient(
            model=model,
            api_key=api_key or None,
            base_url=base_url or None,
        )

    def assess(self, finding: Finding) -> Assessment:
        try:
            state = self._build_state(finding)
            questions = self._build_questions(finding)
            response = self._client.system_one(
                state=state,
                questions=questions,
            )
        except Exception as err:
            return self._fallback_assessment(
                finding, f"Assessment request failed: {err}"
            )

        if not self._is_valid_response(response):
            return self._fallback_assessment(
                finding, "Invalid response payload from model."
            )

        severity_answer = response.scores["severity"]
        exploitable_answer = response.nouls["exploitable"]
        conf = severity_answer.confidence

        if conf < 0.40:
            return self._fallback_assessment(
                finding,
                (
                    f"Low model confidence ({conf:.2f} < 0.40); "
                    f"preserved preliminary severity."
                ),
            )

        candidate_severity = self._map_severity(severity_answer.score)
        is_upgrade = SEVERITY_LEVELS.get(candidate_severity, 0) > SEVERITY_LEVELS.get(
            finding.severity, 0
        )

        final_severity = (
            finding.severity if (is_upgrade and conf < 0.70) else candidate_severity
        )
        is_exploitable = exploitable_answer.noul >= 0.5

        reason, recommendation = self._generate_verdict(
            finding=finding,
            final_severity=final_severity,
            exploitable=is_exploitable,
        )

        probabilities = {
            str(severity_answer.legend.get(k, k)): prob
            for k, prob in severity_answer.probabilities.items()
        }

        return Assessment(
            severity=final_severity,
            severity_score=severity_answer.score,
            severity_probabilities=probabilities,
            severity_confidence=conf,
            category=finding.category,
            category_probabilities={finding.category.value: 1.0},
            category_confidence=1.0,
            exploitable=is_exploitable,
            exploitable_probability=exploitable_answer.noul,
            reason=reason,
            recommendation=recommendation,
            source=self.name,
            model_id=self._model,
        )

    @staticmethod
    def _build_state(finding: Finding) -> dict[str, Any]:
        target_file = finding.file or ""
        is_test = (
            PurePath(target_file).parts[:1] == ("tests",) if target_file else False
        )
        return {
            "file": target_file,
            "is_test": is_test,
            "evidence": [
                {
                    "line": ev.line_start or 0,
                    "code": ev.content,
                    "context": ev.context or "",
                }
                for ev in finding.evidence
            ],
        }

    def _build_questions(self, finding: Finding) -> dict[str, Question]:
        if finding.category == RiskCategory.HARDCODED_CREDENTIAL:
            return {
                "severity": Score(
                    instructions=(
                        "Assess credential severity based on secret sensitivity, "
                        "provider, and whether file is in tests vs production."
                    ),
                    criteria=[
                        "informational",
                        "low",
                        "medium",
                        "high",
                        "critical",
                    ],
                ),
                "exploitable": Noul(
                    instructions=(
                        "Is this credential functional and exploitable in an "
                        "active environment rather than a mock or test fixture?"
                    ),
                    criteria={
                        "true": (
                            "Functional credential in deployable code or "
                            "production file."
                        ),
                        "false": (
                            "Test fixture, documentation sample, or mock placeholder."
                        ),
                    },
                ),
            }

        if finding.category == RiskCategory.DOCKER:
            return {
                "severity": Score(
                    instructions=(
                        "Assess container severity based on privilege escalation, "
                        "attack surface, and deployment risk."
                    ),
                    criteria=[
                        "informational",
                        "low",
                        "medium",
                        "high",
                        "critical",
                    ],
                ),
                "exploitable": Noul(
                    instructions=(
                        "Does this container instruction create a direct runtime "
                        "attack surface rather than build optimization?"
                    ),
                    criteria={
                        "true": (
                            "Direct runtime attack surface or unverified execution."
                        ),
                        "false": (
                            "Build optimization, caching issue, or advisory metadata."
                        ),
                    },
                ),
            }

        if self._is_git_finding(finding):
            return {
                "severity": Score(
                    instructions=(
                        "Assess Git finding severity based on secret exposure, "
                        "arbitrary hook execution, or submodule injection risk."
                    ),
                    criteria=[
                        "informational",
                        "low",
                        "medium",
                        "high",
                        "critical",
                    ],
                ),
                "exploitable": Noul(
                    instructions=(
                        "Does this Git finding expose active secrets or execute "
                        "unverified code on git operations?"
                    ),
                    criteria={
                        "true": (
                            "Active tracked secret, command injection, or "
                            "malicious hook script."
                        ),
                        "false": (
                            "Advisory notice, missing gitignore, or "
                            "non-executable setting."
                        ),
                    },
                ),
            }

        return {
            "severity": Score(
                instructions=(
                    "Assess configuration severity based on exposure and "
                    "information leakage risk in deployment."
                ),
                criteria=[
                    "informational",
                    "low",
                    "medium",
                    "high",
                    "critical",
                ],
            ),
            "exploitable": Noul(
                instructions=(
                    "Does this setting expose internal application details "
                    "in a live deployment rather than local development?"
                ),
                criteria={
                    "true": "Exposes internal state or debug interfaces in deployment.",
                    "false": "Harmless local setting or non-production configuration.",
                },
            ),
        }

    @staticmethod
    def _is_valid_response(response: Any) -> bool:
        scores = getattr(response, "scores", None)
        nouls = getattr(response, "nouls", None)
        if not isinstance(scores, dict) or not isinstance(nouls, dict):
            return False
        if "severity" not in scores or "exploitable" not in nouls:
            return False
        sev = scores["severity"]
        exp = nouls["exploitable"]
        if getattr(sev, "score", None) is None or not isinstance(
            sev.score, (int, float)
        ):
            return False
        if getattr(exp, "noul", None) is None or not isinstance(exp.noul, (int, float)):
            return False
        return True

    def _fallback_assessment(self, finding: Finding, reason: str) -> Assessment:
        return Assessment(
            severity=finding.severity,
            severity_score=0.0,
            severity_probabilities={},
            severity_confidence=0.0,
            category=finding.category,
            category_probabilities={finding.category.value: 1.0},
            category_confidence=1.0,
            exploitable=False,
            exploitable_probability=0.0,
            fallback=True,
            reason=reason,
            recommendation="Manual review required.",
            source=self.name,
            model_id=self._model,
        )

    @staticmethod
    def _generate_verdict(
        finding: Finding,
        final_severity: Severity,
        exploitable: bool,
    ) -> tuple[str, str]:
        file_name = PurePath(finding.file).name if finding.file else "target"
        status = "Exploitable" if exploitable else "Non-exploitable"
        reason = f"{status}: {finding.title} in {file_name}."

        if not exploitable:
            recommendation = (
                f"Verify {finding.title.lower()}; non-exploitable in current context."
            )
        elif finding.category == RiskCategory.HARDCODED_CREDENTIAL:
            recommendation = (
                "Rotate credential and migrate to secrets manager or "
                "environment variable."
            )
        elif finding.category == RiskCategory.DOCKER:
            recommendation = f"Update Dockerfile to remediate {finding.title.lower()}."
        elif finding.category == RiskCategory.CONFIGURATION:
            if JevAssessor._is_git_finding(finding):
                title_lower = finding.title.lower()
                if "hook" in title_lower:
                    recommendation = "Remove untrusted command execution from Git hook."
                elif "submodule" in title_lower:
                    recommendation = "Sanitize submodule configuration in .gitmodules."
                elif "tracked" in title_lower or "gitignore" in title_lower:
                    recommendation = (
                        "Untrack sensitive file with 'git rm --cached' and "
                        "update .gitignore."
                    )
                else:
                    recommendation = (
                        f"Sanitize Git repository configuration: {finding.title}."
                    )
            else:
                recommendation = (
                    f"Update configuration to remediate {finding.title.lower()}."
                )
        else:
            recommendation = f"Remediate {finding.title.lower()}."

        return reason, recommendation

    @staticmethod
    def _is_git_finding(finding: Finding) -> bool:
        file = (finding.file or "").lower()
        return (
            file in (".gitignore", ".gitmodules", ".gitconfig", ".git/config")
            or file.startswith((".husky/", ".githooks/", "githooks/", ".git-hooks/"))
            or "git" in finding.title.lower()
            or "submodule" in finding.title.lower()
        )

    @staticmethod
    def _map_severity(score: float) -> Severity:
        if score >= 3.5:
            return Severity.CRITICAL
        if score >= 2.5:
            return Severity.HIGH
        if score >= 1.5:
            return Severity.MEDIUM
        if score >= 0.5:
            return Severity.LOW
        return Severity.INFORMATIONAL
