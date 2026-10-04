from typesafe_sdk import Choice, Noul, Question, Score, TypeSafeClient

from securelens.models.assessment import Assessment
from securelens.models.enums import RiskCategory, Severity
from securelens.models.finding import Finding


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

    # ponytail: single-finding assessment; add batch evaluation when repo scan scales.
    def assess(self, finding: Finding) -> Assessment:
        questions = self._build_questions(finding)
        response = self._client.system_one(
            state={
                "finding": finding.model_dump(mode="json"),
            },
            questions=questions,
        )

        severity = response.scores["severity"]
        category = response.choices["category"]
        exploitable = response.nouls["exploitable"]

        if finding.category == RiskCategory.HARDCODED_CREDENTIAL:
            reason = f"Credential pattern detected in {finding.file or 'codebase'}."
            recommendation = (
                "Revoke and rotate exposed credential immediately. "
                "Store secrets in environment variables or a secret vault."
            )
        else:
            reason = f"Security issue detected in {finding.file or 'codebase'}."
            recommendation = (
                "Review and remediate finding according to security policy."
            )

        return Assessment(
            severity=self._map_severity(severity.score),
            severity_score=severity.score,
            severity_probabilities={
                str(severity.legend.get(k, k)): prob
                for k, prob in severity.probabilities.items()
            },
            severity_confidence=severity.confidence,
            category=self._map_category(category.choice),
            category_probabilities=category.probabilities,
            category_confidence=category.confidence,
            exploitable=exploitable.noul >= 0.5,
            exploitable_probability=exploitable.noul,
            reason=reason,
            recommendation=recommendation,
            source="jev",
            model_id=self._model,
        )

    def _build_questions(self, finding: Finding) -> dict[str, Question]:
        if finding.category == RiskCategory.HARDCODED_CREDENTIAL:
            return {
                "severity": Score(
                    instructions=(
                        "Assess the severity of this exposed credential in context, "
                        "considering provider type, file location, and impact."
                    ),
                    criteria=[
                        "informational",
                        "low",
                        "medium",
                        "high",
                        "critical",
                    ],
                ),
                "category": Choice(
                    instructions="Classify the risk category of this secret finding.",
                    criteria={
                        "hardcoded_credential": (
                            "A secret, token, API key, password, or private key"
                            " is exposed."
                        ),
                        "configuration": (
                            "An insecure configuration or environment setting."
                        ),
                        "other": "Not a credential or fits another category.",
                    },
                ),
                "exploitable": Noul(
                    instructions=(
                        "Determine whether this exposed secret appears to be a real, "
                        "exploitable credential rather than a test dummy, mock, "
                        "example, or placeholder."
                    ),
                    criteria={
                        "true": (
                            "A real, valid credential format in non-test or"
                            " deployable code that could grant unauthorized access."
                        ),
                        "false": (
                            "A dummy token, synthetic fixture, documentation example,"
                            " or obvious placeholder."
                        ),
                    },
                ),
            }

        return {
            "severity": Score(
                instructions=(
                    "Assess the severity of this security finding in context."
                ),
                criteria=[
                    "informational",
                    "low",
                    "medium",
                    "high",
                    "critical",
                ],
            ),
            "category": Choice(
                instructions="Classify the primary risk category of this finding.",
                criteria={
                    "configuration": (
                        "An insecure application or environment configuration."
                    ),
                    "hardcoded_credential": (
                        "A secret, credential, or authentication material is exposed."
                    ),
                    "other": "The finding does not fit the listed categories.",
                },
            ),
            "exploitable": Noul(
                instructions=(
                    "Determine whether this finding is exploitable as-is "
                    "by an attacker with repository access."
                ),
                criteria={
                    "true": (
                        "The finding can be used as-is without additional conditions."
                    ),
                    "false": ("Exploitation requires additional conditions or access."),
                },
            ),
        }

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

    @staticmethod
    def _map_category(category: str) -> RiskCategory:
        if category == "hardcoded_credential":
            return RiskCategory.HARDCODED_CREDENTIAL

        if category == "configuration":
            return RiskCategory.CONFIGURATION

        return RiskCategory.OTHER
