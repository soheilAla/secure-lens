from typesafe_sdk import Choice, Noul, Score, TypeSafeClient

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

    def assess(self, finding: Finding) -> Assessment:
        response = self._client.system_one(
            state={
                "finding": finding.model_dump(mode="json"),
            },
            questions={
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
                            "A secret, credential, or authentication material"
                            " is exposed."
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
                            "The finding can be used as-is without"
                            " additional conditions."
                        ),
                        "false": (
                            "Exploitation requires additional conditions or access."
                        ),
                    },
                ),
            },
        )

        severity = response.scores["severity"]
        category = response.choices["category"]
        exploitable = response.nouls["exploitable"]

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
            source="jev",
            model_id=self._model,
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

    @staticmethod
    def _map_category(category: str) -> RiskCategory:
        if category == "hardcoded_credential":
            return RiskCategory.HARDCODED_CREDENTIAL

        if category == "configuration":
            return RiskCategory.CONFIGURATION

        return RiskCategory.OTHER
