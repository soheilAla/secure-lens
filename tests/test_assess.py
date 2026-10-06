from typesafe_sdk import Noul, Score

from securelens.assess.base import Assessor
from securelens.assess.jev import JevAssessor
from securelens.models.assessment import Assessment
from securelens.models.enums import RiskCategory, Severity
from securelens.models.evidence import Evidence
from securelens.models.finding import Finding


class MockScoreAnswer:
    def __init__(self, score: float | None, confidence: float = 0.9):
        self.score = score
        self.confidence = confidence
        self.legend = {0: "info", 1: "low", 2: "med", 3: "high", 4: "crit"}
        self.probabilities = {3: 0.9}


class MockNoulAnswer:
    def __init__(self, noul: float):
        self.noul = noul


class MockResponse:
    def __init__(
        self, score: float | None = 2.8, conf: float = 0.85, noul: float = 0.8
    ):
        self.scores = (
            {"severity": MockScoreAnswer(score, conf)} if score is not None else {}
        )
        self.nouls = {"exploitable": MockNoulAnswer(noul)}


class FakeClient:
    def __init__(self, response: MockResponse | Exception):
        self._response = response

    def system_one(self, *args, **kwargs) -> MockResponse:
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def test_assessment_model_and_protocol():
    assessment = Assessment(
        severity=Severity.HIGH,
        severity_score=0.75,
        severity_confidence=0.9,
        category=RiskCategory.CONFIGURATION,
        exploitable=True,
        exploitable_probability=0.8,
    )
    assert assessment.fallback is False
    assert assessment.category == RiskCategory.CONFIGURATION

    assessor = JevAssessor(model="test-model", api_key="test-key")
    assert isinstance(assessor, Assessor)
    assert JevAssessor._map_severity(3.8) == Severity.CRITICAL
    assert JevAssessor._map_severity(0.8) == Severity.LOW


def test_state_and_questions_are_minimal():
    assessor = JevAssessor(model="test-model", api_key="test-key")
    finding = Finding(
        category=RiskCategory.HARDCODED_CREDENTIAL,
        title="Stripe key",
        description="Found key",
        severity=Severity.HIGH,
        file="tests/test_auth.py",
        evidence=[
            Evidence(file="tests/test_auth.py", content="sk_live_x", line_start=1)
        ],
    )

    state = JevAssessor._build_state(finding)
    assert state == {
        "file": "tests/test_auth.py",
        "is_test": True,
        "evidence": [{"line": 1, "code": "sk_live_x", "context": ""}],
    }

    questions = assessor._build_questions(finding)
    assert set(questions.keys()) == {"severity", "exploitable"}
    assert isinstance(questions["severity"], Score)
    assert isinstance(questions["exploitable"], Noul)


def test_assess_success_and_verdict_generation():
    assessor = JevAssessor(model="test-model", api_key="test-key")
    assessor._client = FakeClient(MockResponse(score=2.8, conf=0.85, noul=0.8))  # type: ignore[assignment]

    finding = Finding(
        category=RiskCategory.DOCKER,
        title="Container runs as root user",
        description="USER root in Dockerfile",
        severity=Severity.HIGH,
        file="Dockerfile",
    )

    assessment = assessor.assess(finding)
    assert assessment.fallback is False
    assert assessment.severity == Severity.HIGH
    assert assessment.category == RiskCategory.DOCKER
    assert assessment.exploitable is True
    assert (
        "Exploitable: Container runs as root user in Dockerfile." in assessment.reason
    )
    assert "Update Dockerfile" in assessment.recommendation


def test_conservative_upgrade_and_fallbacks():
    assessor = JevAssessor(model="test-model", api_key="test-key")
    finding = Finding(
        category=RiskCategory.CONFIGURATION,
        title="Debug mode",
        description="DEBUG=true",
        severity=Severity.LOW,
        file=".env",
    )

    assessor._client = FakeClient(MockResponse(score=3.8, conf=0.60, noul=0.8))  # type: ignore[assignment]
    assert assessor.assess(finding).severity == Severity.LOW

    assessor._client = FakeClient(MockResponse(score=2.8, conf=0.85, noul=0.8))  # type: ignore[assignment]
    assert assessor.assess(finding).severity == Severity.HIGH

    assessor._client = FakeClient(MockResponse(score=2.8, conf=0.25, noul=0.8))  # type: ignore[assignment]
    res_low = assessor.assess(finding)
    assert res_low.fallback is True
    assert res_low.severity == Severity.LOW

    assessor._client = FakeClient(ConnectionError("Unreachable"))  # type: ignore[assignment]
    res_err = assessor.assess(finding)
    assert res_err.fallback is True
    assert "Assessment request failed" in res_err.reason
