from typesafe_sdk import Choice

from securelens.assess.base import Assessor
from securelens.assess.jev import JevAssessor
from securelens.models.assessment import Assessment
from securelens.models.enums import RiskCategory, Severity


def test_assessment_defaults():
    assessment = Assessment(
        severity=Severity.HIGH,
        severity_score=0.75,
        severity_probabilities={"high": 0.75, "medium": 0.25},
        severity_confidence=0.9,
        category=RiskCategory.CONFIGURATION,
        category_probabilities={"configuration": 1.0},
        category_confidence=0.95,
        exploitable=True,
        exploitable_probability=0.8,
    )
    assert assessment.fallback is False
    assert assessment.reason == ""
    assert assessment.recommendation == ""
    assert assessment.source == "jev"
    assert assessment.model_id == "jev-latest"


def test_map_severity():
    assert JevAssessor._map_severity(3.8) == Severity.CRITICAL
    assert JevAssessor._map_severity(2.9) == Severity.HIGH
    assert JevAssessor._map_severity(1.9) == Severity.MEDIUM
    assert JevAssessor._map_severity(0.8) == Severity.LOW
    assert JevAssessor._map_severity(0.2) == Severity.INFORMATIONAL


def test_map_category():
    assert (
        JevAssessor._map_category("hardcoded_credential")
        == RiskCategory.HARDCODED_CREDENTIAL
    )
    assert JevAssessor._map_category("configuration") == RiskCategory.CONFIGURATION
    assert JevAssessor._map_category("docker") == RiskCategory.DOCKER
    assert JevAssessor._map_category("unknown") == RiskCategory.OTHER


def test_assessor_protocol():
    assessor = JevAssessor(model="test-model", api_key="test-key")
    assert isinstance(assessor, Assessor)
    assert assessor.name == "jev"


def test_secret_finding_questions():
    from securelens.models.finding import Finding

    assessor = JevAssessor(model="test-model", api_key="test-key")
    secret_finding = Finding(
        category=RiskCategory.HARDCODED_CREDENTIAL,
        title="Potential secret: Stripe API key",
        description="Stripe secret key in code",
        severity=Severity.HIGH,
        file="src/billing.py",
        line_start=10,
        line_end=10,
    )
    questions = assessor._build_questions(secret_finding)
    assert "severity" in questions
    assert "category" in questions
    assert "exploitable" in questions
    cat = questions["category"]
    assert isinstance(cat, Choice)
    assert "secret" in str(cat.instructions).lower()
    assert "hardcoded_credential" in (cat.criteria or {})


def test_docker_finding_questions():
    from securelens.models.finding import Finding

    assessor = JevAssessor(model="test-model", api_key="test-key")
    docker_finding = Finding(
        category=RiskCategory.DOCKER,
        title="Container runs as root user",
        description="Explicit USER root in Dockerfile",
        severity=Severity.HIGH,
        file="Dockerfile",
        line_start=3,
        line_end=3,
    )
    questions = assessor._build_questions(docker_finding)
    assert "severity" in questions
    assert "category" in questions
    assert "exploitable" in questions
    cat = questions["category"]
    assert isinstance(cat, Choice)
    assert "container" in str(cat.instructions).lower()
    assert "docker" in (cat.criteria or {})
