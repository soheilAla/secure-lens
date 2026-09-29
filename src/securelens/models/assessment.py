from pydantic import BaseModel

from securelens.models.enums import RiskCategory, Severity


class Assessment(BaseModel):
    severity: Severity
    severity_score: float
    severity_probabilities: dict[str, float]
    severity_confidence: float

    category: RiskCategory
    category_probabilities: dict[str, float]
    category_confidence: float

    exploitable: bool
    exploitable_probability: float

    model_id: str = "jev-latest"
