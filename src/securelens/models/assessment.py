from pydantic import BaseModel, Field

from securelens.models.enums import RiskCategory, Severity


class Assessment(BaseModel):
    severity: Severity
    severity_score: float
    severity_probabilities: dict[str, float] = Field(default_factory=dict)
    severity_confidence: float

    category: RiskCategory
    category_probabilities: dict[str, float] = Field(default_factory=dict)
    category_confidence: float = 1.0

    exploitable: bool
    exploitable_probability: float

    fallback: bool = False
    reason: str = ""
    recommendation: str = ""

    source: str = "jev"
    model_id: str = "jev-latest"
