from pydantic import BaseModel, Field

from securelens.models.enums import RiskCategory, Severity
from securelens.models.evidence import Evidence


class Finding(BaseModel):
    category: RiskCategory
    title: str
    description: str
    severity: Severity

    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None

    evidence: list[Evidence] = Field(default_factory=list)
