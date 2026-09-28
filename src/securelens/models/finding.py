from enum import StrEnum

from pydantic import BaseModel, Field

from securelens.models.evidence import Evidence


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingSource(StrEnum):
    RULE = "rule"
    JEV = "jev"


class Finding(BaseModel):
    category: str
    title: str
    description: str
    severity: Severity
    source: FindingSource
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    recommendation: str | None = None
