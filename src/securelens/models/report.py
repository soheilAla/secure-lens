from datetime import UTC, datetime

from pydantic import BaseModel, Field

from securelens.models.assessment import Assessment, RiskCategory
from securelens.models.finding import Finding, Severity


class AssessedFinding(BaseModel):
    finding: Finding
    assessment: Assessment | None = None

    @property
    def final_severity(self) -> Severity:
        if self.assessment is not None:
            return self.assessment.severity
        return self.finding.severity

    @property
    def final_category(self) -> RiskCategory:
        if self.assessment is not None:
            return self.assessment.category
        return self.finding.category


class Report(BaseModel):
    target: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    files_collected: int = 0
    files_skipped: int = 0
    assessed_findings: list[AssessedFinding] = Field(default_factory=list)
