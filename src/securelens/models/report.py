from datetime import UTC, datetime

from pydantic import BaseModel, Field

from securelens.models.finding import Finding


class Report(BaseModel):
    target: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[Finding] = Field(default_factory=list)
