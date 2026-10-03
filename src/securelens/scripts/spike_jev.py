from securelens.assess.jev import JevAssessor
from securelens.core.config import get_settings
from securelens.models.enums import RiskCategory, Severity
from securelens.models.finding import Finding

settings = get_settings()

finding = Finding(
    category=RiskCategory.CONFIGURATION,
    title="Debug mode is enabled",
    description=(
        "DEBUG=true is set in .env.production. "
        "Debug mode in production can expose stack traces and internal details."
    ),
    severity=Severity.MEDIUM,
    file=".env.production",
    line_start=1,
    line_end=1,
)

assessor = JevAssessor(
    model=settings.model,
    api_key=settings.api_key or None,
    base_url=settings.base_url or None,
)

assessment = assessor.assess(finding)

print(assessment.model_dump_json(indent=2))
