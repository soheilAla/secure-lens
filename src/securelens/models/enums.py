from enum import StrEnum


class RiskCategory(StrEnum):
    HARDCODED_CREDENTIAL = "hardcoded_credential"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    CODE_PATTERN = "code_pattern"
    DOCKER = "docker"
    OTHER = "other"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
