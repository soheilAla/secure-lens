from securelens.analyzers.dockerfile import DockerfileAnalyzer
from securelens.models.enums import RiskCategory, Severity
from securelens.models.repository import FileTarget, RepositorySnapshot


def findings_for(
    content: str, path: str = "Dockerfile", extra_files: list[str] | None = None
):
    files = [FileTarget(path=path, content=content)]
    if extra_files:
        for f in extra_files:
            files.append(FileTarget(path=f, content=""))
    snapshot = RepositorySnapshot(root="/fake", collected_files=files)
    return DockerfileAnalyzer().analyze(snapshot)


def test_user_and_base_image_rules():
    root_findings = findings_for("FROM python:3.14\nUSER root\n")
    assert len(root_findings) == 1
    assert root_findings[0].severity == Severity.HIGH
    assert root_findings[0].category == RiskCategory.DOCKER
    assert len(findings_for("FROM python:3.14\nUSER appuser\n")) == 0

    assert len(findings_for("FROM python:latest\n")) == 1
    assert len(findings_for("FROM python\n")) == 1

    safe_images = (
        "FROM python:3.14\n"
        "FROM python@sha256:"
        "7176cb4053be4112ef0d3bf192ef94df9f8b4d0bc88e0db43d41ab0a60ff94b3\n"
        "FROM scratch\n"
        "FROM golang:1.21 AS builder\n"
        "FROM builder\n"
    )
    assert len(findings_for(safe_images)) == 0


def test_instruction_security_rules():
    assert (
        len(
            findings_for(
                "FROM alpine:3.18\nADD https://example.com/file.tar.gz /tmp/\n"
            )
        )
        == 1
    )
    assert len(findings_for("FROM alpine:3.18\nADD file.tar.gz /tmp/\n")) == 0

    assert (
        len(findings_for("FROM alpine:3.18\nRUN curl -sSL https://get.sh | sh\n")) == 1
    )
    assert len(findings_for("FROM alpine:3.18\nRUN echo test | grep t\n")) == 0

    assert len(findings_for("FROM alpine:3.18\nEXPOSE 22 2375\n")) == 2
    assert len(findings_for("FROM alpine:3.18\nEXPOSE 80 443\n")) == 0

    bad_apt = "FROM debian:12\nRUN apt-get update && apt-get install curl\n"
    assert len(findings_for(bad_apt)) >= 2

    clean_apt = (
        "FROM debian:12\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends curl && "
        "rm -rf /var/lib/apt/lists/*\n"
    )
    assert len(findings_for(clean_apt)) == 0


def test_copy_context_rules():
    no_ignore = findings_for("FROM python:3.14\nCOPY . /app\n")
    assert len(no_ignore) == 1
    assert no_ignore[0].severity == Severity.LOW

    with_ignore = findings_for(
        "FROM python:3.14\nCOPY . /app\n", extra_files=[".dockerignore"]
    )
    assert len(with_ignore) == 1
    assert with_ignore[0].severity == Severity.INFORMATIONAL

    assert len(findings_for("FROM python:3.14\nCOPY requirements.txt /app/\n")) == 0


def test_parsing_and_file_filtering():
    multiline = (
        "FROM python:3.14\nRUN apt-get update && \\\n    apt-get install -y curl\n"
    )
    findings = findings_for(multiline)
    assert len(findings) == 1
    assert findings[0].line_start == 2
    assert findings[0].line_end == 3

    for path in ("Dockerfile", "Dockerfile.prod", "Containerfile"):
        assert len(findings_for("FROM python:3.14\nUSER root\n", path=path)) == 1

    assert len(findings_for("FROM python:3.14\nUSER root\n", path="dockerfile.py")) == 0
    assert len(findings_for("USER root\n", path="README.md")) == 0
