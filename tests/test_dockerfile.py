import pytest

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


def test_user_root_detected():
    cases = ["USER root", "USER 0", "USER root:root", "USER 0:0", "USER  root "]
    for case in cases:
        findings = findings_for(f"FROM python:3.11\n{case}\n")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == RiskCategory.DOCKER
        assert "root user" in findings[0].title.lower()
        assert findings[0].line_start == 2
        assert findings[0].line_end == 2


def test_safe_user_ignored():
    content = "FROM python:3.11\nUSER appuser\nUSER 10001:10001\n"
    findings = findings_for(content)
    user_findings = [f for f in findings if "root" in f.title.lower()]
    assert len(user_findings) == 0


def test_unpinned_base_image():
    findings = findings_for("FROM python:latest\n")
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "latest" in findings[0].title.lower()

    findings_no_tag = findings_for("FROM python\n")
    assert len(findings_no_tag) == 1
    assert findings_no_tag[0].severity == Severity.MEDIUM
    assert "missing version tag" in findings_no_tag[0].title.lower()


def test_pinned_base_image_ignored():
    cases = [
        "FROM python:3.11\n",
        "FROM python:3.11-slim\n",
        (
            "FROM python@sha256:"
            "7176cb4053be4112ef0d3bf192ef94df9f8b4d0bc88e0db43d41ab0a60ff94b3\n"
        ),
        "FROM scratch\n",
        "FROM ${BASE_IMAGE}\n",
    ]
    for case in cases:
        findings = findings_for(case)
        assert len(findings) == 0, f"False positive on: {case}"


def test_multistage_alias_ignored():
    content = (
        "FROM golang:1.21 AS builder\n"
        "RUN echo building\n"
        "FROM builder AS test\n"
        "FROM test\n"
    )
    findings = findings_for(content)
    base_image_findings = [f for f in findings if "base image" in f.title.lower()]
    assert len(base_image_findings) == 0


def test_remote_add_detected():
    findings = findings_for(
        "FROM alpine:3.18\nADD https://example.com/archive.tar.gz /tmp/\n"
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "remote url" in findings[0].title.lower()
    assert findings[0].line_start == 2


def test_local_add_ignored():
    findings = findings_for("FROM alpine:3.18\nADD archive.tar.gz /tmp/\n")
    add_findings = [f for f in findings if "remote url" in f.title.lower()]
    assert len(add_findings) == 0


def test_pipe_to_shell_detected():
    cases = [
        "RUN curl -fsSL https://get.docker.com | sh",
        "RUN wget -qO- https://example.com/install.sh | bash",
        "RUN curl -sL https://deb.nodesource.com/setup_18.x | /bin/sh",
        "RUN curl -s https://example.com/setup | dash",
    ]
    for case in cases:
        findings = findings_for(f"FROM alpine:3.18\n{case}\n")
        pipe_findings = [f for f in findings if "pipe to shell" in f.title.lower()]
        assert len(pipe_findings) == 1
        assert pipe_findings[0].severity == Severity.HIGH


def test_pipe_to_non_shell_ignored():
    findings = findings_for("FROM alpine:3.18\nRUN echo 'test' | grep 't'\n")
    pipe_findings = [f for f in findings if "pipe to shell" in f.title.lower()]
    assert len(pipe_findings) == 0


def test_risky_expose_ports():
    cases = [
        ("EXPOSE 22", Severity.HIGH, "SSH"),
        ("EXPOSE 22/tcp", Severity.HIGH, "SSH"),
        ("EXPOSE 2375", Severity.CRITICAL, "Docker daemon"),
        ("EXPOSE 2376", Severity.HIGH, "Docker daemon"),
        ("EXPOSE 23", Severity.HIGH, "Telnet"),
        ("EXPOSE 3389", Severity.HIGH, "RDP"),
    ]
    for expose_line, expected_sev, expected_svc in cases:
        findings = findings_for(f"FROM alpine:3.18\n{expose_line}\n")
        assert len(findings) == 1
        assert findings[0].severity == expected_sev
        assert expected_svc.lower() in findings[0].title.lower()


def test_safe_expose_ignored():
    findings = findings_for("FROM alpine:3.18\nEXPOSE 80 443 8080 3000\n")
    assert len(findings) == 0


def test_apt_update_standalone():
    findings = findings_for("FROM debian:12\nRUN apt-get update\n")
    update_findings = [
        f for f in findings if "standalone apt-get update" in f.title.lower()
    ]
    assert len(update_findings) == 1
    assert update_findings[0].severity == Severity.MEDIUM


def test_apt_install_issues():
    # Missing -y and missing cleanup
    findings = findings_for(
        "FROM debian:12\nRUN apt-get update && apt-get install curl\n"
    )
    titles = [f.title.lower() for f in findings]
    assert any("non-interactive" in t for t in titles)
    assert any("cache cleanup" in t for t in titles)

    # Clean install
    clean = (
        "FROM debian:12\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends curl && "
        "rm -rf /var/lib/apt/lists/*\n"
    )
    clean_findings = findings_for(clean)
    assert len(clean_findings) == 0


def test_copy_all_without_dockerignore():
    findings = findings_for("FROM python:3.11\nCOPY . /app\n")
    copy_findings = [f for f in findings if "without .dockerignore" in f.title.lower()]
    assert len(copy_findings) == 1
    assert copy_findings[0].severity == Severity.HIGH


def test_copy_all_with_dockerignore():
    findings = findings_for(
        "FROM python:3.11\nCOPY . /app\n", extra_files=[".dockerignore"]
    )
    copy_findings = [f for f in findings if "broad copy" in f.title.lower()]
    assert len(copy_findings) == 1
    assert copy_findings[0].severity == Severity.LOW


def test_copy_targeted_or_stage_ignored():
    content = (
        "FROM python:3.11 AS builder\n"
        "COPY requirements.txt /app/\n"
        "FROM python:3.11\n"
        "COPY --from=builder /app /app\n"
    )
    findings = findings_for(content)
    copy_findings = [f for f in findings if "copy" in f.title.lower()]
    assert len(copy_findings) == 0


def test_multiline_instruction_line_numbers_and_evidence():
    content = (
        "# line 1 comment\n"
        "FROM python:3.11\n"
        "RUN apt-get update && \\\n"
        "    apt-get install -y curl\n"
        "USER root\n"
    )
    findings = findings_for(content)
    user_finding = next(f for f in findings if "root user" in f.title.lower())
    assert user_finding.line_start == 5
    assert user_finding.line_end == 5

    apt_finding = next(f for f in findings if "cache cleanup" in f.title.lower())
    assert apt_finding.line_start == 3
    assert apt_finding.line_end == 4
    assert "\\" in apt_finding.evidence[0].content


@pytest.mark.parametrize(
    "filename",
    [
        "Dockerfile",
        "dockerfile",
        "Dockerfile.prod",
        "Dockerfile.dev",
        "api.dockerfile",
        "Containerfile",
        "Containerfile.ci",
    ],
)
def test_dockerfile_naming_variants_recognized(filename: str):
    findings = findings_for("FROM python:3.11\nUSER root\n", path=filename)
    assert len(findings) == 1


def test_non_dockerfiles_skipped():
    assert len(findings_for("FROM python:3.11\nUSER root\n", path="dockerfile.py")) == 0
    assert len(findings_for("USER root\nEXPOSE 22\n", path="README.md")) == 0
    assert (
        len(findings_for("USER root\nEXPOSE 22\n", path="Dockerfile")) == 0
    )  # no FROM
