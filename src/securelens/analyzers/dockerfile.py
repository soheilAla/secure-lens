from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePath

from securelens.models.enums import RiskCategory, Severity
from securelens.models.evidence import Evidence
from securelens.models.finding import Finding
from securelens.models.repository import RepositorySnapshot

RISKY_PORTS: dict[str, tuple[str, Severity]] = {
    "22": ("SSH", Severity.LOW),
    "23": ("Telnet", Severity.LOW),
    "2375": ("Docker daemon (unencrypted)", Severity.LOW),
    "2376": ("Docker daemon (TLS)", Severity.LOW),
    "3389": ("RDP", Severity.LOW),
}

MUTABLE_BASE_TAGS: set[str] = {
    "latest",
    "edge",
    "nightly",
    "canary",
    "master",
    "main",
    "dev",
    "devel",
}

PIPE_SHELL_PATTERN = re.compile(
    r"\b(curl|wget)\b[^|;\n]+?\|\s*(?:/bin/)?(?:ba|da|z|a)?sh\b",
    re.IGNORECASE,
)
APT_UPDATE_PATTERN = re.compile(r"\b(apt-get|apt)\s+update\b", re.IGNORECASE)
APT_INSTALL_PATTERN = re.compile(r"\b(apt-get|apt)\s+install\b", re.IGNORECASE)
APT_NONINTERACTIVE_PATTERN = re.compile(
    r"(?<!\S)(?:-y|--yes|-q|-qq)(?!\S)", re.IGNORECASE
)
APT_CLEANUP_PATTERN = re.compile(
    r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/var/lib/apt/lists", re.IGNORECASE
)
COPY_ALL_PATTERN = re.compile(
    r"\bCOPY\s+(?:--[a-z0-9_=-]+\s+)*(\.|\./)\s+", re.IGNORECASE
)


@dataclass(frozen=True)
class DockerInstruction:
    instruction: str
    arguments: str
    raw: str
    line_start: int
    line_end: int


NON_DOCKER_EXTENSIONS = {
    ".py",
    ".go",
    ".rs",
    ".js",
    ".ts",
    ".c",
    ".cpp",
    ".h",
    ".java",
    ".rb",
    ".php",
    ".sh",
    ".bash",
    ".zsh",
    ".md",
    ".txt",
    ".toml",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".html",
    ".css",
    ".rst",
}


def is_dockerfile(path_str: str) -> bool:
    p = PurePath(path_str)
    if p.suffix.lower() in NON_DOCKER_EXTENSIONS:
        return False

    name = p.name.lower()
    return (
        name == "dockerfile"
        or name.startswith("dockerfile.")
        or name.endswith(".dockerfile")
        or name == "containerfile"
        or name.startswith("containerfile.")
        or name.endswith(".containerfile")
    )


def parse_dockerfile(content: str) -> list[DockerInstruction]:
    instructions: list[DockerInstruction] = []
    lines = content.splitlines()

    current_lines: list[str] = []
    start_line = 1

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not current_lines and (not stripped or stripped.startswith("#")):
            continue

        if not current_lines:
            start_line = idx

        if stripped.endswith("\\"):
            current_lines.append(line)
        else:
            current_lines.append(line)
            raw_text = "\n".join(current_lines)

            cleaned_parts: list[str] = []
            for part in current_lines:
                p = part.strip()
                if p.endswith("\\"):
                    p = p[:-1].strip()
                if p and not p.startswith("#"):
                    cleaned_parts.append(p)

            combined = " ".join(cleaned_parts)
            if combined:
                parts = combined.split(maxsplit=1)
                keyword = parts[0].upper()
                arguments = parts[1] if len(parts) > 1 else ""
                instructions.append(
                    DockerInstruction(
                        instruction=keyword,
                        arguments=arguments,
                        raw=raw_text,
                        line_start=start_line,
                        line_end=idx,
                    )
                )
            current_lines = []

    if current_lines:
        raw_text = "\n".join(current_lines)
        cleaned_parts = [
            p.strip()[:-1].strip() if p.strip().endswith("\\") else p.strip()
            for p in current_lines
            if p.strip() and not p.strip().startswith("#")
        ]
        combined = " ".join(cleaned_parts)
        if combined:
            parts = combined.split(maxsplit=1)
            keyword = parts[0].upper()
            arguments = parts[1] if len(parts) > 1 else ""
            instructions.append(
                DockerInstruction(
                    instruction=keyword,
                    arguments=arguments,
                    raw=raw_text,
                    line_start=start_line,
                    line_end=len(lines) or 1,
                )
            )

    return instructions


class DockerfileAnalyzer:
    name = "dockerfile"

    def analyze(self, snapshot: RepositorySnapshot) -> list[Finding]:
        findings: list[Finding] = []
        has_dockerignore = any(
            PurePath(f.path).name == ".dockerignore" for f in snapshot.collected_files
        )

        for file in snapshot.collected_files:
            if not is_dockerfile(file.path):
                continue

            instructions = parse_dockerfile(file.content)
            has_from = any(inst.instruction == "FROM" for inst in instructions)
            if not has_from:
                continue

            known_stages: set[str] = set()

            for inst in instructions:
                if inst.instruction == "FROM":
                    stage = self._record_stage(inst.arguments)
                    if stage:
                        known_stages.add(stage.lower())

            for inst in instructions:
                match inst.instruction:
                    case "USER":
                        f = self._check_user_root(file.path, inst)
                        if f:
                            findings.append(f)
                    case "FROM":
                        f = self._check_base_image(file.path, inst, known_stages)
                        if f:
                            findings.append(f)
                    case "ADD":
                        f = self._check_remote_add(file.path, inst)
                        if f:
                            findings.append(f)
                    case "EXPOSE":
                        findings.extend(self._check_expose(file.path, inst))
                    case "RUN":
                        findings.extend(self._check_run(file.path, inst))
                    case "COPY":
                        f = self._check_copy(file.path, inst, has_dockerignore)
                        if f:
                            findings.append(f)

        return findings

    @staticmethod
    def _record_stage(arguments: str) -> str | None:
        tokens = arguments.split()
        for i, token in enumerate(tokens):
            if token.upper() == "AS" and i + 1 < len(tokens):
                return tokens[i + 1]
        return None

    def _check_user_root(self, path: str, inst: DockerInstruction) -> Finding | None:
        raw_user = inst.arguments.strip().split(":")[0].strip()
        if raw_user.lower() in ("root", "0"):
            return self._finding(
                path=path,
                inst=inst,
                severity=Severity.HIGH,
                title="Container runs as root user",
                description=(
                    f"Explicit 'USER {inst.arguments}' runs container processes "
                    "with root privileges. Use a dedicated non-root user instead."
                ),
            )
        return None

    def _check_base_image(
        self, path: str, inst: DockerInstruction, known_stages: set[str]
    ) -> Finding | None:
        tokens = [t for t in inst.arguments.split() if not t.startswith("--")]
        if not tokens:
            return None

        image = tokens[0]
        if image.startswith("$") or image.startswith("${"):
            return None
        if image.lower() == "scratch" or image.lower() in known_stages:
            return None

        if "@" in image:
            return None

        image_name_part = image.split("/")[-1]

        if ":" not in image_name_part:
            return self._finding(
                path=path,
                inst=inst,
                severity=Severity.LOW,
                title="Untagged base image (defaults to latest)",
                description=(
                    f"Base image '{image}' specifies no tag and defaults "
                    "to mutable 'latest'. Pin to an exact version tag or SHA256 digest."
                ),
            )

        tag = image_name_part.rsplit(":", 1)[-1]
        if tag.lower() in MUTABLE_BASE_TAGS:
            return self._finding(
                path=path,
                inst=inst,
                severity=Severity.LOW,
                title=f"Mutable tag used in base image: ':{tag}'",
                description=(
                    f"Base image '{image}' uses mutable tag ':{tag}'. "
                    "Pin to an exact tag or SHA256 digest for reproducible builds."
                ),
            )

        return None

    def _check_remote_add(self, path: str, inst: DockerInstruction) -> Finding | None:
        tokens = [t for t in inst.arguments.split() if not t.startswith("--")]
        if len(tokens) < 2:
            return None

        sources = tokens[:-1]
        remote_sources = [
            s for s in sources if s.startswith(("http://", "https://", "ftp://"))
        ]
        if remote_sources:
            return self._finding(
                path=path,
                inst=inst,
                severity=Severity.MEDIUM,
                title="Remote URL used in ADD instruction",
                description=(
                    "ADD instruction downloads remote files without checksum "
                    "verification. Use curl/wget with hash verification in a "
                    "RUN instruction or COPY local files."
                ),
            )
        return None

    def _check_expose(self, path: str, inst: DockerInstruction) -> list[Finding]:
        findings: list[Finding] = []
        ports = re.findall(r"\b(\d+)(?:/(?:tcp|udp))?\b", inst.arguments)

        for port in ports:
            if port in RISKY_PORTS:
                service, severity = RISKY_PORTS[port]
                title = (
                    f"Sensitive port declared in EXPOSE metadata: "
                    f"{service} (port {port})"
                )
                findings.append(
                    self._finding(
                        path=path,
                        inst=inst,
                        severity=severity,
                        title=title,
                        description=(
                            f"Container metadata declares port {port} ({service}). "
                            "EXPOSE is advisory and does not publish ports, "
                            "but indicates an administrative daemon may run."
                        ),
                    )
                )
        return findings

    def _check_run(self, path: str, inst: DockerInstruction) -> list[Finding]:
        findings: list[Finding] = []

        if PIPE_SHELL_PATTERN.search(inst.arguments):
            findings.append(
                self._finding(
                    path=path,
                    inst=inst,
                    severity=Severity.HIGH,
                    title="Insecure pipe to shell execution",
                    description=(
                        "Piping curl or wget directly into a shell interpreter "
                        "executes unverified remote code. Download script, verify "
                        "integrity, and execute explicitly."
                    ),
                )
            )

        has_apt_update = bool(APT_UPDATE_PATTERN.search(inst.arguments))
        has_apt_install = bool(APT_INSTALL_PATTERN.search(inst.arguments))

        if has_apt_update and not has_apt_install:
            findings.append(
                self._finding(
                    path=path,
                    inst=inst,
                    severity=Severity.MEDIUM,
                    title="Standalone apt-get update instruction",
                    description=(
                        "Running 'apt-get update' in an isolated RUN layer creates "
                        "stale cache layers. Combine 'apt-get update && apt-get "
                        "install' in the same RUN command."
                    ),
                )
            )

        if has_apt_install:
            if not APT_NONINTERACTIVE_PATTERN.search(inst.arguments):
                findings.append(
                    self._finding(
                        path=path,
                        inst=inst,
                        severity=Severity.LOW,
                        title="apt-get install missing non-interactive flag",
                        description=(
                            "'apt-get install' without '-y' or '--yes' can "
                            "prompt interactively, causing builds to fail."
                        ),
                    )
                )

            if not APT_CLEANUP_PATTERN.search(inst.arguments):
                findings.append(
                    self._finding(
                        path=path,
                        inst=inst,
                        severity=Severity.LOW,
                        title="Missing package manager cache cleanup",
                        description=(
                            "'apt-get install' without 'rm -rf /var/lib/apt/lists/*' "
                            "leaves cached package lists in the container layer, "
                            "increasing image size and attack surface."
                        ),
                    )
                )

        return findings

    def _check_copy(
        self, path: str, inst: DockerInstruction, has_dockerignore: bool
    ) -> Finding | None:
        tokens = inst.arguments.split()
        if any(t.startswith("--from=") for t in tokens):
            return None

        if not COPY_ALL_PATTERN.search(inst.raw):
            return None

        if not has_dockerignore:
            return self._finding(
                path=path,
                inst=inst,
                severity=Severity.LOW,
                title="Build context copy without .dockerignore",
                description=(
                    "COPY instruction copies entire working directory into the "
                    "image without a .dockerignore file. Sensitive files like "
                    ".git, .env, or credentials may leak into image layers."
                ),
            )

        return self._finding(
            path=path,
            inst=inst,
            severity=Severity.INFORMATIONAL,
            title="Broad COPY of entire build context",
            description=(
                "Copying entire context root ('.') may include unnecessary "
                "files into the image. Prefer copying specific directories."
            ),
        )

    @staticmethod
    def _finding(
        path: str,
        inst: DockerInstruction,
        severity: Severity,
        title: str,
        description: str,
    ) -> Finding:
        return Finding(
            category=RiskCategory.DOCKER,
            title=title,
            description=description,
            severity=severity,
            file=path,
            line_start=inst.line_start,
            line_end=inst.line_end,
            evidence=[
                Evidence(
                    file=path,
                    content=inst.raw.strip(),
                    line_start=inst.line_start,
                    line_end=inst.line_end,
                    context=f"Instruction: {inst.instruction}",
                )
            ],
        )
