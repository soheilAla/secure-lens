from __future__ import annotations

import configparser
import fnmatch
import re
from pathlib import PurePath

from securelens.models.enums import RiskCategory, Severity
from securelens.models.evidence import Evidence
from securelens.models.finding import Finding
from securelens.models.repository import RepositorySnapshot

SENSITIVE_PATTERNS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "*.kdbx",
    "*credentials*.json",
    "*service-account*.json",
)

NON_SENSITIVE = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.default",
}

HOOK_DIR_PREFIXES = (".husky/", ".githooks/", "githooks/", ".git-hooks/")
HOOK_IGNORE_FILES = {".gitignore", "README.md", "package.json"}

HOOK_PATTERNS = (
    (
        re.compile(
            r"\b(curl|wget)\b[^|;\n]+?\|\s*(?:/bin/)?(?:ba|da|z|a)?sh\b",
            re.IGNORECASE,
        ),
        "pipe to shell",
    ),
    (
        re.compile(r"\b(nc\s+-[a-zA-Z]*e|/dev/tcp/|bash\s+-i\b)", re.IGNORECASE),
        "reverse shell",
    ),
    (
        re.compile(
            r"base64\s+(?:-d|--decode)\s*\|\s*(?:/bin/)?(?:ba|da|z|a)?sh\b",
            re.IGNORECASE,
        ),
        "base64 execution",
    ),
)


class GitRepositoryAnalyzer:
    name = "git-repository"

    def analyze(self, snapshot: RepositorySnapshot) -> list[Finding]:
        findings: list[Finding] = []
        files = {PurePath(f.path).name: f for f in snapshot.collected_files}

        findings.extend(self._check_gitignore(snapshot, files.get(".gitignore")))
        findings.extend(self._check_hooks(snapshot))

        gitmodules = files.get(".gitmodules")
        if gitmodules:
            findings.extend(self._check_submodules(gitmodules.path, gitmodules.content))

        gitconfig = next(
            (
                f
                for f in snapshot.collected_files
                if PurePath(f.path).name in (".gitconfig", "config")
            ),
            None,
        )
        if gitconfig:
            findings.extend(self._check_config(gitconfig.path, gitconfig.content))

        return findings

    def _check_gitignore(
        self, snapshot: RepositorySnapshot, gitignore
    ) -> list[Finding]:
        if not gitignore:
            if snapshot.collected_files:
                return [
                    self._finding(
                        ".gitignore",
                        "Missing .gitignore file",
                        "Repository lacks .gitignore.",
                        Severity.LOW,
                    )
                ]
            return []

        rules = [
            line.strip().lstrip("/").rstrip("/")
            for line in gitignore.content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        findings: list[Finding] = []

        for file in snapshot.collected_files:
            name = PurePath(file.path).name
            if name == ".gitignore" or name in NON_SENSITIVE:
                continue

            if not any(
                fnmatch.fnmatch(name, p) or fnmatch.fnmatch(file.path, p)
                for p in SENSITIVE_PATTERNS
            ):
                continue

            matches = any(
                fnmatch.fnmatch(name, r) or fnmatch.fnmatch(file.path, r) for r in rules
            )
            if matches:
                findings.append(
                    self._finding(
                        file.path,
                        f"Sensitive file tracked despite .gitignore: {file.path}",
                        "File matches .gitignore but is tracked in git index.",
                        Severity.HIGH,
                        text=file.path,
                    )
                )
            else:
                findings.append(
                    self._finding(
                        file.path,
                        f"Sensitive file tracked and unignored: {file.path}",
                        "Sensitive file is tracked and not listed in .gitignore.",
                        Severity.HIGH,
                        text=file.path,
                    )
                )

        return findings

    def _check_hooks(self, snapshot: RepositorySnapshot) -> list[Finding]:
        findings: list[Finding] = []
        for file in snapshot.collected_files:
            if not any(file.path.startswith(p) for p in HOOK_DIR_PREFIXES):
                continue

            name = PurePath(file.path).name
            if name in HOOK_IGNORE_FILES:
                continue

            for line_no, line in enumerate(file.content.splitlines(), start=1):
                for rx, label in HOOK_PATTERNS:
                    if rx.search(line):
                        findings.append(
                            self._finding(
                                file.path,
                                f"Suspicious command in Git hook: {name}",
                                f"Hook executes suspicious command ({label}).",
                                Severity.HIGH,
                                line=line_no,
                                text=line.strip(),
                            )
                        )
        return findings

    def _check_submodules(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        cp = configparser.ConfigParser()
        try:
            cp.read_string(content)
        except Exception:
            return findings

        for sec in cp.sections():
            if not sec.lower().startswith("submodule"):
                continue
            url = cp.get(sec, "url", fallback="").strip()
            sub_path = cp.get(sec, "path", fallback="").strip()
            line = self._find_line(content, url or sub_path)

            if url.startswith("-") or sub_path.startswith("-"):
                findings.append(
                    self._finding(
                        path,
                        "Command injection flag in submodule configuration",
                        f"Submodule flag injection: '{url or sub_path}'.",
                        Severity.CRITICAL,
                        line,
                        f"url = {url}",
                    )
                )
            if url.startswith(("http://", "git://")):
                findings.append(
                    self._finding(
                        path,
                        "Insecure transport protocol in submodule URL",
                        f"Submodule uses unencrypted transport '{url}'.",
                        Severity.MEDIUM,
                        line,
                        f"url = {url}",
                    )
                )
            if re.search(r"://[^/\s:@]+:[^/\s:@]+@", url):
                findings.append(
                    self._finding(
                        path,
                        "Hardcoded credentials in submodule URL",
                        "Submodule URL embeds credentials.",
                        Severity.HIGH,
                        line,
                        f"url = {url}",
                    )
                )

        return findings

    def _check_config(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        cp = configparser.ConfigParser()
        try:
            cp.read_string(content)
        except Exception:
            return findings

        if cp.has_option("core", "fsmonitor"):
            val = cp.get("core", "fsmonitor").strip()
            findings.append(
                self._finding(
                    path,
                    "Arbitrary command in core.fsmonitor configuration",
                    f"core.fsmonitor runs external command '{val}'.",
                    Severity.HIGH,
                    self._find_line(content, val),
                    f"fsmonitor = {val}",
                )
            )

        if cp.has_option("core", "hooksPath"):
            val = cp.get("core", "hooksPath").strip()
            if val.startswith(("/tmp", "/var/tmp", "/dev/shm", "..")):
                findings.append(
                    self._finding(
                        path,
                        "Dangerous core.hooksPath in Git configuration",
                        f"core.hooksPath points to external directory '{val}'.",
                        Severity.HIGH,
                        self._find_line(content, val),
                        f"hooksPath = {val}",
                    )
                )

        if (
            cp.has_option("protocol.ext", "allow")
            and cp.get("protocol.ext", "allow").strip().lower() == "always"
        ):
            findings.append(
                self._finding(
                    path,
                    "Dangerous protocol.ext.allow configuration",
                    "protocol.ext.allow set to 'always'.",
                    Severity.CRITICAL,
                    self._find_line(content, "allow"),
                    "allow = always",
                )
            )

        return findings

    @staticmethod
    def _finding(
        path: str,
        title: str,
        desc: str,
        sev: Severity,
        line: int = 1,
        text: str = "",
    ) -> Finding:
        ev = (
            [Evidence(file=path, content=text, line_start=line, line_end=line)]
            if text
            else []
        )
        return Finding(
            category=RiskCategory.CONFIGURATION,
            title=title,
            description=desc,
            severity=sev,
            file=path,
            line_start=line,
            line_end=line,
            evidence=ev,
        )

    @staticmethod
    def _find_line(content: str, text: str) -> int:
        if not text:
            return 1
        for idx, line in enumerate(content.splitlines(), start=1):
            if text in line:
                return idx
        return 1
