from pathlib import Path


def read_file(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError, PermissionError:
        return None
