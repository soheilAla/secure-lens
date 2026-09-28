from pathlib import Path

IGNORED_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
}


IGNORED_EXTENSIONS = {
    ".png",
    ".svg",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".mp3",
    ".mp4",
    ".avi",
    ".woff",
    ".woff2",
    ".ttf",
    ".zip",
    ".tar",
    ".gz",
    ".pdf",
}


def should_skip(path: Path) -> bool:
    if any(part.lower() in IGNORED_DIRS for part in path.parts):
        return True

    return path.suffix.lower() in IGNORED_EXTENSIONS
