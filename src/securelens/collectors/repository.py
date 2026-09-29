from pathlib import Path

from securelens.collectors.files import read_file
from securelens.collectors.filters import should_skip
from securelens.models.repository import FileTarget, RepositorySnapshot


class RepositoryCollector:
    def collect(self, root: str) -> RepositorySnapshot:
        root_path = Path(root).resolve()

        collected = []
        skipped = []

        for path in root_path.rglob("*"):
            if not path.is_file():
                continue
            if should_skip(path):
                skipped.append(str(path))
                continue

            content = read_file(path)

            if content is None:
                skipped.append(str(path))
                continue

            collected.append(
                FileTarget(path=str(path.relative_to(root_path)), content=content)
            )

        return RepositorySnapshot(
            root=str(root_path), collected_files=collected, skipped_files=skipped
        )
