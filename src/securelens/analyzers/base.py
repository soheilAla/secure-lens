from typing import Protocol

from securelens.models.finding import Finding
from securelens.models.repository import RepositorySnapshot


class Analyzer(Protocol):
    name: str

    def analyze(self, snapshot: RepositorySnapshot) -> list[Finding]: ...
