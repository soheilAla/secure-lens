from typing import Protocol, runtime_checkable

from securelens.models.assessment import Assessment
from securelens.models.finding import Finding


@runtime_checkable
class Assessor(Protocol):
    name: str

    def assess(self, finding: Finding) -> Assessment: ...
