from pydantic import BaseModel, Field


class FileTarget(BaseModel):
    path: str
    content: str


class RepositorySnapshot(BaseModel):
    root: str
    files: list[FileTarget]
    skipped_files: list[str] = Field(default_factory=list)
