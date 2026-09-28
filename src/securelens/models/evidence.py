from pydantic import BaseModel


class Evidence(BaseModel):
    file: str
    content: str
    line_start: int | None = None
    line_end: int | None = None
    context: str | None = None
