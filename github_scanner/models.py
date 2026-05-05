from pydantic import BaseModel, Field
from typing import List, Optional


class GitHubRequest(BaseModel):
    username: str


class LeakItem(BaseModel):
    repo: str
    file: str
    type: str
    severity: str
    source: str

    # NEW FIELDS
    value: Optional[str] = None
    line: Optional[int] = None
    snippet: Optional[str] = None
    score: Optional[int] = None


class GitHubResponse(BaseModel):
    leaks: List[LeakItem]