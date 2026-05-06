from pydantic import BaseModel
from typing import List, Dict, Any

class EmailRequest(BaseModel):
    email: str

class GitHubRequest(BaseModel):
    username: str

class RiskRequest(BaseModel):
    email: str
    username: str
    breaches: List[Dict[str, Any]]
    github_leaks: List[Dict[str, Any]]

class AnalyzeRequest(BaseModel):
    email: str
    username: str