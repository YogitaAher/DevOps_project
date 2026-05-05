from pydantic import BaseModel
from typing import List, Dict, Any

class RiskRequest(BaseModel):
    email: str
    username: str
    breaches: List[Dict[str, Any]]
    github_leaks: List[Dict[str, Any]]

class RiskResponse(BaseModel):
    email: str
    username: str
    summary: Dict[str, Any]
    breaches: List[Dict[str, Any]]
    github_leaks: List[Dict[str, Any]]
    top_issues: List[str]
    recommendations: List[str]