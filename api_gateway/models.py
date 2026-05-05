from pydantic import BaseModel

class AnalyzeRequest(BaseModel):
    email: str
    username: str