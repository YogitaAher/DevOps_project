from fastapi import FastAPI
from models import AnalyzeRequest
from service import aggregate_data

app = FastAPI(title="API Gateway")
from db import init_db

init_db()
@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    result = aggregate_data(request.email, request.username)
    return result

@app.get("/health")
def health():
    return {"status": "ok"}