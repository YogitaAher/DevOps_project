from fastapi import FastAPI
from models import RiskRequest
from service import analyze_risk

app = FastAPI(title="Risk Analyzer Service")

@app.post("/analyze/risk")
def analyze(request: RiskRequest):
    return analyze_risk(request.dict())

@app.get("/health")
def health():
    return {"status": "ok"}