import logging
from fastapi import FastAPI
from models import AnalyzeRequest, EmailRequest, GitHubRequest, RiskRequest
from service import aggregate_data, call_breach_scanner, call_github_scanner, call_risk_analyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api_gateway")

app = FastAPI(title="API Gateway")
from db import init_db

init_db()
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow frontend (demo mode)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
@app.post("/scan/email")
def scan_email(request: EmailRequest):
    logger.info("Received /scan/email request: %s", request.dict())
    breaches = call_breach_scanner(request.email)
    response = {"breaches": breaches}
    logger.info("Returning /scan/email response: %s", response)
    return response

@app.post("/scan/github")
def scan_github(request: GitHubRequest):
    logger.info("Received /scan/github request: %s", request.dict())
    leaks = call_github_scanner(request.username)
    response = {"leaks": leaks}
    logger.info("Returning /scan/github response: %s", response)
    return response

@app.post("/analyze/risk")
def analyze_risk(request: RiskRequest):
    logger.info("Received /analyze/risk request: %s", request.dict())
    result = call_risk_analyzer(request.dict())
    logger.info("Returning /analyze/risk response: %s", result)
    return result

@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    logger.info("Received /analyze request: %s", request.dict())
    result = aggregate_data(request.email, request.username)
    logger.info("Returning /analyze response: %s", result)
    return result

@app.get("/health")
def health():
    logger.info("Received /health request")
    return {"status": "ok"}