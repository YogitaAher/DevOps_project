from fastapi import FastAPI
from models import EmailRequest
from service import scan_email

app = FastAPI()

@app.post("/scan/email")
async def scan_email_endpoint(request: EmailRequest):
    breaches = scan_email(request.email)
    return {"breaches": breaches}