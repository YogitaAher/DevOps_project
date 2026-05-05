from fastapi import FastAPI
from fastapi.responses import JSONResponse
from models import GitHubRequest, GitHubResponse
from service import scan_github

# Initialize FastAPI app with title and description
app = FastAPI(
    title="GitHub Scanner",
    description="Microservice to scan GitHub profiles for data leaks and exposed secrets",
    version="1.0.0"
)


@app.post("/scan/github", response_model=GitHubResponse)
async def scan_github_route(request: GitHubRequest):

    result = scan_github(
        username=request.username,
    )

    return {"leaks": result}


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}
