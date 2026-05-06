import logging
import requests
from db import insert_scan, get_last_two_scans

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api_gateway")

BREACH_URL = "http://breach-scanner:8001"
GITHUB_URL = "http://github-scanner:8002"
RISK_URL = "http://risk-analyzer:8003"


def call_breach_scanner(email: str):
    logger.info("Calling breach scanner for email=%s", email)
    try:
        response = requests.post(
            f"{BREACH_URL}/scan/email",
            json={"email": email},
            timeout=5
        )
        response.raise_for_status()
        breaches = response.json().get("breaches", [])
        logger.info("Breach scanner returned %d items", len(breaches))
        return breaches
    except requests.exceptions.RequestException as e:
        logger.error("Breach Error: %s", e)

    return []


def call_github_scanner(username: str):
    logger.info("Calling GitHub scanner for username=%s", username)
    try:
        response = requests.post(
            f"{GITHUB_URL}/scan/github",
            json={"username": username},
            timeout=15
        )
        response.raise_for_status()

        data = response.json()
        leaks = data.get("leaks", [])
        logger.info("GitHub scanner returned %d leaks", len(leaks))

        # ✅ Deduplicate here (defensive layer)
        return deduplicate_leaks(leaks)

    except requests.exceptions.RequestException as e:
        logger.error("GitHub Error: %s", e)

    return []


# ✅ Deduplication helper
def deduplicate_leaks(leaks):
    seen = set()
    unique = []

    for leak in leaks:
        key = (
            leak.get("repo"),
            leak.get("file"),
            leak.get("type"),
            leak.get("line")
        )

        if key not in seen:
            seen.add(key)
            unique.append(leak)

    return unique

def compute_comparison(history):
    if len(history) < 2:
        return None

    current = history[0]["risk_score"]
    previous = history[1]["risk_score"]

    change = current - previous

    if change > 0:
        trend = "WORSENED"
    elif change < 0:
        trend = "IMPROVED"
    else:
        trend = "NO CHANGE"

    return {
        "previous_score": previous,
        "current_score": current,
        "change": change,
        "trend": trend
    }

def call_risk_analyzer(payload: dict):
    logger.info("Calling risk analyzer with email=%s username=%s", payload.get("email"), payload.get("username"))
    try:
        response = requests.post(
            f"{RISK_URL}/analyze/risk",
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        result = response.json()
        logger.info("Risk analyzer returned status=%s", response.status_code)
        return result
    except requests.exceptions.RequestException as e:
        logger.error("Risk Analyzer Error: %s", e)
        raise


def aggregate_data(email: str, username: str):

    # Step 1: Call scanners
    breaches = call_breach_scanner(email)
    github_leaks = call_github_scanner(username)


    # Step 2: Combine data
    combined = {
        "email": email,
        "username": username,
        "breaches": breaches,
        "github_leaks": github_leaks
    }

    logger.info("Sending to risk analyzer: %s", combined)

    # Step 3: Send to Risk Analyzer
    try:
        result = call_risk_analyzer(combined)
        # ✅ store in DB
        try:
            insert_scan(result)
        except Exception as e:
            logger.error("DB Insert Error: %s", e)

        # ✅ fetch last 2 scans
        history = get_last_two_scans(email)

        # ✅ attach history (for now)
        comparison = compute_comparison(history)

        result["history"] = history

        if comparison:
            result["comparison"] = comparison

        logger.info("Returning aggregated response")
        return result

    except Exception:
        return {
            "error": "Risk analysis failed",
            "data": combined
        }
