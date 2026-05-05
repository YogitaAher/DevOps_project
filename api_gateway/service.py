from unittest import result

import requests
from db import insert_scan, get_last_two_scans
BREACH_URL = "http://breach-scanner:8001"
GITHUB_URL = "http://github-scanner:8002"
RISK_URL = "http://risk-analyzer:8003"


def call_breach_scanner(email: str):
    try:
        response = requests.post(
            BREACH_URL,
            json={"email": email},
            timeout=5
        )
        if response.status_code == 200:
            return response.json().get("breaches", [])
    except Exception as e:
        print("Breach Error:", e)

    return []


def call_github_scanner(username: str):
    try:
        response = requests.post(
            GITHUB_URL,
            json={"username": username},
            timeout=15
        )

        print("GitHub Status:", response.status_code)
        print("GitHub Raw Response:", response.text)

        if response.status_code == 200:
            data = response.json()
            leaks = data.get("leaks", [])

            # ✅ Deduplicate here (defensive layer)
            return deduplicate_leaks(leaks)

    except Exception as e:
        print("GitHub Error:", e)

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

    print("Sending to risk analyzer:", combined)

    # Step 3: Send to Risk Analyzer
    try:
        response = requests.post(
            RISK_URL,
            json=combined,
            timeout=10   # slightly increased
        )

        print("Risk Analyzer Status:", response.status_code)
        print("Risk Analyzer Response:", response.text)

        if response.status_code == 200:
            result = response.json()
            # ✅ store in DB
            try:
                insert_scan(result)
            except Exception as e:
                print("DB Insert Error:", e)

            # ✅ fetch last 2 scans
            history = get_last_two_scans(email)

            # ✅ attach history (for now)
            comparison = compute_comparison(history)

            result["history"] = history

            if comparison:
                result["comparison"] = comparison

            return result

    except Exception as e:
        print("Risk Analyzer Error:", e)

    return {
        "error": "Risk analysis failed",
        "data": combined
    }
