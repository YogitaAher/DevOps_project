import json
import requests
# Add at top
from pydantic import BaseModel

class BreachItem(BaseModel):
    name: str
    year: int
    data_exposed: list[str]
    severity: str
    source: str
def scan_email(email: str):
    # ---- 1. Try LeakCheck API ----
    try:
        url = f"https://leakcheck.io/api/public?check={email}"
        res = requests.get(url, timeout=5)

        if res.status_code == 200:
            data = res.json()

            if data.get("success") and data.get("found", 0) > 0:
                breaches = []

                for src in data.get("sources", []):
                    name = src.get("name", "Unknown")
                    year = src.get("date", "0000")[:4]

                    data_exp = data.get("fields", [])

                    # Severity logic (same as your existing)
                    if "password" in data_exp:
                        severity = "HIGH"
                    elif any(x in data_exp for x in ["username", "phone"]):
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

                    breaches.append({
                        "name": name,
                        "year": int(year) if year.isdigit() else 0,
                        "data_exposed": data_exp,
                        "severity": severity,
                        "source": "LEAKCHECK"
                    })

                breaches.sort(key=lambda x: x["year"], reverse=True)
                return breaches

    except Exception:
        pass  # silently fallback

    # ---- 2. Fallback to local dataset ----
    with open("data.json", "r") as f:
        data = json.load(f)
    
    matching = [entry for entry in data if entry["email"] == email]
    
    breaches = []
    for entry in matching:
        data_exp = entry["data_exposed"]

        if "password" in data_exp:
            severity = "HIGH"
        elif any(x in data_exp for x in ["username", "phone"]):
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        breaches.append({
            "name": entry["breach"],
            "year": entry["year"],
            "data_exposed": data_exp,
            "severity": severity,
            "source": "LOCAL"
        })
    
    breaches.sort(key=lambda x: x["year"], reverse=True)
    return breaches