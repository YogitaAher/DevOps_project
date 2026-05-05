from rules import SEVERITY_WEIGHTS, EXPOSURE_RULES, GENERAL_RULES

def analyze_risk(data):
    email = data.get("email")
    username = data.get("username")
    breaches = data.get("breaches", [])
    leaks = data.get("github_leaks", [])

    score = 0
    issues = set()
    recommendations = set()

    # ---- Breach Analysis ----
    for breach in breaches:
        score += 10  # base breach weight

        exposed = [d.lower() for d in breach.get("data_exposed", [])]

        for item in exposed:
            if item in EXPOSURE_RULES:
                rule = EXPOSURE_RULES[item]
                issues.add(rule["issue"])
                recommendations.add(rule["recommendation"])
                score += 20

        # Recency factor
        if breach.get("year", 2000) >= 2022:
            score += 15

    # ---- GitHub Leak Analysis ----
    for leak in leaks:
        severity = leak.get("severity", "LOW").upper()
        score += SEVERITY_WEIGHTS.get(severity, 5)

        leak_type = leak.get("type", "").lower()

        if leak_type in EXPOSURE_RULES:
            rule = EXPOSURE_RULES[leak_type]
            issues.add(rule["issue"])
            recommendations.add(rule["recommendation"])

        if severity == "HIGH":
            issues.add("Hardcoded credentials found in GitHub")

    # ---- General Rules ----
    if len(breaches) >= 2:
        recommendations.add(GENERAL_RULES["multiple_breaches"])

    if len(leaks) > 0:
        recommendations.add(GENERAL_RULES["github_secrets"])

    # ---- Normalize Score ----
    score = min(score, 100)

    # ---- Risk Level ----
    if score > 70:
        level = "HIGH"
    elif score > 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    # ---- Final Response ----
    return {
        "email": email,
        "username": username,
        "summary": {
            "breach_count": len(breaches),
            "github_leak_count": len(leaks),
            "risk_score": score,
            "risk_level": level
        },
        "breaches": breaches,
        "github_leaks": [
            {
                "repo": l.get("repo"),
                "file": l.get("file"),
                "type": l.get("type"),
                "line": l.get("line"),
                "severity": l.get("severity")
            } for l in leaks
        ],
        "top_issues": list(issues),
        "recommendations": list(recommendations)
    }