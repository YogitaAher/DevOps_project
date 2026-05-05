# Severity weights
SEVERITY_WEIGHTS = {
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 5
}

# Exposure-based rules
EXPOSURE_RULES = {
    "password": {
        "issue": "Password exposed in breach",
        "recommendation": "Change all compromised passwords immediately"
    },
    "api_key": {
        "issue": "API key exposed",
        "recommendation": "Revoke and rotate exposed API keys"
    },
    "token": {
        "issue": "Authentication token exposed",
        "recommendation": "Invalidate tokens and regenerate new ones"
    }
}

# General recommendations
GENERAL_RULES = {
    "multiple_breaches": "Enable 2FA on important accounts",
    "github_secrets": "Remove secrets from GitHub repositories"
}