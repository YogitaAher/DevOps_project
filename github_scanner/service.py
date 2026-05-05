"""
Enhanced GitHub Scanner Service
Detects exposed secrets using:
- Regex patterns
- Real-world API key patterns
- Entropy-based detection
- Line-level analysis
"""

import os
import requests
import base64
import re
import math
from collections import Counter
from typing import List, Dict, Any

GITHUB_SEARCH_API = "https://api.github.com/search/code"

# ------------------ PATTERNS ------------------

PATTERNS = {
    "API_KEY": r"(?i)(api[_-]?key|apikey|access[_-]?token|token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{10,})",

    "PASSWORD": r"(?i)(password|passwd|pass|pwd)[A-Za-z0-9_]*\s*[:=]\s*['\"]?(.+)",

    "SECRET": r"(?i)(secret|client[_-]?secret|private[_-]?key|jwt_secret)[A-Za-z0-9_]*\s*[:=]\s*['\"]?(.+)",

    "EMAIL": r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,})"
}

# Real-world key patterns (Feature B)
ADVANCED_PATTERNS = {
    "AWS_KEY": r"AKIA[0-9A-Z]{16}",
    "GITHUB_TOKEN": r"ghp_[A-Za-z0-9]{36}",
    "GOOGLE_API_KEY": r"AIza[0-9A-Za-z\-_]{35}",
    "JWT": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"
}

# Severity scoring (Feature D)
SEVERITY_SCORE = {
    "PASSWORD": 10,
    "API_KEY": 9,
    "AWS_KEY": 10,
    "GITHUB_TOKEN": 9,
    "GOOGLE_API_KEY": 9,
    "SECRET": 8,
    "JWT": 8,
    "EMAIL": 3,
    "ENTROPY_SECRET": 7
}

# ------------------ UTIL FUNCTIONS ------------------

def mask_value(value: str):
    if len(value) <= 6:
        return "***"
    return value[:3] + "***" + value[-3:]


# Feature A: Entropy detection
def shannon_entropy(data: str):
    if not data:
        return 0
    prob = [n_x / len(data) for x, n_x in Counter(data).items()]
    return -sum(p * math.log2(p) for p in prob)


def detect_entropy_secrets(line: str):
    results = []
    tokens = re.findall(r"[A-Za-z0-9_\-]{12,}", line)

    for token in tokens:
        entropy = shannon_entropy(token)

        if entropy > 4.5:
            results.append({
                "type": "ENTROPY_SECRET",
                "value": token,
                "entropy": round(entropy, 2)
            })

    return results


# ------------------ QUERY BUILDER ------------------

def build_query(keyword: str, username: str, repo: str | None = None) -> str:
    if repo:
        return f"{keyword}+repo:{username}/{repo}"
    return f"{keyword}+user:{username}"


# ------------------ SEARCH FUNCTION ------------------

def search_github(keyword: str, username: str, repo: str | None = None):
    token = os.getenv("GITHUB_TOKEN")

    if not token:
        raise Exception("GITHUB_TOKEN not set")

    query = build_query(keyword, username, repo)
    url = f"{GITHUB_SEARCH_API}?q={query}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return []

    data = response.json()
    items = data.get("items", [])

    results = []

    for item in items:
        results.append({
            "repo": item.get("repository", {}).get("full_name", ""),
            "file": item.get("name", ""),
            "path": item.get("path", ""),
            "html_url": item.get("html_url", ""),
            "url": item.get("url", "")
        })

    return results


# ------------------ FILE CONTENT ------------------


def get_user_repos(username: str):
    token = os.getenv("GITHUB_TOKEN")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }

    repos = []
    page = 1

    while True:
        url = f"https://api.github.com/users/{username}/repos?per_page=100&page={page}"
        res = requests.get(url, headers=headers)

        if res.status_code != 200:
            break

        data = res.json()

        if not data:
            break

        for repo in data:
            repos.append(repo["name"])

        page += 1

    return repos
def get_repo_files(username: str, repo: str):
    token = os.getenv("GITHUB_TOKEN")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }

    # get default branch
    repo_url = f"https://api.github.com/repos/{username}/{repo}"
    repo_data = requests.get(repo_url, headers=headers).json()
    branch = repo_data.get("default_branch", "main")

    # get tree recursively
    tree_url = f"https://api.github.com/repos/{username}/{repo}/git/trees/{branch}?recursive=1"
    res = requests.get(tree_url, headers=headers)

    if res.status_code != 200:
        return []

    tree = res.json().get("tree", [])

    files = []
    for item in tree:
        if item["type"] == "blob":
            files.append(item["path"])

    return files
def get_file_content_full(username, repo, path, headers):
    url = f"https://api.github.com/repos/{username}/{repo}/contents/{path}"
    res = requests.get(url, headers=headers)

    if res.status_code != 200:
        return ""

    data = res.json()
    content = data.get("content", "")

    try:
        return base64.b64decode(content).decode("utf-8", errors="ignore")
    except:
        return ""
# ------------------ CLASSIFICATION (UPDATED) ------------------

def classify_leak(content: str):
    results = []

    lines = content.split("\n")

    for i, line in enumerate(lines):

        # ---- Basic patterns ----
        for leak_type, pattern in PATTERNS.items():
            matches = re.findall(pattern, line)

            for match in matches:
                if isinstance(match, tuple):
                    match = " ".join(match)

                results.append({
                    "type": leak_type,
                    "value": match.strip(),
                    "line": i + 1,
                    "snippet": line.strip()
                })

        # ---- Advanced patterns ----
        for leak_type, pattern in ADVANCED_PATTERNS.items():
            matches = re.findall(pattern, line)

            for match in matches:
                results.append({
                    "type": leak_type,
                    "value": match,
                    "line": i + 1,
                    "snippet": line.strip()
                })

        # ---- Entropy detection ----
        entropy_matches = detect_entropy_secrets(line)

        for ent in entropy_matches:
            ent["line"] = i + 1
            ent["snippet"] = line.strip()
            results.append(ent)
        # ---- .env specific parsing ----
        if "=" in line and not line.strip().startswith("#"):
            parts = line.split("=", 1)

            if len(parts) == 2:
                key = parts[0].strip().lower()
                value = parts[1].strip().strip('"').strip("'")

                if "password" in key:
                    results.append({
                        "type": "PASSWORD",
                        "value": value,
                        "line": i + 1,
                        "snippet": line.strip()
                    })

                elif "secret" in key:
                    results.append({
                        "type": "SECRET",
                        "value": value,
                        "line": i + 1,
                        "snippet": line.strip()
                    })

                elif "api_key" in key or "token" in key:
                    results.append({
                        "type": "API_KEY",
                        "value": value,
                        "line": i + 1,
                        "snippet": line.strip()
                    })

    return results


# ------------------ MAIN SCAN FUNCTION ------------------

def scan_github(username: str):
    token = os.getenv("GITHUB_TOKEN")

    if not token:
        raise Exception("GITHUB_TOKEN not set")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }

    all_results = []
    seen = set()

    repos = get_user_repos(username)

    for repo in repos:
        print(f"Scanning repo: {repo}")

        files = get_repo_files(username, repo)

        for file_path in files:
            # optional: skip large/unwanted files
            if not file_path.endswith((".py", ".env", ".js", ".json", ".txt")):
                continue

            content = get_file_content_full(username, repo, file_path, headers)

            if not content:
                continue

            leaks = classify_leak(content)

            for leak in leaks:
                key = (repo, file_path, leak["type"], leak["value"])

                if key in seen:
                    continue

                seen.add(key)

                score = SEVERITY_SCORE.get(leak["type"], 5)

                all_results.append({
                    "repo": f"{username}/{repo}",
                    "file": file_path,
                    "type": leak["type"],
                    "severity": "HIGH" if score >= 8 else "MEDIUM" if score >= 5 else "LOW",
                    "score": score,
                    "value": mask_value(leak["value"]),
                    "line": leak.get("line"),
                    "snippet": leak.get("snippet"),
                    "source": "github"
                })

    return sorted(all_results, key=lambda x: x["score"], reverse=True)