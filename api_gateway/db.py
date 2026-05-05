import sqlite3
import json
from datetime import datetime
import uuid



def get_connection():
    return sqlite3.connect("data/scans.db")


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        email TEXT,
        username TEXT,
        timestamp TEXT,
        risk_score INTEGER,
        risk_level TEXT,
        breach_count INTEGER,
        github_leak_count INTEGER,
        critical_issues INTEGER,
        top_issues TEXT
    )
    """)

    conn.commit()
    conn.close()


def insert_scan(data):
    conn = get_connection()
    cursor = conn.cursor()

    scan_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()

    summary = data.get("summary", {})

    cursor.execute("""
    INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        data.get("email"),
        data.get("username"),
        timestamp,
        summary.get("risk_score"),
        summary.get("risk_level"),
        summary.get("breach_count"),
        summary.get("github_leak_count"),
        len(data.get("top_issues", [])),
        json.dumps(data.get("top_issues", []))
    ))

    conn.commit()
    conn.close()


def get_last_two_scans(email):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT risk_score, timestamp FROM scans
    WHERE email = ?
    ORDER BY timestamp DESC
    LIMIT 2
    """, (email,))

    rows = cursor.fetchall()
    conn.close()

    result = []
    for row in rows:
        result.append({
            "risk_score": row[0],
            "timestamp": row[1]
        })

    return result