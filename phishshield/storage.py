"""SQLite persistence for scan history and awareness-quiz results.

Only a short preview of scanned content is stored, never the full message,
so the history doesn't become a store of users' private data.
"""
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta

from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    channel TEXT NOT NULL,
    verdict TEXT NOT NULL,
    risk_score REAL,
    preview TEXT,
    flags TEXT
);
CREATE TABLE IF NOT EXISTS quiz_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    nickname TEXT,
    score INTEGER NOT NULL,
    total INTEGER NOT NULL
);
"""


def connect(path=None):
    path = path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def log_scan(result: dict, preview: str, path=None):
    with closing(connect(path)) as c, c:
        c.execute("INSERT INTO scans (ts, channel, verdict, risk_score, preview, flags) VALUES (?,?,?,?,?,?)", (
            datetime.now().isoformat(timespec="seconds"), result["channel"], result["verdict"],
            result.get("risk_score"), (preview or "")[:120],
            json.dumps([f["title"] for f in result.get("red_flags", [])])))


def log_quiz(nickname: str, score: int, total: int, path=None):
    with closing(connect(path)) as c, c:
        c.execute("INSERT INTO quiz_attempts (ts, nickname, score, total) VALUES (?,?,?,?)", (
            datetime.now().isoformat(timespec="seconds"), (nickname or "Anonymous")[:30], score, total))


def stats(path=None) -> dict:
    with closing(connect(path)) as c:
        total = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        by_verdict = {r["verdict"]: r["n"] for r in
                      c.execute("SELECT verdict, COUNT(*) n FROM scans GROUP BY verdict")}
        by_channel = {}
        for r in c.execute("SELECT channel, verdict, COUNT(*) n FROM scans GROUP BY channel, verdict"):
            by_channel.setdefault(r["channel"], {})[r["verdict"]] = r["n"]
        since = (datetime.now() - timedelta(days=13)).date().isoformat()
        daily_rows = {r["d"]: r["n"] for r in c.execute(
            "SELECT substr(ts,1,10) d, COUNT(*) n FROM scans WHERE ts >= ? GROUP BY d", (since,))}
        daily = [{"date": (datetime.now() - timedelta(days=i)).date().isoformat()} for i in range(13, -1, -1)]
        for d in daily:
            d["count"] = daily_rows.get(d["date"], 0)
        flag_counts = {}
        for r in c.execute("SELECT flags FROM scans"):
            for f in json.loads(r["flags"] or "[]"):
                flag_counts[f] = flag_counts.get(f, 0) + 1
        top_flags = sorted(flag_counts.items(), key=lambda kv: -kv[1])[:8]
        recent = [dict(r) for r in c.execute(
            "SELECT ts, channel, verdict, risk_score, preview FROM scans ORDER BY id DESC LIMIT 10")]
        quiz = c.execute("SELECT COUNT(*) n, AVG(100.0*score/total) avg FROM quiz_attempts").fetchone()
        leaderboard = [dict(r) for r in c.execute(
            "SELECT nickname, score, total, ts FROM quiz_attempts ORDER BY 1.0*score/total DESC, ts ASC LIMIT 10")]
    return {
        "total_scans": total,
        "threats_blocked": by_verdict.get("phishing", 0),
        "by_verdict": by_verdict,
        "by_channel": by_channel,
        "daily": daily,
        "top_flags": [{"flag": k, "count": v} for k, v in top_flags],
        "recent": recent,
        "quiz_attempts": quiz["n"],
        "quiz_avg": round(quiz["avg"] or 0, 1),
        "leaderboard": leaderboard,
    }
