"""Immutable scan snapshots and separately refreshable advisory cache."""
import json
import sqlite3
from pathlib import Path

from .manifest import InputError


def connect(path):
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout = 10000")
    return db


def initialise(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                report TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS advisory_cache (
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                retrieved_at TEXT NOT NULL,
                source TEXT NOT NULL,
                response TEXT NOT NULL,
                PRIMARY KEY(package, version)
            );
        """)


def cached(db, name, version):
    row = db.execute("SELECT * FROM advisory_cache WHERE package=? AND version=?",
                     (name, version)).fetchone()
    if not row:
        return None
    value = dict(row)
    value["response"] = json.loads(value["response"])
    return value


def save_cache(db, name, version, retrieved, response, source="OSV live cache"):
    db.execute("""INSERT INTO advisory_cache VALUES (?,?,?,?,?)
        ON CONFLICT(package,version) DO UPDATE SET retrieved_at=excluded.retrieved_at,
        source=excluded.source,response=excluded.response""",
        (name, version, retrieved, source, json.dumps(response)))


def save_scan(db, report):
    cursor = db.execute("""INSERT INTO scans
        SELECT ?,?,?,? WHERE (SELECT COUNT(*) FROM scans) < 200""",
        (report["id"], report["name"], report["created_at"], json.dumps(report)))
    if cursor.rowcount != 1:
        raise InputError("This local demo supports 200 immutable scans per data directory.")


def get_scan(db, scan_id):
    row = db.execute("SELECT report FROM scans WHERE id=?", (scan_id,)).fetchone()
    if row is None:
        raise LookupError("The requested scan does not exist.")
    return json.loads(row["report"])


def list_scans(db):
    rows = db.execute("SELECT report FROM scans ORDER BY created_at DESC, rowid DESC LIMIT 50").fetchall()
    return [json.loads(row["report"]) for row in rows]
