import sqlite3
from pathlib import Path
from typing import Iterable

from app.config import get_settings


SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    ip_address TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    vendor TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown',
    location TEXT NOT NULL DEFAULT 'Main Site',
    source TEXT NOT NULL DEFAULT 'simulated'
);

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    packet_loss REAL NOT NULL,
    cpu_usage REAL NOT NULL,
    memory_usage REAL NOT NULL,
    traffic_in_mbps REAL NOT NULL,
    traffic_out_mbps REAL NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_device_id INTEGER NOT NULL,
    target_device_id INTEGER NOT NULL,
    link_type TEXT NOT NULL DEFAULT 'ethernet',
    FOREIGN KEY(source_device_id) REFERENCES devices(id),
    FOREIGN KEY(target_device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    is_active INTEGER NOT NULL DEFAULT 1,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    csrf_token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
"""


SEED_DEVICES = [
    ("Core Router", "192.168.1.1", "router", "Cisco", "Main Site"),
    ("Distribution Switch", "192.168.1.2", "switch", "Cisco", "Main Site"),
    ("Firewall", "192.168.1.254", "firewall", "Fortinet", "Edge"),
    ("App Server", "192.168.1.20", "server", "Linux", "Server Room"),
    ("Database Server", "192.168.1.30", "server", "Linux", "Server Room"),
]


def connect() -> sqlite3.Connection:
    db_path = Path(get_settings().db_path)
    if db_path.parent != Path("."):
        db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA busy_timeout=30000")
    if get_settings().app_env == "production":
        current_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        if current_mode.lower() != "wal":
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    else:
        current_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        if current_mode.lower() != "off":
            conn.execute("PRAGMA journal_mode=OFF")
        conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
        if "source" not in columns:
            conn.execute(
                "ALTER TABLE devices ADD COLUMN source TEXT NOT NULL DEFAULT 'simulated'"
            )
        user_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()
        }
        if "must_change_password" not in user_columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"
            )
        count = conn.execute("SELECT COUNT(*) AS total FROM devices").fetchone()["total"]
        if count == 0:
            conn.executemany(
                "INSERT INTO devices (name, ip_address, role, vendor, location) VALUES (?, ?, ?, ?, ?)",
                SEED_DEVICES,
            )
            rows = conn.execute("SELECT id, role FROM devices ORDER BY id").fetchall()
            ids = [row["id"] for row in rows]
            conn.executemany(
                "INSERT INTO links (source_device_id, target_device_id) VALUES (?, ?)",
                [(ids[0], ids[1]), (ids[1], ids[3]), (ids[1], ids[4]), (ids[2], ids[0])],
            )


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict]:
    return [dict(row) for row in rows]
