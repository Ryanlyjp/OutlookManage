import sqlite3
from pathlib import Path

ACCOUNTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    client_id TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    status TEXT DEFAULT 'new',
    health_status TEXT DEFAULT '',
    health_severity TEXT DEFAULT '',
    ban_reason TEXT DEFAULT '',
    error_detail TEXT DEFAULT '',
    graph_status TEXT DEFAULT '',
    imap_status TEXT DEFAULT '',
    pop_status TEXT DEFAULT '',
    smtp_status TEXT DEFAULT '',
    registered_at TEXT DEFAULT '',
    registered_source TEXT DEFAULT '',
    last_alive_at TEXT DEFAULT '',
    last_refresh_at TEXT DEFAULT '',
    last_refresh_status TEXT DEFAULT '',
    last_refresh_error TEXT DEFAULT '',
    refresh_token_updated_at TEXT DEFAULT '',
    last_protocol_test_at TEXT DEFAULT '',
    remote_sync_status TEXT DEFAULT '',
    remote_sync_at TEXT DEFAULT '',
    remote_sync_error TEXT DEFAULT '',
    remote_last_refresh_at TEXT DEFAULT '',
    remote_last_refresh_status TEXT DEFAULT '',
    token_sync_status TEXT DEFAULT '',
    remote_id TEXT DEFAULT '',
    remark TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

HISTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    email TEXT DEFAULT '',
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_account ON history(account_id, id DESC);
"""

# 增量迁移：旧库缺失的列在此补齐（幂等）
MIGRATIONS = {
    "health_severity": "TEXT DEFAULT ''",
    "ban_reason": "TEXT DEFAULT ''",
    "error_detail": "TEXT DEFAULT ''",
    "remote_id": "TEXT DEFAULT ''",
    "remark": "TEXT DEFAULT ''",
    "recovery_status": "TEXT DEFAULT ''",
    "recovery_attempts": "INTEGER DEFAULT 0",
    "recovery_last_at": "TEXT DEFAULT ''",
    "recovery_last_reason": "TEXT DEFAULT ''",
    "recovery_last_temp_mail": "TEXT DEFAULT ''",
    "oauth_reauth_at": "TEXT DEFAULT ''",
    "oauth_reauth_status": "TEXT DEFAULT ''",
    "oauth_reauth_error": "TEXT DEFAULT ''",
    "registered_at": "TEXT DEFAULT ''",
    "registered_source": "TEXT DEFAULT ''",
    "last_alive_at": "TEXT DEFAULT ''",
    "refresh_token_updated_at": "TEXT DEFAULT ''",
    "remote_last_refresh_at": "TEXT DEFAULT ''",
    "remote_last_refresh_status": "TEXT DEFAULT ''",
    "token_sync_status": "TEXT DEFAULT ''",
}


def get_conn(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with get_conn(db_path) as conn:
        conn.executescript(ACCOUNTS_SCHEMA)
        conn.executescript(HISTORY_SCHEMA)
        existing = {row[1] for row in conn.execute("PRAGMA table_info(accounts)").fetchall()}
        for column, decl in MIGRATIONS.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE accounts ADD COLUMN {column} {decl}")
        conn.commit()


def add_history(conn: sqlite3.Connection, account_id: int, email: str, action: str, status: str, detail: str, ts: str) -> None:
    conn.execute(
        "INSERT INTO history (account_id, email, action, status, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (account_id, email, action, status, str(detail or "")[:2000], ts),
    )
