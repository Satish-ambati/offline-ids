"""SQLite storage. Everything is stored locally; passwords and command lines are never stored."""
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger("database")

SCHEMA = """
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, severity TEXT, category TEXT,
  event_type TEXT, source TEXT, process TEXT, message TEXT, details TEXT, is_demo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS network_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, src_ip TEXT, dst_ip TEXT, src_port INTEGER,
  dst_port INTEGER, protocol TEXT, direction TEXT, packets INTEGER, bytes INTEGER, flags TEXT,
  pid INTEGER, process TEXT, is_demo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS host_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, event_id INTEGER, channel TEXT, event_type TEXT,
  user TEXT, source_ip TEXT, message TEXT, is_demo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS process_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, action TEXT, pid INTEGER, ppid INTEGER, name TEXT,
  exe TEXT, username TEXT, parent_name TEXT, reasons TEXT, is_demo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS file_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, path TEXT, action TEXT, old_hash TEXT, new_hash TEXT,
  hash_status TEXT, risk TEXT, is_demo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS service_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, name TEXT, display_name TEXT, action TEXT,
  old_state TEXT, new_state TEXT, start_type TEXT, binary_path TEXT, is_demo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, severity TEXT, category TEXT, source TEXT,
  description TEXT, risk_score INTEGER, incident_id TEXT, acknowledged INTEGER DEFAULT 0, details TEXT,
  is_demo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, opened_ts REAL, updated_ts REAL, severity TEXT, category TEXT, title TEXT, key TEXT,
  risk_score INTEGER, status TEXT, reason TEXT, summary TEXT, timeline TEXT, components TEXT,
  is_demo INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS risk_scores (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, score INTEGER, level TEXT, components TEXT);
CREATE TABLE IF NOT EXISTS fim_folders (path TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS fim_baseline (path TEXT PRIMARY KEY, hash TEXT, size INTEGER, mtime REAL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS ix_sec_ts ON security_events(ts);
CREATE INDEX IF NOT EXISTS ix_alert_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS ix_net_ts ON network_events(ts);
CREATE INDEX IF NOT EXISTS ix_host_ts ON host_events(ts);
CREATE INDEX IF NOT EXISTS ix_proc_ts ON process_events(ts);
CREATE INDEX IF NOT EXISTS ix_file_ts ON file_events(ts);
"""

# Filter name -> columns it applies to (whitelist prevents SQL injection through column names)
SEARCH_MAP = {
    "security_events": dict(severity=["severity"], category=["category"], source=["source"], process=["process"],
                            event_type=["event_type"], q=["message", "category", "source", "process"]),
    "network_events": dict(source=["src_ip", "dst_ip"], process=["process"], event_type=["protocol"],
                           q=["src_ip", "dst_ip", "process", "protocol"]),
    "host_events": dict(source=["source_ip"], event_type=["event_type"], q=["message", "user", "source_ip"]),
    "process_events": dict(process=["name", "exe"], event_type=["action"], q=["name", "exe", "username", "parent_name"]),
    "file_events": dict(severity=["risk"], event_type=["action"], q=["path"]),
    "service_events": dict(event_type=["action"], process=["name"], q=["name", "display_name", "binary_path"]),
    "alerts": dict(severity=["severity"], category=["category"], source=["source"],
                   q=["description", "category", "source"]),
    "incidents": dict(severity=["severity"], category=["category"], q=["title", "reason", "summary"]),
}


# Every table the app is allowed to write to.
TABLES = frozenset({
    "security_events", "network_events", "host_events", "process_events", "file_events", "service_events",
    "alerts", "incidents", "risk_scores", "fim_folders", "fim_baseline", "settings",
})


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._cols: dict[str, frozenset[str]] = {}
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.executescript(SCHEMA)
            self.conn.commit()
            self._load_columns()
            self._migrate()

    # -- schema introspection ------------------------------------------
    def _load_columns(self) -> None:
        """Cache the real column names; SQLite cannot bind identifiers, so writes are validated against these."""
        self._cols = {}
        for t in TABLES:
            self._cols[t] = frozenset(r["name"] for r in self.conn.execute(f"PRAGMA table_info({t})"))

    def _migrate(self) -> None:
        """Add columns introduced after a database was first created (CREATE TABLE IF NOT EXISTS never alters)."""
        for table, ddl in (("incidents", "components TEXT"),):
            col = ddl.split()[0]
            if col not in self._cols.get(table, frozenset()):
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
                log.info("migrated %s: added column %s", table, col)
        self.conn.commit()
        self._load_columns()

    def _target(self, table: str, cols: list[str]) -> list[str]:
        if table not in TABLES:
            raise ValueError(f"refusing to write to unknown table {table!r}")
        bad = [c for c in cols if c not in self._cols.get(table, frozenset())]
        if bad:
            raise ValueError(f"refusing to write unknown column(s) {bad} to {table}")
        return cols

    # -- statements ----------------------------------------------------
    def execute(self, sql: str, params: Iterable = ()) -> int:
        with self.lock:
            cur = self.conn.execute(sql, tuple(params))
            self.conn.commit()
            return cur.lastrowid

    def update(self, sql: str, params: Iterable = ()) -> int:
        """Run an UPDATE/DELETE and return the number of rows matched (0 = nothing matched)."""
        with self.lock:
            cur = self.conn.execute(sql, tuple(params))
            self.conn.commit()
            return cur.rowcount

    def query(self, sql: str, params: Iterable = ()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, tuple(params)).fetchall()]

    def one(self, sql: str, params: Iterable = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def insert(self, table: str, row: dict) -> int:
        cols = self._target(table, list(row))
        sql = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
        return self.execute(sql, [self._enc(row[c]) for c in cols])

    def insert_many(self, table: str, rows: list[dict]) -> None:
        if not rows:
            return
        cols = self._target(table, list(rows[0]))
        sql = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
        with self.lock:
            self.conn.executemany(sql, [[self._enc(r.get(c)) for c in cols] for r in rows])
            self.conn.commit()

    def upsert(self, table: str, row: dict) -> None:
        cols = self._target(table, list(row))
        sql = f"INSERT OR REPLACE INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
        self.execute(sql, [self._enc(row[c]) for c in cols])

    @staticmethod
    def _enc(v: Any) -> Any:
        return json.dumps(v) if isinstance(v, (dict, list)) else v

    def search(self, table: str, filters: dict, limit: int = 200, offset: int = 0, include_demo: bool = True) -> list[dict]:
        if table not in SEARCH_MAP:
            raise ValueError(f"unknown table {table}")
        m = SEARCH_MAP[table]
        unsupported = sorted(set(filters) - set(m) - {"since", "until"})
        if unsupported:
            raise ValueError(f"filter(s) {', '.join(unsupported)} are not supported for {table}; "
                             f"supported: {', '.join(sorted(set(m) | {'since', 'until'}))}")
        tscol = "updated_ts" if table == "incidents" else "ts"
        where, params = [], []
        if filters.get("since"):
            where.append(f"{tscol} >= ?"); params.append(float(filters["since"]))
        if filters.get("until"):
            where.append(f"{tscol} <= ?"); params.append(float(filters["until"]))
        for name in ("severity", "category", "source", "process", "event_type"):
            val, cols = filters.get(name), m.get(name, [])
            if val and cols:
                where.append("(" + " OR ".join(f"{c} LIKE ?" for c in cols) + ")")
                params += [f"%{val}%"] * len(cols)
        if filters.get("q") and m.get("q"):
            where.append("(" + " OR ".join(f"{c} LIKE ?" for c in m["q"]) + ")")
            params += [f"%{filters['q']}%"] * len(m["q"])
        if not include_demo:
            where.append("is_demo = 0")
        sql = f"SELECT * FROM {table}" + (" WHERE " + " AND ".join(where) if where else "")
        sql += f" ORDER BY {tscol} DESC LIMIT ? OFFSET ?"
        return self.query(sql, params + [min(int(limit), 2000), int(offset)])

    def load_settings(self) -> dict:
        return {r["key"]: json.loads(r["value"]) for r in self.query("SELECT key,value FROM settings")}

    def save_setting(self, key: str, value: Any) -> None:
        self.upsert("settings", {"key": key, "value": json.dumps(value)})

    def purge_older_than(self, days: int) -> None:
        cutoff = time.time() - days * 86400
        for t in ("security_events", "network_events", "host_events", "process_events", "file_events",
                  "service_events", "alerts", "risk_scores"):
            self.execute(f"DELETE FROM {t} WHERE ts < ?", (cutoff,))

    def clear_alerts(self, include_demo: bool = False) -> int:
        """Delete stored alerts. Mirrors search(): demo rows survive while demo mode is off. Returns rows removed."""
        sql = "DELETE FROM alerts" if include_demo else "DELETE FROM alerts WHERE is_demo = 0"
        return self.update(sql)

    def purge_demo(self) -> None:
        for t in ("security_events", "network_events", "host_events", "process_events", "file_events",
                  "service_events", "alerts", "incidents"):
            self.execute(f"DELETE FROM {t} WHERE is_demo = 1")
