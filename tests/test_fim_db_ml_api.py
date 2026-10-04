import os
import sqlite3
import time

import numpy as np
import pytest
from fastapi.testclient import TestClient

from api import create_app
from config import DEFAULT_SETTINGS
from core import Engine
from database.db import Database
from filesystem.fim import FileIntegrityMonitor, classify, sha256_file
from hub import Hub
from ml.detector import FEATURES, MLDetector


def test_fim_hash_and_change_detection(tmp_path):
    db = Database(tmp_path / "f.sqlite3")
    events = []
    fim = FileIntegrityMonitor(db, lambda ev, n: events.append(ev), lambda: DEFAULT_SETTINGS)
    watched = tmp_path / "w"; watched.mkdir()
    f = watched / "tool.exe"; f.write_bytes(b"v1")
    (watched / "notes.txt").write_text("hello")
    db.upsert("fim_folders", {"path": str(watched)})
    fim.build_baseline()
    assert db.one("SELECT hash FROM fim_baseline WHERE path=?", (str(f),))["hash"] == sha256_file(str(f))
    fim.process_change("modified", str(f))                    # identical content -> no event
    assert events == []
    f.write_bytes(b"v2")
    fim.process_change("modified", str(f))
    assert events[-1]["hash_status"] == "CHANGED" and events[-1]["risk"] == "HIGH"
    (watched / "notes.txt").write_text("changed")
    fim.process_change("modified", str(watched / "notes.txt"))
    assert events[-1]["risk"] == "LOW"                         # ordinary document edits are not treated as malicious
    fim.process_change("created", str(watched / "new.txt"))    # missing file -> ignored
    os.remove(f)
    fim.process_change("deleted", str(f))
    assert events[-1]["hash_status"] == "REMOVED"
    assert classify("created", "a.exe", "NEW", False) == "MEDIUM"


def test_fim_watchdog_end_to_end(tmp_path):
    db = Database(tmp_path / "f.sqlite3")
    events = []
    fim = FileIntegrityMonitor(db, lambda ev, n: events.append(ev), lambda: DEFAULT_SETTINGS)
    w = tmp_path / "w"; w.mkdir()
    db.upsert("fim_folders", {"path": str(w)})
    fim.build_baseline(); fim.start(); time.sleep(0.5)
    (w / "dropped.exe").write_bytes(b"MZ")
    for _ in range(40):
        if events: break
        time.sleep(0.25)
    fim.stop()
    assert events and events[0]["action"] == "CREATED" and events[0]["risk"] == "MEDIUM"


def test_fim_remove_folder_keeps_a_sibling_sharing_its_prefix(tmp_path):
    db = Database(tmp_path / "f.sqlite3")
    fim = FileIntegrityMonitor(db, lambda ev, n: None, lambda: DEFAULT_SETTINGS)
    data, database = tmp_path / "Data", tmp_path / "Database"
    data.mkdir(); database.mkdir()
    (data / "a.txt").write_text("a")
    (database / "b.txt").write_text("b")
    db.upsert("fim_folders", {"path": str(data)})
    db.upsert("fim_folders", {"path": str(database)})
    fim.build_baseline()
    fim.remove_folder(str(data))
    paths = {r["path"] for r in db.query("SELECT path FROM fim_baseline")}
    assert paths == {str(database / "b.txt")}


def test_fim_rename_keeps_the_baseline_so_it_is_not_reported_as_new(tmp_path):
    db = Database(tmp_path / "f.sqlite3")
    events = []
    fim = FileIntegrityMonitor(db, lambda ev, n: events.append(ev), lambda: DEFAULT_SETTINGS)
    w = tmp_path / "w"; w.mkdir()
    src, dest = w / "tool.exe", w / "moved.exe"
    src.write_bytes(b"original")
    sha256_file_before = sha256_file(str(src))
    db.upsert("fim_folders", {"path": str(w)})
    fim.build_baseline()

    os.replace(src, dest)                      # moved...
    dest.write_bytes(b"tampered")              # ...and altered
    fim.process_change("renamed", str(dest), old_path=str(src))
    assert events[-1]["hash_status"] == "CHANGED" and events[-1]["risk"] == "HIGH"
    assert events[-1]["old_hash"] == sha256_file_before
    assert db.one("SELECT hash FROM fim_baseline WHERE path=?", (str(src),)) is None
    assert db.one("SELECT hash FROM fim_baseline WHERE path=?", (str(dest),))["hash"] == sha256_file(str(dest))

    events.clear()
    other = w / "clean.exe"; other.write_bytes(b"same")
    fim.build_baseline()
    os.replace(other, w / "renamed2.exe")          # a pure move is not an integrity event
    assert fim.process_change("renamed", str(w / "renamed2.exe"), old_path=str(other)) is None
    assert events == []
    assert db.one("SELECT hash FROM fim_baseline WHERE path=?", (str(w / "renamed2.exe"),)) is not None


def test_fim_a_move_is_one_event_and_survives_a_later_modify(tmp_path):
    """watchdog delivers the move and then a modify for the same destination; letting the modify win loses the
    link back to the baseline and the file is misreported as newly created."""
    from filesystem.fim import _Handler
    db = Database(tmp_path / "f.sqlite3")
    fim = FileIntegrityMonitor(db, lambda ev, n: None, lambda: DEFAULT_SETTINGS)
    src, dest = str(tmp_path / "old.exe"), str(tmp_path / "new.exe")

    e = type("Ev", (), {"is_directory": False, "src_path": src, "dest_path": dest})()
    _Handler(fim).on_moved(e)
    assert list(fim.pending) == [dest], "a move is not a delete plus a create"
    assert fim.pending[dest] == ("renamed", fim.pending[dest][1], src)

    fim.queue_change("modified", dest)          # the file is edited right after the move
    assert fim.pending[dest][0] == "renamed" and fim.pending[dest][2] == src

    fim.queue_change("modified", str(tmp_path / "unrelated.exe"))
    assert fim.pending[str(tmp_path / "unrelated.exe")][0] == "modified"


def test_database_search_and_filters(tmp_path):
    db = Database(tmp_path / "d.sqlite3")
    now = time.time()
    for i, sev in enumerate(["LOW", "HIGH", "HIGH"]):
        db.insert("alerts", {"ts": now - i, "severity": sev, "category": "Port Scan", "source": f"1.1.1.{i}", "description": "d", "is_demo": 0})
    assert len(db.search("alerts", {"severity": "HIGH"})) == 2
    assert len(db.search("alerts", {"source": "1.1.1.0"})) == 1
    assert len(db.search("alerts", {"since": now - 0.5})) == 1
    assert db.search("alerts", {"q": "'; DROP TABLE alerts;--"}) == [] and db.query("SELECT COUNT(*) n FROM alerts")[0]["n"] == 3
    # a filter the table cannot answer must fail loudly rather than silently returning unfiltered rows
    with pytest.raises(ValueError, match="not supported"):
        db.search("alerts", {"process": "chrome"})
    with pytest.raises(ValueError, match="not supported"):
        db.search("alerts", {"colour": "red"})


def test_database_refuses_unknown_tables_and_columns(tmp_path):
    db = Database(tmp_path / "d.sqlite3")
    with pytest.raises(ValueError, match="unknown table"):
        db.insert("alerts; DROP TABLE alerts", {"ts": 1})
    with pytest.raises(ValueError, match="unknown column"):
        db.insert("alerts", {"ts": 1, "acknowledged) VALUES (1)--": 1})
    assert db.query("SELECT COUNT(*) n FROM alerts")[0]["n"] == 0


def test_migrates_an_existing_database_missing_the_components_column(tmp_path):
    legacy = tmp_path / "old.sqlite3"
    with sqlite3.connect(legacy) as conn:
        conn.executescript("CREATE TABLE incidents (id TEXT PRIMARY KEY, opened_ts REAL, updated_ts REAL, "
                           "severity TEXT, category TEXT, title TEXT, key TEXT, risk_score INTEGER, status TEXT, "
                           "reason TEXT, summary TEXT, timeline TEXT, is_demo INTEGER DEFAULT 0)")
        conn.execute("INSERT INTO incidents (id, status) VALUES ('INC-1','closed')")
    db = Database(legacy)
    assert "components" in db._cols["incidents"]
    row = {"id": "INC-1", "opened_ts": 1.0, "updated_ts": 2.0, "severity": "LOW", "category": "c", "title": "t",
           "key": "host", "risk_score": 0, "status": "closed", "reason": "r", "is_demo": 0}
    db.upsert("incidents", {**row, "components": {"port_scan": 30}})
    assert db.one("SELECT components FROM incidents WHERE id='INC-1'")["components"] == '{"port_scan": 30}'


def test_ml_isolation_forest_learns_and_flags_outlier(tmp_path):
    cfg = {"ml": {**DEFAULT_SETTINGS["ml"], "min_train_windows": 80, "persist_windows": 1}}
    ml = MLDetector(tmp_path, lambda: cfg)
    rng = np.random.default_rng(0)
    base = lambda: {k: abs(rng.normal(50, 5)) for k in FEATURES}
    for _ in range(80):
        ml.score(base())
    assert ml.iso is not None
    assert not ml.score(base())["anomaly"]
    out = ml.score({k: 5000.0 for k in FEATURES})
    assert out["anomaly"] and out["score"] > 0.9
    assert MLDetector(tmp_path, lambda: cfg).iso is not None    # persisted to disk


def test_ml_supervised_rf(tmp_path):
    import pandas as pd
    rng = np.random.default_rng(1)
    rows = []
    for y in (0, 1):
        for _ in range(100):
            r = {k: abs(rng.normal(10 + 90 * y, 5)) for k in FEATURES}; r["label"] = y; rows.append(r)
    pd.DataFrame(rows).to_csv(tmp_path / "l.csv", index=False)
    ml = MLDetector(tmp_path, lambda: {"ml": DEFAULT_SETTINGS["ml"]})
    assert ml.train_supervised(str(tmp_path / "l.csv"))["report"]["accuracy"] > 0.9


def test_api_auth_settings_reports_and_demo(tmp_path):
    engine = Engine(Database(tmp_path / "a.sqlite3"), Hub())
    app = create_app(engine, engine.hub, token="secret")
    with TestClient(app) as c:
        assert c.get("/api/health").json()["ok"]
        assert c.get("/api/status").status_code == 401
        h = {"X-Engine-Token": "secret"}
        assert c.get("/api/status", headers=h).json()["running"] is False
        assert c.put("/api/settings", headers=h, json={"animations": "off"}).json()["animations"] == "off"
        engine.emit_alert(severity="HIGH", category="Port Scan", source="9.9.9.9", kind="port_scan", description="test")
        assert c.get("/api/events/alerts?severity=HIGH", headers=h).json()[0]["source"] == "9.9.9.9"
        assert c.get("/api/events/nope", headers=h).status_code == 404
        name = c.post("/api/reports", headers=h, json={"hours": 1}).json()["name"]
        r = c.get(f"/api/reports/{name}", headers=h)
        assert r.status_code == 200 and r.content.startswith(b"%PDF")
        assert c.get("/api/live/processes", headers=h).json()
        with c.websocket_connect("/ws?token=secret") as ws:
            hello = ws.receive_json()
            assert hello["type"] == "hello"


def test_api_rejects_unsupported_filters_and_unknown_acks(tmp_path):
    engine = Engine(Database(tmp_path / "a.sqlite3"), Hub())
    with TestClient(create_app(engine, engine.hub, token="secret")) as c:
        h = {"X-Engine-Token": "secret"}
        r = c.get("/api/events/alerts?process=chrome", headers=h)
        assert r.status_code == 400 and "not supported" in r.json()["detail"]
        assert c.post("/api/alerts/424242/ack", headers=h).status_code == 404
        a = engine.emit_alert(severity="HIGH", category="Port Scan", source="9.9.9.9", description="x")
        assert c.post(f"/api/alerts/{a['id']}/ack", headers=h).json() == {"ok": True}


def test_clearing_alerts_respects_demo_visibility_and_spares_other_history(tmp_path):
    engine = Engine(Database(tmp_path / "a.sqlite3"), Hub())
    engine.emit_alert(severity="HIGH", category="Port Scan", source="9.9.9.9", description="real")
    engine.emit_alert(severity="HIGH", category="Port Scan", source="9.9.9.9", description="sim", demo=True)
    engine.db.insert("security_events", {"ts": 1.0, "message": "kept"})
    engine.db.insert("incidents", {"id": "INC-K", "opened_ts": 1.0, "updated_ts": 1.0, "status": "open"})
    with TestClient(create_app(engine, engine.hub, token="secret")) as c:
        h = {"X-Engine-Token": "secret"}
        assert c.post("/api/alerts/clear", headers=h).json() == {"ok": True, "removed": 1}
        # demo mode is off, so the simulated row stays hidden but is not destroyed
        assert c.get("/api/events/alerts", headers=h).json() == []
        assert engine.db.one("SELECT COUNT(*) n FROM alerts")["n"] == 1
        # only alerts are cleared: incidents, security events and risk history are untouched
        assert engine.db.one("SELECT COUNT(*) n FROM incidents")["n"] == 1
        # security_events keeps its own copy of every alert, so it still holds all 3 rows
        assert engine.db.one("SELECT COUNT(*) n FROM security_events")["n"] == 3
        # with demo running the simulated row is visible, and therefore clearable
        engine.demo = True
        assert c.post("/api/alerts/clear", headers=h).json()["removed"] == 1
        assert engine.db.one("SELECT COUNT(*) n FROM alerts")["n"] == 0


def test_api_survives_a_corrupt_json_column(tmp_path):
    engine = Engine(Database(tmp_path / "a.sqlite3"), Hub())
    engine.db.execute("INSERT INTO incidents (id, status, summary, timeline) VALUES ('INC-X','closed','{not json','[1,')")
    with TestClient(create_app(engine, engine.hub, token=None)) as c:
        r = c.get("/api/incidents/INC-X")
    assert r.status_code == 200
    assert r.json()["summary"] is None and r.json()["timeline"] is None and r.json()["components"] is None


def test_websocket_hello_carries_the_alert_backlog_for_reconnects(tmp_path):
    engine = Engine(Database(tmp_path / "a.sqlite3"), Hub())
    a = engine.emit_alert(severity="HIGH", category="Port Scan", source="9.9.9.9", description="raised while offline")
    with TestClient(create_app(engine, engine.hub, token=None)) as c:
        with c.websocket_connect("/ws") as ws:
            hello = ws.receive_json()
    assert hello["type"] == "hello" and [x["id"] for x in hello["alerts"]] == [a["id"]]
    assert isinstance(hello["incidents"], list)
