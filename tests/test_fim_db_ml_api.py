import os
import time

import numpy as np
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


def test_database_search_and_filters(tmp_path):
    db = Database(tmp_path / "d.sqlite3")
    now = time.time()
    for i, sev in enumerate(["LOW", "HIGH", "HIGH"]):
        db.insert("alerts", {"ts": now - i, "severity": sev, "category": "Port Scan", "source": f"1.1.1.{i}", "description": "d", "is_demo": 0})
    assert len(db.search("alerts", {"severity": "HIGH"})) == 2
    assert len(db.search("alerts", {"source": "1.1.1.0"})) == 1
    assert len(db.search("alerts", {"since": now - 0.5})) == 1
    assert db.search("alerts", {"q": "'; DROP TABLE alerts;--"}) == [] and db.query("SELECT COUNT(*) n FROM alerts")[0]["n"] == 3


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
            assert ws.receive_json()["type"] == "hello"
