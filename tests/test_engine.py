import time

from config import DEFAULT_SETTINGS
from core import Engine
from database.db import Database
from hub import Hub
from risk.scoring import RiskEngine


def make_engine(tmp_path):
    return Engine(Database(tmp_path / "t.sqlite3"), Hub())


def test_risk_levels_and_bonus():
    r = RiskEngine(lambda: DEFAULT_SETTINGS)
    assert [r.level(x) for x in (0, 29, 30, 59, 60, 79, 80, 100)] == ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]

    class S:
        def __init__(self, k): self.kind = k
    one, _ = r.score([S("port_scan")])
    two, comps = r.score([S("port_scan"), S("unusual_path")])
    assert one == 30 and two == 30 + 12 + 6 and comps["_correlation_bonus"] == 6
    assert r.score([S("port_scan")] * 10)[0] == 30       # repeats of one kind do not stack


def test_correlated_incident_process_network_file(tmp_path):
    e = make_engine(tmp_path)
    e._on_process_created({"pid": 501, "ppid": 4, "name": "x.exe", "exe": r"C:\Users\a\AppData\Local\Temp\x.exe", "user": "a", "parent_name": "explorer.exe"})
    assert e.corr.open_incidents() == []                 # unusual path alone: no incident
    e._on_new_external({"pid": 501, "process": "x.exe", "local": "10.0.0.5:5000", "remote": "8.8.4.4:443", "proto": "TCP"})
    inc = e.corr.open_incidents()
    assert inc and inc[0]["severity"] == "MEDIUM"        # two signal types
    e._on_fim({"ts": time.time(), "path": r"C:\docs\a.docx", "action": "MODIFIED", "old_hash": "a", "new_hash": "b",
               "hash_status": "CHANGED", "risk": "LOW", "is_demo": 0}, 1)
    e.emit_alert(severity="MEDIUM", category="Abnormal Traffic", source=None, kind="network_anomaly", description="spike")
    inc = e.corr.open_incidents()[0]
    assert inc["severity"] == "HIGH" and inc["risk_score"] >= 60
    kinds = {t["kind"] for t in inc["timeline"]}
    assert {"unusual_path", "external_connection", "file_modification", "network_anomaly"} <= kinds
    assert inc["summary"]["process"] == "x.exe" and "application-defined" in inc["reason"].lower()
    assert e.db.query("SELECT * FROM alerts WHERE category='Correlated Incident'")


def test_benign_external_connection_creates_no_incident(tmp_path):
    e = make_engine(tmp_path)
    e._on_process_created({"pid": 7, "ppid": 4, "name": "chrome.exe", "exe": r"C:\Program Files\Google\Chrome\chrome.exe", "user": "a", "parent_name": "explorer.exe"})
    e._on_new_external({"pid": 7, "process": "chrome.exe", "local": "10.0.0.5:5000", "remote": "142.250.1.1:443", "proto": "TCP"})
    assert e.corr.open_incidents() == [] and e.db.query("SELECT * FROM alerts") == []


def test_demo_data_is_flagged_and_isolated(tmp_path):
    from demo.simulator import DemoSimulator
    e = make_engine(tmp_path)
    sim = DemoSimulator(e)
    sim._sleep = lambda s: True
    sim.scenario()
    alerts = e.db.query("SELECT * FROM alerts")
    assert alerts and all(a["is_demo"] == 1 and "[DEMO/SIMULATION]" in a["description"] for a in alerts)
    assert e.corr.open_incidents() and all(i["is_demo"] for i in e.corr.open_incidents())
    e.db.purge_demo()
    assert e.db.query("SELECT * FROM alerts") == []


def test_alert_cooldown(tmp_path):
    e = make_engine(tmp_path)
    for _ in range(5):
        e.emit_alert(severity="LOW", category="X", source="s", description="same", kind="network_anomaly")
    assert len(e.db.query("SELECT * FROM alerts")) == 1


def test_incident_score_components_survive_a_restart(tmp_path):
    """components used to live only in engine.corr.incidents, so every historical incident lost its breakdown."""
    from api import create_app
    from fastapi.testclient import TestClient
    e = make_engine(tmp_path)
    e._on_process_created({"pid": 501, "ppid": 4, "name": "x.exe", "exe": r"C:\Users\a\AppData\Local\Temp\x.exe",
                           "user": "a", "parent_name": "explorer.exe"})
    e._on_new_external({"pid": 501, "process": "x.exe", "local": "10.0.0.5:5000", "remote": "8.8.4.4:443", "proto": "TCP"})
    inc = e.corr.open_incidents()[0]
    assert inc["components"], "the live incident should carry its score components"

    e.corr.tick(inc["updated_ts"] + 10_000)          # idle timeout closes it and drops it from memory
    assert inc["id"] not in e.corr.incidents

    restarted = Engine(Database(tmp_path / "t.sqlite3"), Hub())   # same file, empty in-memory state
    app = create_app(restarted, restarted.hub, token=None)
    with TestClient(app) as c:
        detail = c.get(f"/api/incidents/{inc['id']}").json()
    assert detail["components"] == inc["components"]
    assert detail["timeline"] and detail["reason"]


def test_risk_history_is_written_on_elapsed_time_not_the_wall_clock(tmp_path):
    e = make_engine(tmp_path)
    e.tick(); e.tick(); e.tick()                     # three ticks within 30 s must not spam risk_scores
    assert len(e.db.query("SELECT * FROM risk_scores")) == 1
    e._last_risk_save -= 31
    e.tick()
    assert len(e.db.query("SELECT * FROM risk_scores")) == 2


def test_recent_alerts_backlog_hides_demo_data_when_demo_is_off(tmp_path):
    e = make_engine(tmp_path)
    e.emit_alert(severity="HIGH", category="Port Scan", source="9.9.9.9", description="real")
    e.emit_alert(severity="HIGH", category="Port Scan", source="9.9.9.9", description="fake", demo=True)
    assert [a["description"] for a in e.recent_alerts()] == ["real"]
    assert len(e.db.search("alerts", {}, include_demo=True)) == 2
