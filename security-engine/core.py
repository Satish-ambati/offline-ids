"""Engine coordinator: wires monitors -> detectors -> correlation -> risk -> storage -> UI (via Hub)."""
import logging
import os
import platform
import threading
import time
from collections import Counter

import psutil

from config import DEFAULT_SETTINGS, MODELS_DIR, merge
from correlation.engine import CorrelationEngine, Signal
from detection.process_rules import assess_process
from detection.rules import (BruteForceDetector, Detection, PortScanDetector, SynFloodDetector, TrafficAnomalyDetector)
from filesystem.fim import FileIntegrityMonitor
from host import sysmetrics
from host.eventlog import EventLogMonitor
from host.services import ServiceMonitor
from ml.detector import MLDetector
from network.connections import ConnectionTracker
from network.flows import FlowAggregator
from network.sniffer import CaptureUnavailable, PacketSniffer
from process.monitor import ProcessMonitor
from risk.scoring import RiskEngine

log = logging.getLogger("core")
SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
UNUSUAL = ("\\appdata\\local\\temp\\", "\\temp\\", "\\downloads\\", "\\users\\public\\", "\\programdata\\")


def is_admin() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


class Engine:
    def __init__(self, db, hub):
        self.db, self.hub = db, hub
        self.settings = merge(DEFAULT_SETTINGS, db.load_settings())
        self.risk = RiskEngine(lambda: self.settings)
        self.corr = CorrelationEngine(db, self.risk, lambda: self.settings, self._on_incident, self._on_incident_change)
        self.flows = FlowAggregator()
        self.counters: Counter = Counter()
        self.ml = MLDetector(MODELS_DIR, lambda: self.settings)
        self.fim = FileIntegrityMonitor(db, self._on_fim, lambda: self.settings)
        self.tracker = ConnectionTracker(self._on_new_external)
        self.sniffer: PacketSniffer | None = None
        self.proc_mon: ProcessMonitor | None = None
        self.evlog: EventLogMonitor | None = None
        self.svc_mon: ServiceMonitor | None = None
        self.modules: dict[str, dict] = {n: {"state": "stopped", "detail": ""} for n in
                                          ("network", "connections", "process", "eventlog", "services", "filesystem", "ml")}
        self.running = False
        self.started_at = self.last_scan = None
        self.admin = is_admin()
        self.demo = None
        self.cooldowns: dict = {}
        self.latest_risk = {"score": 0, "level": "LOW", "components": {}}
        self.latest_sys = {"cpu": 0, "mem": 0, "latency_ms": 0}
        self._stop = threading.Event()
        self._build_detectors()

    # ------------------------------------------------------------------ settings
    def _build_detectors(self):
        t = self.settings["thresholds"]
        self.portscan = PortScanDetector(t["port_scan_window"], t["port_scan_unique_ports"])
        self.synflood = SynFloodDetector(t["syn_window"], t["syn_min_count"], t["syn_ratio"])
        self.brute = BruteForceDetector(t["brute_force_failures"], t["brute_force_window"])
        self.brute_demo = BruteForceDetector(t["brute_force_failures"], t["brute_force_window"])
        self.traffic = TrafficAnomalyDetector(t)

    def update_settings(self, patch: dict) -> dict:
        self.settings = merge(self.settings, patch)
        for k, v in self.settings.items():
            self.db.save_setting(k, v)
        self._build_detectors()
        return self.settings

    # ------------------------------------------------------------------ publishing helpers
    def publish(self, type_: str, **payload):
        self.hub.publish({"type": type_, **payload})

    def _demo_where(self, prefix="WHERE") -> str:
        return "" if self.demo else f" {prefix} is_demo=0"

    # ------------------------------------------------------------------ alerts
    def emit_alert(self, *, severity, category, source, description, kind=None, pid=None, details=None,
                   demo=False, feed=True, force=False, ts=None) -> dict | None:
        now = ts or time.time()
        ck = (category, source, pid, demo, description[:40])
        if not force and now - self.cooldowns.get(ck, 0) < self.settings["thresholds"]["alert_cooldown"]:
            return None
        self.cooldowns[ck] = now
        if demo:
            description = "[DEMO/SIMULATION] " + description
        incident = None
        if feed and kind:
            incident = self.corr.add_signal(Signal(kind, now, description, severity, pid, source, details or {}, demo))
        score = incident["risk_score"] if incident else self._standalone_score(kind)
        alert = {"ts": now, "severity": severity, "category": category, "source": source, "description": description,
                 "risk_score": score, "incident_id": incident["id"] if incident else None, "acknowledged": 0,
                 "details": details or {}, "is_demo": int(demo)}
        alert["id"] = self.db.insert("alerts", alert)
        self.db.insert("security_events", {"ts": now, "severity": severity, "category": category, "event_type": "alert",
                                           "source": source, "process": (details or {}).get("process"), "message": description,
                                           "details": details or {}, "is_demo": int(demo)})
        self.publish("alert", alert=alert)
        return alert

    def _standalone_score(self, kind) -> int:
        return int(self.risk.cfg["weights"].get(kind, 10)) if kind else 0

    def _on_incident(self, inc: dict, escalated: bool):
        demo = bool(inc.get("is_demo"))
        s = inc.get("summary") or {}
        self.emit_alert(severity=inc["severity"], category="Correlated Incident", source=s.get("source") or s.get("process"),
                        description=f"{inc['id']}: {inc['title']} — risk {inc['risk_score']}/100",
                        details={"incident_id": inc["id"], "process": s.get("process")}, demo=demo, feed=False, force=True)

    def _on_incident_change(self, inc: dict):
        self.publish("incident", incident=inc)

    def _det(self, d: Detection | None, pid=None, demo=False):
        if d:
            self.emit_alert(severity=d.severity, category=d.category, source=d.source, description=d.description,
                            kind=d.kind, pid=pid, details=d.details, demo=demo)

    # ------------------------------------------------------------------ network
    def _on_packet(self, p: dict):
        self.flows.add(p)
        self._det(self.portscan.feed(p))
        self._det(self.synflood.feed(p))

    def _on_new_external(self, row: dict, demo=False):
        self.counters["new_ext"] += 1
        host, _, port = row["remote"].rpartition(":")
        ev = {"ts": time.time(), "src_ip": row["local"].rpartition(":")[0], "dst_ip": host,
              "src_port": int(row["local"].rpartition(":")[2] or 0), "dst_port": int(port or 0), "protocol": row["proto"],
              "direction": "out", "packets": 0, "bytes": 0, "flags": "NEW_CONN", "pid": row["pid"],
              "process": row["process"], "is_demo": int(demo)}
        self.db.insert("network_events", ev)
        self.publish("event", table="network_events", row=ev)
        # only a process that already has other suspicious behaviour gets this connection attached
        self.corr.add_signal(Signal("external_connection", ev["ts"], f"{row['process'] or row['pid']} connected to {row['remote']}",
                                    "LOW", row["pid"], host, {"dst": row["remote"], "process": row["process"]}, demo),
                             only_if_group_exists=True)

    # ------------------------------------------------------------------ processes
    def _on_process_created(self, i: dict, demo=False):
        self.counters["proc_created"] += 1
        reasons = assess_process(i["name"], i["exe"], i.get("parent_name", ""))
        row = {"ts": time.time(), "action": "created", "pid": i["pid"], "ppid": i["ppid"], "name": i["name"], "exe": i["exe"],
               "username": i["user"], "parent_name": i.get("parent_name", ""), "reasons": [r["text"] for r in reasons],
               "is_demo": int(demo)}
        self.db.insert("process_events", row)
        self.publish("event", table="process_events", row=row)
        self.corr.note_process(i["pid"], {"name": i["name"], "exe": i["exe"], "user": i["user"]})
        for r in reasons:
            sig = Signal(r["kind"], row["ts"], f"{i['name']} (PID {i['pid']}): {r['text']}",
                         "MEDIUM", i["pid"], None, {"process": i["name"], "path": i["exe"]}, demo)
            if r["kind"] == "parent_child_anomaly":
                self.emit_alert(severity="MEDIUM", category="Suspicious Process", source=i["name"], description=sig.message,
                                kind=r["kind"], pid=i["pid"], details=sig.details, demo=demo)
            else:
                self.corr.add_signal(sig)      # quiet: an unusual path alone is common (installers, portable apps)

    def _on_process_terminated(self, i: dict):
        row = {"ts": time.time(), "action": "terminated", "pid": i["pid"], "ppid": i["ppid"], "name": i["name"], "exe": i["exe"],
               "username": i["user"], "parent_name": "", "reasons": [], "is_demo": 0}
        self.db.insert("process_events", row)
        self.publish("event", table="process_events", row=row)

    # ------------------------------------------------------------------ host logs & services
    def _on_eventlog(self, e: dict, demo=False):
        row = {"ts": e["ts"], "event_id": e["event_id"], "channel": e["channel"], "event_type": e["event_type"], "user": e["user"],
               "source_ip": e["source_ip"], "message": e["message"], "is_demo": int(demo)}
        self.db.insert("host_events", row)
        self.publish("event", table="host_events", row=row)
        et = e["event_type"]
        if et in ("logon_failure", "logon_success"):
            if et == "logon_failure":
                self.counters["failed_logins"] += 1
            self._det((self.brute_demo if demo else self.brute).feed({"ts": e["ts"], "success": et == "logon_success", "user": e["user"], "source_ip": e["source_ip"]}), demo=demo)
        elif et == "service_installed":
            sev = "HIGH" if any(m in (e.get("image") or "").lower() for m in UNUSUAL) else "MEDIUM"
            self.emit_alert(severity=sev, category="Service Change", source=e.get("service"), description=e["message"],
                            kind="service_change", details={"image": e.get("image")}, demo=demo)
        elif et == "audit_log_cleared":
            self.emit_alert(severity="HIGH", category="Audit Tampering", source=e["user"], description="Windows Security audit log was cleared",
                            kind="audit_tamper", demo=demo)
        elif et in ("account_created", "group_member_added"):
            self.emit_alert(severity="MEDIUM", category="Account Change", source=e["user"], description=e["message"],
                            kind="account_change", demo=demo)

    def _on_service(self, ch: dict):
        row = {"ts": time.time(), "name": ch["name"], "display_name": ch["display_name"], "action": ch["action"],
               "old_state": ch["old_state"], "new_state": ch["new_state"], "start_type": ch["start_type"],
               "binary_path": ch["binpath"], "is_demo": 0}
        self.db.insert("service_events", row)
        self.publish("event", table="service_events", row=row)
        if ch["action"] in ("created", "binary_changed"):
            sev = "HIGH" if any(m in ch["binpath"].lower() for m in UNUSUAL) else "MEDIUM"
            self.emit_alert(severity=sev, category="Service Change", source=ch["name"],
                            description=f"Service {ch['name']} {ch['action'].replace('_', ' ')}: {ch['binpath']}",
                            kind="service_change", details={"path": ch["binpath"]})

    # ------------------------------------------------------------------ file integrity
    def _on_fim(self, ev: dict, recent_count: int, demo=False):
        if demo:
            ev["is_demo"] = 1
        self.counters["file_mods"] += 1
        self.db.insert("file_events", ev)
        self.publish("event", table="file_events", row=ev)
        details = {"path": ev["path"], "old_hash": ev["old_hash"], "new_hash": ev["new_hash"]}
        # quiet host-wide signal so file changes can be attached to a suspicious process that just started
        self.corr.add_signal(Signal("file_modification", ev["ts"], f"{ev['action']} {ev['path']}", ev["risk"], None, None, details, demo))
        if ev["risk"] in ("MEDIUM", "HIGH"):
            self.emit_alert(severity=ev["risk"], category="File Integrity", source=os.path.basename(ev["path"]),
                            description=f"{ev['action']}: {ev['path']} (hash {ev['hash_status']})", kind="fim_change", details=details, demo=demo)
        t = self.settings["thresholds"]
        if recent_count >= t["mass_file_count"]:
            self.emit_alert(severity="HIGH", category="Mass File Modification", source=None,
                            description=f"{recent_count} monitored files changed within {t['mass_file_window']}s",
                            kind="mass_file_change", details={"count": recent_count}, demo=demo)

    # ------------------------------------------------------------------ lifecycle
    def _set(self, name, state, detail=""):
        self.modules[name] = {"state": state, "detail": detail}

    def start(self):
        if self.running:
            return
        self._stop.clear()
        self.running, self.started_at = True, time.time()
        # network capture
        try:
            self.sniffer = PacketSniffer(self._on_packet, self.settings.get("interface", ""))
            self.sniffer.start()
            self._set("network", "running")
        except CaptureUnavailable as e:
            self.sniffer = None
            self._set("network", "unavailable", str(e))
            log.warning("network capture unavailable: %s", e)
        # socket table (process <-> network)
        self.tracker = ConnectionTracker(self._on_new_external)
        self.tracker.prime()
        self.tracker.start()
        self._set("connections", "limited" if self.tracker.error else "running", self.tracker.error or "")
        # processes
        self.proc_mon = ProcessMonitor(self._on_process_created, self._on_process_terminated)
        self.proc_mon.prime()
        for i in self.proc_mon.known.values():
            self.corr.note_process(i["pid"], {"name": i["name"], "exe": i["exe"], "user": i["user"]})
        self.proc_mon.start()
        self._set("process", "running", "WMI trace active" if self.proc_mon.wmi_active else "polling every 1 s")
        # windows-only host telemetry
        if EventLogMonitor.available():
            self.evlog = EventLogMonitor(self._on_eventlog)
            self.evlog.start()
            self._set("eventlog", "running")
        else:
            self._set("eventlog", "unavailable", "Windows Event Log requires Windows")
        if ServiceMonitor.available():
            self.svc_mon = ServiceMonitor(self._on_service)
            self.svc_mon.start()
            self._set("services", "running")
        else:
            self._set("services", "unavailable", "Windows services require Windows")
        # file integrity
        try:
            self.fim.start()
            self._set("filesystem", "running", f"{len(self.fim.folders())} folder(s) watched")
        except Exception as e:
            self._set("filesystem", "unavailable", str(e))
        self._set("ml", "running" if self.settings["ml"]["enabled"] else "stopped", "")
        threading.Thread(target=self._tick_loop, daemon=True, name="engine-tick").start()
        self.publish("status", status=self.status())
        log.info("protection started (admin=%s)", self.admin)

    def stop(self):
        if not self.running:
            return
        self._stop.set()
        for m in (self.sniffer, self.tracker, self.proc_mon, self.evlog, self.svc_mon):
            try:
                if m:
                    m.stop()
            except Exception:
                log.exception("stop failed")
        self.fim.stop()
        self.sniffer = self.proc_mon = self.evlog = self.svc_mon = None
        for n in self.modules:
            self._set(n, "stopped")
        self.running = False
        self.publish("status", status=self.status())
        log.info("protection stopped")

    # ------------------------------------------------------------------ periodic analysis
    def _tick_loop(self):
        n = 0
        while not self._stop.wait(self.settings["tick_seconds"]):
            try:
                self.tick()
                n += 1
                if n % 720 == 0:
                    self.db.purge_older_than(self.settings["retention_days"])
            except Exception:
                log.exception("tick failed")

    def tick(self):
        now, T = time.time(), self.settings["tick_seconds"]
        m = self.flows.metrics(T, now)
        sysm = sysmetrics.sample()
        self.latest_sys = sysm
        self._det(self.traffic.check(now, m, sysm))
        self._det(self.synflood.check(now))
        rows = self.flows.flush()
        if rows:
            self.db.insert_many("network_events", rows)
            self.publish("flows", flows=rows[:40])
        c, self.counters = self.counters, Counter()
        feats = {"packet_rate": m["pps"], "byte_rate": m["bps"], "connection_count": len(self.tracker.snapshot),
                 "new_flow_rate": m["cps"], "dport_diversity": m["unique_dports"], "syn_ratio": m["syn_ratio"],
                 "failed_logins": c["failed_logins"], "process_creation_rate": c["proc_created"] / T,
                 "file_mod_rate": c["file_mods"] / T, "outbound_conn_freq": c["new_ext"] / T}
        ml = self.ml.score(feats)
        self._set("ml", "running", ml["status"]["isolation_forest"])
        if ml["anomaly"] and ml["persistent"]:
            self.emit_alert(severity="MEDIUM" if ml["score"] >= 0.9 else "LOW", category="ML Anomaly Signal", source=None,
                            description=f"Local model flags behaviour unlike this PC's learned baseline (score {ml['score']:.2f}). "
                                        "This is a statistical signal, not proof of an attack.",
                            kind="ml_anomaly", details={"features": feats, "method": ml["method"]})
        self.corr.tick(now)
        score, comps = self.risk.host_risk(list(self.corr.all_signals), now)
        for inc in self.corr.open_incidents():
            if not inc.get("is_demo") and inc["risk_score"] > score:
                score, comps = inc["risk_score"], inc.get("components", comps)
        self.latest_risk = {"score": score, "level": self.risk.level(score), "components": comps}
        self.last_scan = now
        if int(now) % 30 < T:
            self.db.insert("risk_scores", {"ts": now, "score": score, "level": self.latest_risk["level"], "components": comps})
        self.publish("risk", risk=self.latest_risk, metrics={"pps": m["pps"], "bps": m["bps"], "cps": m["cps"], "ts": now}, system=sysm)
        self.publish("stats", stats=self.stats())

    # ------------------------------------------------------------------ queries
    def stats(self) -> dict:
        w = self._demo_where("AND")
        wh = self._demo_where("WHERE")
        one = lambda sql: self.db.one(sql)["n"]
        return {
            "total_events": one(f"SELECT COUNT(*) n FROM security_events{wh}"),
            "suspicious_events": one(f"SELECT COUNT(*) n FROM alerts WHERE severity IN ('MEDIUM','HIGH','CRITICAL'){w}"),
            "active_threats": len([i for i in self.corr.open_incidents() if self.demo or not i.get("is_demo")]),
            "critical_alerts": one(f"SELECT COUNT(*) n FROM alerts WHERE severity='CRITICAL' AND acknowledged=0{w}"),
            "network_connections": len(self.tracker.snapshot),
            "running_processes": len(psutil.pids()),
        }

    def status(self) -> dict:
        return {"running": self.running, "started_at": self.started_at, "last_scan": self.last_scan, "admin": self.admin,
                "platform": platform.platform(), "modules": self.modules, "demo": bool(self.demo), "risk": self.latest_risk,
                "ml": self.ml.status(), "fim": self.fim.progress, "system": self.latest_sys,
                "notice": "Detection is based on observable host and network behaviour and cannot catch every attack."}

    def live_processes(self) -> list[dict]:
        out, names = [], {}
        for p in psutil.process_iter():
            try:
                names[p.pid] = p.name()
            except Exception:
                pass
        for p in psutil.process_iter():
            i = ProcessMonitor.info(p)
            if not i:
                continue
            try:
                mem = round(p.memory_info().rss / 1048576, 1)
            except Exception:
                mem = 0
            i["parent_name"] = names.get(i["ppid"], "")
            i["memory_mb"] = mem
            i["reasons"] = [r["text"] for r in assess_process(i["name"], i["exe"], i["parent_name"])]
            out.append(i)
        return sorted(out, key=lambda x: (-len(x["reasons"]), -x["memory_mb"]))

    def connections(self) -> dict:
        if not self.running:
            self.tracker.poll()
        return {"connections": self.tracker.snapshot[:800], "listening": self.tracker.listening_ports, "error": self.tracker.error}

    def services(self) -> list[dict]:
        if self.svc_mon and self.svc_mon.current:
            return self.svc_mon.current
        if ServiceMonitor.available():
            try:
                return list(ServiceMonitor(lambda x: None).snapshot().values())
            except Exception:
                return []
        return []

    def ack_alert(self, alert_id: int):
        self.db.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
