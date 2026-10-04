"""Event correlation: links signals (process, network, file, auth) into incidents."""
import threading
import time
from collections import deque
from dataclasses import dataclass, field

# Signals that describe the machine as a whole rather than one process
HOST_WIDE = {"network_anomaly", "syn_flood", "dos", "mass_file_change", "fim_change", "file_modification",
             "ml_anomaly", "service_change", "account_change", "audit_tamper"}
PROCESS_ANCHORS = {"unusual_path", "parent_child_anomaly", "suspicious_process"}
TITLES = {
    "port_scan": "Port scanning activity", "syn_flood": "SYN-flood-like traffic", "dos": "DoS-like traffic with system impact",
    "brute_force": "Repeated authentication failures", "auth_after_failures": "Successful login after repeated failures",
    "network_anomaly": "Abnormal network activity", "unusual_path": "Process running from an unusual location",
    "parent_child_anomaly": "Unusual parent/child process chain", "external_connection": "External network connection",
    "file_modification": "File modification", "fim_change": "Monitored file changed", "mass_file_change": "Mass file modification",
    "service_change": "Windows service change", "ml_anomaly": "Machine-learning anomaly signal",
    "suspicious_process": "Suspicious process behaviour", "account_change": "Local account change",
    "audit_tamper": "Security audit log cleared",
}


@dataclass
class Signal:
    kind: str
    ts: float
    message: str
    severity: str = "MEDIUM"
    pid: int | None = None
    source: str | None = None
    details: dict = field(default_factory=dict)
    demo: bool = False
    scale: float = 1.0


class CorrelationEngine:
    def __init__(self, db, risk, get_settings, on_incident, on_change):
        self.db, self.risk, self._get = db, risk, get_settings
        self.on_incident = on_incident      # (incident_dict, escalated: bool)
        self.on_change = on_change          # (incident_dict)
        self.lock = threading.RLock()
        self.groups: dict[str, list[Signal]] = {}
        self.incidents: dict[str, dict] = {}
        self.proc_info: dict[int, dict] = {}
        self.all_signals: deque[Signal] = deque(maxlen=2000)
        self._counter = 0

    @property
    def cfg(self):
        return self._get()["risk"]

    # -- registry of processes so incidents can show name/user/path --------
    def note_process(self, pid: int, info: dict):
        with self.lock:
            self.proc_info[pid] = info
            if len(self.proc_info) > 3000:
                for k in list(self.proc_info)[:500]:
                    self.proc_info.pop(k, None)

    def _key(self, s: Signal) -> str:
        prefix = "demo:" if s.demo else ""
        if s.pid is not None and s.kind not in HOST_WIDE:
            return f"{prefix}pid:{s.pid}"
        if s.kind in HOST_WIDE:
            return f"{prefix}host"
        if s.source:
            return f"{prefix}src:{s.source}"
        return f"{prefix}host"

    def add_signal(self, s: Signal, only_if_group_exists: bool = False) -> dict | None:
        """Add a signal; returns the incident dict if one exists/was updated for it."""
        with self.lock:
            key = self._key(s)
            if only_if_group_exists and key not in self.groups:
                return None
            self._append(key, s)
            self.all_signals.append(s)
            touched = [key]
            if s.kind in HOST_WIDE:   # temporal attachment to recently-anchored process groups
                window = self.cfg["correlation_window"]
                for gk, sigs in list(self.groups.items()):
                    if gk.startswith("demo:") != s.demo or "pid:" not in gk:
                        continue
                    if any(x.kind in PROCESS_ANCHORS and s.ts - x.ts <= window for x in sigs):
                        c = Signal(**{**s.__dict__, "details": {**s.details, "association": "temporal"}})
                        self._append(gk, c)
                        touched.append(gk)
            result = self._evaluate(key)
            for k in touched[1:]:
                result = self._evaluate(k) or result
            return result

    def _append(self, key: str, s: Signal):
        lst = self.groups.setdefault(key, [])
        if not any(x.kind == s.kind and x.message == s.message for x in lst):
            lst.append(s)

    def _evaluate(self, key: str) -> dict | None:
        sigs = self.groups.get(key, [])
        if key.endswith("host"):     # host-wide signals only correlate with each other inside the short window
            cutoff = time.time() - self.cfg["correlation_window"]
            sigs = [x for x in sigs if x.ts >= cutoff]
        kinds = {x.kind for x in sigs}
        score, comps = self.risk.score(sigs)
        lv = self.cfg["levels"]
        existing = self.incidents.get(key)
        single_critical = score >= lv["critical"]
        if not existing and (len(kinds) < self.cfg["incident_min_kinds"] or score < lv["medium"]) and not single_critical:
            return None
        level = self.risk.level(score)
        demo = key.startswith("demo:")
        now = time.time()
        if existing is None:
            self._counter += 1
            inc_id = f"INC-{time.strftime('%Y%m%d')}-{self._counter:04d}" + ("-DEMO" if demo else "")
            existing = {"id": inc_id, "opened_ts": now, "status": "open", "key": key, "severity": "LOW", "is_demo": int(demo)}
            self.incidents[key] = existing
            escalated = True
        else:
            escalated = self._rank(level) > self._rank(existing["severity"])
        pid = next((x.pid for x in sigs if x.pid is not None), None)
        info = self.proc_info.get(pid, {}) if pid is not None else {}
        primary = max(sigs, key=lambda x: self.cfg["weights"].get(x.kind, 0))
        dst = next((x.details.get("dst") for x in sigs if x.details.get("dst")), None)
        src = next((x.source for x in sigs if x.source), None)
        timeline = [{"ts": x.ts, "kind": x.kind, "severity": x.severity, "message": x.message,
                     "association": x.details.get("association", "direct")} for x in sorted(sigs, key=lambda z: z.ts)]
        reason = (f"{len(kinds)} independent signal type(s) correlated: " + ", ".join(sorted(TITLES.get(k, k) for k in kinds))
                  + f". Application-defined risk score {score}/100 ({level}); this is not an attack probability.")
        existing.update({
            "updated_ts": now, "severity": level, "risk_score": score, "category": TITLES.get(primary.kind, primary.kind),
            "title": f"{TITLES.get(primary.kind, primary.kind)}" + (f" — {info.get('name')}" if info.get("name") else ""),
            "reason": reason, "timeline": timeline, "components": comps,
            "summary": {"pid": pid, "process": info.get("name"), "exe": info.get("exe"), "user": info.get("user"),
                        "source": src, "destination": dst,
                        "files": [x.details.get("path") for x in sigs if x.details.get("path")][:10]},
        })
        self._persist(existing)
        self.on_change(existing)
        if escalated:
            self.on_incident(existing, True)
        return existing

    @staticmethod
    def _rank(sev: str) -> int:
        return ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(sev)

    def _persist(self, inc: dict):
        row = {k: inc.get(k) for k in ("id", "opened_ts", "updated_ts", "severity", "category", "title", "key",
                                       "risk_score", "status", "reason", "is_demo")}
        row["summary"] = inc.get("summary")
        row["timeline"] = inc.get("timeline")
        row["components"] = inc.get("components")   # persisted so historical incidents keep their score breakdown
        self.db.upsert("incidents", row)

    def tick(self, now: float | None = None):
        """Expire stale signals and close idle incidents."""
        now = now or time.time()
        ttl = self.cfg["incident_ttl"]
        with self.lock:
            for key in list(self.groups):
                self.groups[key] = [s for s in self.groups[key] if now - s.ts < ttl * 2]
                if not self.groups[key]:
                    self.groups.pop(key)
            for key, inc in list(self.incidents.items()):
                if inc["status"] == "open" and now - inc["updated_ts"] > ttl:
                    inc["status"] = "closed"
                    self._persist(inc)
                    self.on_change(inc)
                    self.incidents.pop(key, None)
                    self.groups.pop(key, None)

    def open_incidents(self) -> list[dict]:
        with self.lock:
            return [i for i in self.incidents.values() if i["status"] == "open"]
