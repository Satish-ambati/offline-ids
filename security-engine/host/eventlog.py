"""Windows Event Log monitoring through wevtutil (read-only). Never reads or stores passwords."""
import logging
import os
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

log = logging.getLogger("host.eventlog")
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Security log: logons, failures, logoffs, privilege use, account & policy changes; System log: services
SECURITY_IDS = {4624: "logon_success", 4625: "logon_failure", 4634: "logoff", 4647: "logoff",
                4672: "special_privileges", 4720: "account_created", 4722: "account_enabled",
                4724: "password_reset_attempt", 4732: "group_member_added", 1102: "audit_log_cleared"}
SYSTEM_IDS = {7045: "service_installed", 7040: "service_start_type_changed", 6005: "eventlog_started", 6006: "eventlog_stopped"}
NOISY_LOGON_TYPES = {"0", "5"}   # system / service logons


def _data(root) -> dict:
    return {d.get("Name"): (d.text or "") for d in root.findall(".//e:EventData/e:Data", NS)}


def parse_event(xml_text: str) -> dict | None:
    try:
        root = ET.fromstring(xml_text)
        sysn = root.find("e:System", NS)
        eid = int(sysn.find("e:EventID", NS).text)
        rec = int(sysn.find("e:EventRecordID", NS).text)
        chan = sysn.find("e:Channel", NS).text
        ts_raw = sysn.find("e:TimeCreated", NS).get("SystemTime")
        ts = time.mktime(time.strptime(ts_raw[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
        d = _data(root)
    except Exception:
        return None
    table = SECURITY_IDS if chan == "Security" else SYSTEM_IDS
    et = table.get(eid)
    if not et:
        return None
    user = d.get("TargetUserName") or d.get("SubjectUserName") or ""
    if eid in (4624, 4625) and d.get("LogonType") in NOISY_LOGON_TYPES:
        return None
    if user.endswith("$") or user in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "UMFD-0", "UMFD-1"):
        if eid in (4624, 4634, 4672):
            return None
    return {"ts": ts, "record_id": rec, "event_id": eid, "channel": chan, "event_type": et, "user": user,
            "source_ip": d.get("IpAddress", ""), "logon_type": d.get("LogonType", ""),
            "service": d.get("ServiceName", ""), "image": d.get("ImagePath", ""),
            "message": _message(eid, et, user, d)}


def _message(eid, et, user, d) -> str:
    if eid == 4625:
        return f"Failed logon for '{user}' (type {d.get('LogonType','?')}) from {d.get('IpAddress') or 'local'}"
    if eid == 4624:
        return f"Logon for '{user}' (type {d.get('LogonType','?')}) from {d.get('IpAddress') or 'local'}"
    if eid == 7045:
        return f"Service installed: {d.get('ServiceName','?')} -> {d.get('ImagePath','?')}"
    return f"{et.replace('_',' ').capitalize()} ({user})" if user else et.replace("_", " ").capitalize()


class EventLogMonitor(threading.Thread):
    def __init__(self, on_event, interval: float = 5.0):
        super().__init__(daemon=True, name="eventlog")
        self.on_event, self.interval = on_event, interval
        self.stop_event = threading.Event()
        self.last = {"Security": None, "System": None}
        self.error: str | None = None

    @staticmethod
    def available() -> bool:
        return os.name == "nt"

    def _query(self, channel: str, ids: dict, extra: str = "", count: int = 100) -> list[str]:
        cond = " or ".join(f"EventID={i}" for i in ids)
        q = f"*[System[({cond}){extra}]]"
        cmd = ["wevtutil", "qe", channel, f"/q:{q}", f"/c:{count}", "/rd:true", "/f:xml"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if r.returncode != 0:
            raise PermissionError(r.stderr.strip() or f"wevtutil exit {r.returncode}")
        out = r.stdout.strip()
        return [f"<r>{out}</r>"] if not out else [x for x in out.replace("</Event>", "</Event>\n").splitlines() if x.strip().startswith("<Event")]

    def _latest_id(self, channel: str) -> int:
        cmd = ["wevtutil", "qe", channel, "/c:1", "/rd:true", "/f:xml"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if r.returncode != 0:
            raise PermissionError(r.stderr.strip())
        try:
            return int(ET.fromstring(r.stdout.strip()).find("e:System/e:EventRecordID", NS).text)
        except Exception:
            return 0

    def poll(self):
        for channel, ids in (("Security", SECURITY_IDS), ("System", SYSTEM_IDS)):
            try:
                if self.last[channel] is None:
                    self.last[channel] = self._latest_id(channel)
                    continue
                lines = self._query(channel, ids, f" and (EventRecordID>{self.last[channel]})")
                events = [e for e in (parse_event(x) for x in lines) if e]
                allrec = []
                for x in lines:
                    try:
                        allrec.append(int(ET.fromstring(x).find("e:System/e:EventRecordID", NS).text))
                    except Exception:
                        pass
                if allrec:
                    self.last[channel] = max(allrec + [self.last[channel]])
                for e in sorted(events, key=lambda z: z["record_id"]):
                    self.on_event(e)
                if channel == "Security":
                    self.error = None
            except PermissionError as e:
                if channel == "Security":
                    self.error = f"Cannot read Security log (administrator rights required): {e}"
            except Exception:
                log.exception("event log poll failed for %s", channel)

    def run(self):
        while not self.stop_event.wait(self.interval):
            self.poll()

    def stop(self):
        self.stop_event.set()
