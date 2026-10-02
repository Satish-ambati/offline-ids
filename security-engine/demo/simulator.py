"""DEMO / SIMULATION mode. Everything produced here is flagged is_demo=1 and labelled in the UI and in alert text.
It never touches real processes, files or network interfaces."""
import threading
import time


class DemoSimulator(threading.Thread):
    def __init__(self, engine):
        super().__init__(daemon=True, name="demo-sim")
        self.e = engine
        self.stop_event = threading.Event()
        self.round = 0

    def _sleep(self, s) -> bool:
        return not self.stop_event.wait(s)

    def run(self):
        while not self.stop_event.is_set():
            self.round += 1
            if not self.scenario():
                break
            if not self._sleep(20):
                break

    def scenario(self) -> bool:
        e, pid = self.e, 9000 + self.round
        now = time.time
        e.emit_alert(severity="MEDIUM", category="Port Scan", source="203.0.113.45", kind="port_scan", demo=True,
                     description="34 unique ports probed by 203.0.113.45 within 10s (targeting this PC)",
                     details={"unique_ports": 34})
        if not self._sleep(4):
            return False
        e._on_process_created({"pid": pid, "ppid": 4242, "name": "update_helper.exe", "exe": r"C:\Users\Demo\AppData\Local\Temp\update_helper.exe",
                               "user": "DEMO\\student", "parent_name": "explorer.exe"}, demo=True)
        if not self._sleep(3):
            return False
        e._on_new_external({"pid": pid, "process": "update_helper.exe", "local": "192.168.1.20:50231", "remote": "198.51.100.23:443",
                            "proto": "TCP", "status": "ESTABLISHED", "external": True}, demo=True)
        if not self._sleep(3):
            return False
        ev = {"ts": now(), "path": r"C:\Users\Demo\Documents\Protected\quarterly.xlsx", "action": "MODIFIED", "old_hash": "a1" * 32,
              "new_hash": "b2" * 32, "hash_status": "CHANGED", "risk": "LOW", "is_demo": 1}
        e._on_fim(ev, 1, demo=True)
        if not self._sleep(3):
            return False
        e._on_fim({"ts": now(), "path": r"C:\Demo\tools\helper.exe", "action": "MODIFIED", "old_hash": "c3" * 32, "new_hash": "d4" * 32,
                   "hash_status": "CHANGED", "risk": "HIGH", "is_demo": 1}, 1, demo=True)
        if not self._sleep(3):
            return False
        e.emit_alert(severity="MEDIUM", category="Abnormal Traffic", source=None, kind="network_anomaly", demo=True,
                     description="Traffic well above learned baseline (pps=4200, baseline 310); no system impact observed",
                     details={"spikes": {"pps": 4200}})
        if not self._sleep(4):
            return False
        for i in range(6):
            e._on_eventlog({"ts": now(), "event_id": 4625, "channel": "Security", "event_type": "logon_failure", "user": "administrator",
                            "source_ip": "203.0.113.77", "message": "Failed logon for 'administrator' (type 3) from 203.0.113.77"}, demo=True)
            if not self._sleep(0.5):
                return False
        return True

    def stop(self):
        self.stop_event.set()
