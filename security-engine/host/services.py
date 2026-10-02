"""Windows service change monitor (start/stop, start-type and binary-path changes, new services)."""
import logging
import threading

import psutil

log = logging.getLogger("host.services")


class ServiceMonitor(threading.Thread):
    def __init__(self, on_change, interval: float = 10.0):
        super().__init__(daemon=True, name="services")
        self.on_change, self.interval = on_change, interval
        self.stop_event = threading.Event()
        self.state: dict[str, dict] = {}
        self.current: list[dict] = []

    @staticmethod
    def available() -> bool:
        return hasattr(psutil, "win_service_iter")

    def snapshot(self) -> dict[str, dict]:
        out = {}
        for s in psutil.win_service_iter():
            try:
                d = s.as_dict()
                out[d["name"]] = {"name": d["name"], "display_name": d.get("display_name", ""), "status": d.get("status", ""),
                                  "start_type": d.get("start_type", ""), "binpath": d.get("binpath", "")}
            except Exception:
                continue
        return out

    def poll(self, first: bool = False):
        snap = self.snapshot()
        self.current = list(snap.values())
        if not first:
            for name, s in snap.items():
                old = self.state.get(name)
                if old is None:
                    self.on_change({"action": "created", "old_state": "", "new_state": s["status"], **s})
                else:
                    if old["binpath"] != s["binpath"]:
                        self.on_change({"action": "binary_changed", "old_state": old["binpath"], "new_state": s["binpath"], **s})
                    if old["start_type"] != s["start_type"]:
                        self.on_change({"action": "start_type_changed", "old_state": old["start_type"], "new_state": s["start_type"], **s})
                    if old["status"] != s["status"]:
                        self.on_change({"action": "state_changed", "old_state": old["status"], "new_state": s["status"], **s})
            for name in set(self.state) - set(snap):
                o = self.state[name]
                self.on_change({"action": "deleted", "old_state": o["status"], "new_state": "", **o})
        self.state = snap

    def run(self):
        try:
            self.poll(first=True)
        except Exception:
            log.exception("service baseline failed")
        while not self.stop_event.wait(self.interval):
            try:
                self.poll()
            except Exception:
                log.exception("service poll failed")

    def stop(self):
        self.stop_event.set()
