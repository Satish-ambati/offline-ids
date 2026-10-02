"""Process creation/termination monitor with parent-child tracking.

Polls the process table (1 s). When running as administrator with the optional `wmi` package
installed it additionally listens to Win32_ProcessStartTrace so very short-lived processes are seen.
Command lines are deliberately NOT collected (they may contain secrets).
"""
import logging
import threading
import time

import psutil

log = logging.getLogger("process.monitor")


class ProcessMonitor(threading.Thread):
    def __init__(self, on_created, on_terminated, interval: float = 1.0):
        super().__init__(daemon=True, name="process-monitor")
        self.on_created, self.on_terminated, self.interval = on_created, on_terminated, interval
        self.stop_event = threading.Event()
        self.known: dict[int, dict] = {}
        self.wmi_active = False

    @staticmethod
    def info(p: psutil.Process) -> dict | None:
        try:
            with p.oneshot():
                return {"pid": p.pid, "ppid": p.ppid(), "name": p.name(), "exe": _safe(p.exe),
                        "user": _safe(p.username), "create_time": p.create_time()}
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            try:
                return {"pid": p.pid, "ppid": p.ppid(), "name": p.name(), "exe": "", "user": "", "create_time": time.time()}
            except Exception:
                return None

    def snapshot(self) -> list[dict]:
        return [i for i in (self.info(p) for p in psutil.process_iter()) if i]

    def prime(self):
        self.known = {i["pid"]: i for i in self.snapshot()}

    def poll(self):
        current = {}
        for p in psutil.process_iter():
            if p.pid in self.known:
                current[p.pid] = self.known[p.pid]
                continue
            i = self.info(p)
            if i:
                current[p.pid] = i
                i["parent_name"] = self.known.get(i["ppid"], current.get(i["ppid"], {})).get("name", "")
                self.on_created(i)
        for pid in set(self.known) - set(current):
            self.on_terminated(self.known[pid])
        self.known = current

    def _start_wmi(self):
        try:
            import pythoncom
            import wmi
        except Exception:
            return
        def loop():
            try:
                pythoncom.CoInitialize()
                c = wmi.WMI()
                watcher = c.Win32_ProcessStartTrace.watch_for()
                self.wmi_active = True
                while not self.stop_event.is_set():
                    try:
                        ev = watcher(timeout_ms=1000)
                    except wmi.x_wmi_timed_out:
                        continue
                    pid = int(ev.ProcessID)
                    if pid in self.known:
                        continue
                    try:
                        i = self.info(psutil.Process(pid)) or {"pid": pid, "ppid": int(ev.ParentProcessID), "name": ev.ProcessName,
                                                               "exe": "", "user": "", "create_time": time.time()}
                    except Exception:
                        i = {"pid": pid, "ppid": int(ev.ParentProcessID), "name": ev.ProcessName, "exe": "", "user": "", "create_time": time.time()}
                    i["parent_name"] = self.known.get(i["ppid"], {}).get("name", "")
                    self.known[pid] = i
                    self.on_created(i)
            except Exception as e:
                log.info("WMI process trace unavailable (%s); using polling only", e)
                self.wmi_active = False
        threading.Thread(target=loop, daemon=True, name="wmi-trace").start()

    def run(self):
        self._start_wmi()
        while not self.stop_event.wait(self.interval):
            try:
                self.poll()
            except Exception:
                log.exception("process poll failed")

    def stop(self):
        self.stop_event.set()


def _safe(fn):
    try:
        return fn() or ""
    except Exception:
        return ""
