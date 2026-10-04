"""File integrity monitoring: SHA-256 baselines + Watchdog change detection."""
import hashlib
import logging
import os
import threading
import time
from collections import deque

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

log = logging.getLogger("filesystem.fim")
EXEC_EXT = {".exe", ".dll", ".sys", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".msi", ".com", ".jar"}


def sha256_file(path: str, max_bytes: int | None = None) -> str | None:
    try:
        if max_bytes and os.path.getsize(path) > max_bytes:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def classify(action: str, path: str, hash_status: str, in_baseline: bool) -> str:
    """Risk is contextual. A modified document is LOW; a changed executable that was in the baseline is HIGH."""
    is_exec = os.path.splitext(path)[1].lower() in EXEC_EXT
    if hash_status == "UNCHANGED":
        return "LOW"
    if is_exec and action == "modified" and in_baseline:
        return "HIGH"
    # a pure rename never reaches here (identical content is ignored), so a baselined executable that arrives
    # as "renamed" was both moved and altered
    if is_exec and action == "renamed":
        return "HIGH" if in_baseline else "MEDIUM"
    if is_exec and action == "created":
        return "MEDIUM"
    if is_exec and action == "deleted":
        return "MEDIUM"
    if action == "deleted" and in_baseline:
        return "LOW"
    return "LOW"


def _like_escape(s: str) -> str:
    """Escape LIKE wildcards so a folder named e.g. C:\\My_Data cannot match C:\\My1Data."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class _Handler(FileSystemEventHandler):
    def __init__(self, mon):
        self.mon = mon

    def on_created(self, e):
        if not e.is_directory:
            self.mon.queue_change("created", e.src_path)

    def on_modified(self, e):
        if not e.is_directory:
            self.mon.queue_change("modified", e.src_path)

    def on_deleted(self, e):
        if not e.is_directory:
            self.mon.queue_change("deleted", e.src_path)

    def on_moved(self, e):
        if not e.is_directory:
            # one event, not a delete plus a create: the move itself carries the link back to the old baseline
            self.mon.queue_change("renamed", e.dest_path, old_path=e.src_path)


class FileIntegrityMonitor:
    def __init__(self, db, on_event, get_settings):
        self.db, self.on_event, self._get = db, on_event, get_settings
        self.observer: Observer | None = None
        self.pending: dict[str, tuple[str, float, str | None]] = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.recent: deque[float] = deque()
        self.mod_count = 0
        self.progress = {"state": "idle", "files": 0}

    # -- folder management ---------------------------------------------
    def folders(self) -> list[str]:
        return [r["path"] for r in self.db.query("SELECT path FROM fim_folders ORDER BY path")]

    def add_folder(self, path: str):
        path = os.path.abspath(path)
        if not os.path.isdir(path):
            raise ValueError("Folder does not exist")
        self.db.upsert("fim_folders", {"path": path})
        if self.observer:
            self.observer.schedule(_Handler(self), path, recursive=True)
        threading.Thread(target=self.build_baseline, args=([path],), daemon=True).start()

    def remove_folder(self, path: str):
        path = os.path.abspath(path)
        self.db.execute("DELETE FROM fim_folders WHERE path=?", (path,))
        # two patterns: the folder itself, and its descendants only. A single "folder%" would also match a
        # sibling such as C:\Database when C:\Data is removed.
        base = _like_escape(path.rstrip("\\/"))
        self.db.execute("DELETE FROM fim_baseline WHERE path LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\'",
                        (base, base + _like_escape(os.sep) + "%"))
        if self.observer:      # simplest correct behaviour: reschedule everything
            self.observer.unschedule_all()
            for f in self.folders():
                self.observer.schedule(_Handler(self), f, recursive=True)

    # -- baseline ---------------------------------------------------------
    def _excluded(self, path: str) -> bool:
        return os.path.splitext(path)[1].lower() in set(self._get().get("fim_excluded_ext", []))

    def build_baseline(self, folders: list[str] | None = None):
        folders = folders or self.folders()
        max_bytes = int(self._get().get("fim_max_file_mb", 200)) * 1024 * 1024
        self.progress = {"state": "scanning", "files": 0}
        rows = []
        for root_dir in folders:
            for dp, _, files in os.walk(root_dir):
                for fn in files:
                    fp = os.path.join(dp, fn)
                    if self._excluded(fp):
                        continue
                    h = sha256_file(fp, max_bytes)
                    if h is None:
                        continue
                    try:
                        st = os.stat(fp)
                    except OSError:
                        continue
                    rows.append({"path": fp, "hash": h, "size": st.st_size, "mtime": st.st_mtime})
                    self.progress["files"] += 1
                    if len(rows) >= 500:
                        self._save(rows); rows = []
        self._save(rows)
        self.progress["state"] = "ready"
        log.info("baseline complete: %d files", self.progress["files"])

    def _save(self, rows):
        for r in rows:
            self.db.upsert("fim_baseline", r)

    # -- monitoring -------------------------------------------------------------
    def start(self):
        self.stop_event.clear()
        self.observer = Observer()
        for f in self.folders():
            if os.path.isdir(f):
                self.observer.schedule(_Handler(self), f, recursive=True)
        self.observer.start()
        self.worker = threading.Thread(target=self._loop, daemon=True, name="fim-worker")
        self.worker.start()

    def stop(self):
        self.stop_event.set()
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=3)
            except Exception:
                pass
            self.observer = None

    def queue_change(self, action: str, path: str, old_path: str | None = None):
        if self._excluded(path):
            return
        with self.lock:
            prev = self.pending.get(path)
            if prev and prev[0] == "renamed":
                return    # keep the pending move: it is what links this path to its baseline. Editing the file
                          # afterwards must not downgrade it to a plain modify, or the rename reads as NEW.
            act = "created" if prev and prev[0] == "created" and action == "modified" else action
            self.pending[path] = (act, time.time(), old_path)

    def _loop(self):
        while not self.stop_event.wait(0.5):
            now = time.time()
            with self.lock:
                due = [(p, v) for p, v in self.pending.items() if now - v[1] >= 1.0]   # debounce 1 s
                for p, _ in due:
                    self.pending.pop(p, None)
                # a move must transfer its baseline before any deletion of the source path is processed
                due.sort(key=lambda pv: pv[1][0] != "renamed")
            for path, (action, _, old_path) in due:
                try:
                    self.process_change(action, path, old_path)
                except Exception:
                    log.exception("fim process error")

    def process_change(self, action: str, path: str, old_path: str | None = None) -> dict | None:
        base = self.db.one("SELECT hash FROM fim_baseline WHERE path=?", (path,))
        old = base["hash"] if base else None
        if old is None and action == "renamed" and old_path:
            # a moved file has no baseline at its destination yet, so adopt the source's before classifying it
            prev = self.db.one("SELECT hash FROM fim_baseline WHERE path=?", (old_path,))
            if prev:
                old = prev["hash"]
        max_bytes = int(self._get().get("fim_max_file_mb", 200)) * 1024 * 1024
        if action == "deleted":
            new = None
            self.db.execute("DELETE FROM fim_baseline WHERE path=?", (path,))
            status = "REMOVED"
        else:
            new = sha256_file(path, max_bytes)
            if new is None:
                return None
            if old is None:
                status = "NEW"
                if action == "modified":
                    action = "created"
            elif old == new:
                if action == "renamed" and old_path:      # unchanged content, still move the baseline across
                    self.db.execute("DELETE FROM fim_baseline WHERE path=?", (old_path,))
                    self._save_row(path, new)
                return None            # touched but content identical: not an integrity event
            else:
                status = "CHANGED"
            if action == "renamed" and old_path:
                self.db.execute("DELETE FROM fim_baseline WHERE path=?", (old_path,))
            self._save_row(path, new)
        risk = classify(action, path, status, old is not None)
        ev = {"ts": time.time(), "path": path, "action": action.upper(), "old_hash": old, "new_hash": new,
              "hash_status": status, "risk": risk, "is_demo": 0}
        self.mod_count += 1
        self.recent.append(ev["ts"])
        self.on_event(ev, self._mass_change())
        return ev

    def _save_row(self, path: str, digest: str) -> None:
        try:
            st = os.stat(path)
        except OSError:
            return
        self.db.upsert("fim_baseline", {"path": path, "hash": digest, "size": st.st_size, "mtime": st.st_mtime})

    def _mass_change(self) -> int:
        t = self._get()["thresholds"]
        now = time.time()
        while self.recent and now - self.recent[0] > t["mass_file_window"]:
            self.recent.popleft()
        return len(self.recent)
