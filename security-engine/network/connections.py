"""Socket table poller: maps TCP/UDP connections to owning processes (Process <-> Network link)."""
import ipaddress
import logging
import socket
import threading
import time

import psutil

log = logging.getLogger("network.connections")

_DNS: dict[str, tuple[str, float]] = {}
_DNS_TTL = 600.0
_DNS_LOCK = threading.Lock()


def resolve_host(ip: str) -> str:
    if not ip or ip in ("local", "*", "0.0.0.0", "::"):
        return ip
    try:
        ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return ip
    now = time.time()
    with _DNS_LOCK:
        hit = _DNS.get(ip)
        if hit and now - hit[1] < _DNS_TTL:
            return hit[0]
    name = ip
    try:
        name = socket.getfqdn(ip)
        if not name or name == ip:
            name = socket.getnameinfo((ip, 0), 0)[0]
    except Exception:
        name = ip
    if not name:
        name = ip
    with _DNS_LOCK:
        _DNS[ip] = (name, now)
        if len(_DNS) > 2000:
            for k in list(_DNS)[:500]:
                _DNS.pop(k, None)
    return name


def is_external(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_global
    except ValueError:
        return False


class ConnectionTracker(threading.Thread):
    def __init__(self, on_new_external, interval: float = 2.0):
        super().__init__(daemon=True, name="conn-tracker")
        self.on_new_external, self.interval = on_new_external, interval
        self.stop_event = threading.Event()
        self.snapshot: list[dict] = []
        self.known: set[tuple] = set()
        self.names: dict[int, str] = {}
        self.error: str | None = None
        self.listening_ports: list[dict] = []

    def _pname(self, pid: int | None) -> str:
        if pid is None:
            return ""
        if pid not in self.names:
            try:
                self.names[pid] = psutil.Process(pid).name()
            except Exception:
                self.names[pid] = ""
        return self.names[pid]

    def poll(self) -> None:
        try:
            conns = psutil.net_connections(kind="inet")
            self.error = None
        except (psutil.AccessDenied, PermissionError) as e:
            self.error = f"Access denied reading socket table (run as administrator): {e}"
            return
        snap, listening, current = [], [], set()
        for c in conns:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            rhost = resolve_host(c.raddr.ip) if c.raddr else ""
            row = {"pid": c.pid, "process": self._pname(c.pid), "local": laddr, "remote": raddr,
                   "remote_ip": c.raddr.ip if c.raddr else "", "remote_host": rhost,
                   "status": c.status, "proto": "TCP" if c.type == 1 else "UDP",
                   "external": bool(c.raddr and is_external(c.raddr.ip))}
            snap.append(row)
            if c.status == psutil.CONN_LISTEN:
                listening.append({"pid": c.pid, "process": row["process"], "port": c.laddr.port, "address": c.laddr.ip})
            if c.raddr and c.status == psutil.CONN_ESTABLISHED and row["external"] and c.pid:
                k = (c.pid, raddr)
                current.add(k)
                if k not in self.known:
                    try:
                        self.on_new_external(row)
                    except Exception:
                        log.exception("callback error")
        self.known = current   # forget closed connections so a reconnect counts as new
        self.snapshot, self.listening_ports = snap, listening

    def run(self):
        first = True
        while not self.stop_event.wait(self.interval):
            try:
                self.poll()
                if first:      # do not treat connections that pre-exist at start as "new"
                    first = False
            except Exception:
                log.exception("connection poll failed")

    def prime(self):
        """Record existing connections so only genuinely new ones raise events."""
        self.on_new_external, cb = (lambda r: None), self.on_new_external
        self.poll()
        self.on_new_external = cb

    def stop(self):
        self.stop_event.set()
