"""Aggregates packets into flow summaries and per-second metrics (never stores raw payloads)."""
import threading
import time
from collections import deque


class FlowAggregator:
    def __init__(self):
        self.lock = threading.Lock()
        self.flows: dict[tuple, dict] = {}
        self.seen: dict[tuple, float] = {}
        self.secs: dict[int, dict] = {}
        self.ports: deque = deque()          # (ts, dport) inbound attempts
        self.series: deque = deque(maxlen=300)  # for charts: (ts,pps,bps,cps)
        self.total_packets = 0

    def add(self, p: dict):
        with self.lock:
            sec = int(p["ts"])
            b = self.secs.setdefault(sec, {"pkts": 0, "bytes": 0, "new": 0, "syn": 0, "tcp": 0})
            b["pkts"] += 1
            b["bytes"] += p["size"]
            self.total_packets += 1
            inbound = p["direction"] == "in"
            remote, rport, lport = (p["src"], p["sport"], p["dport"]) if inbound else (p["dst"], p["dport"], p["sport"])
            key = (p["direction"], remote, rport, lport, p["proto"])
            if p["proto"] == "TCP":
                b["tcp"] += 1
                if "S" in p["flags"] and "A" not in p["flags"]:
                    b["syn"] += 1
                    if inbound:
                        self.ports.append((p["ts"], p["dport"]))
            f = self.flows.get(key)
            if f is None:
                f = self.flows[key] = {"packets": 0, "bytes": 0, "flags": set(), "first": p["ts"], "last": p["ts"]}
            f["packets"] += 1
            f["bytes"] += p["size"]
            f["last"] = p["ts"]
            if p["flags"]:
                f["flags"].add(p["flags"])
            if key not in self.seen:
                b["new"] += 1
            self.seen[key] = p["ts"]

    def metrics(self, seconds: int = 5, now: float | None = None) -> dict:
        now = now or time.time()
        lo = int(now) - seconds
        with self.lock:
            rows = [v for s, v in self.secs.items() if s > lo]
            while self.ports and now - self.ports[0][0] > seconds:
                self.ports.popleft()
            ports = {x[1] for x in self.ports}
        pk = sum(r["pkts"] for r in rows)
        by = sum(r["bytes"] for r in rows)
        new = sum(r["new"] for r in rows)
        syn = sum(r["syn"] for r in rows)
        tcp = sum(r["tcp"] for r in rows)
        m = {"pps": pk / seconds, "bps": by / seconds, "cps": new / seconds, "packets": pk, "bytes": by,
             "unique_dports": len(ports), "syn_ratio": (syn / tcp) if tcp else 0.0}
        with self.lock:
            self.series.append((now, m["pps"], m["bps"], m["cps"]))
        return m

    def flush(self, limit: int = 200) -> list[dict]:
        """Return and clear flow summaries accumulated since last flush."""
        with self.lock:
            flows, self.flows = self.flows, {}
            cutoff = time.time() - 900
            for k in [k for k, t in self.seen.items() if t < cutoff]:
                self.seen.pop(k, None)
            for s in [s for s in self.secs if s < int(time.time()) - 900]:
                self.secs.pop(s, None)
        rows = []
        for (direction, remote, rport, lport, proto), f in sorted(flows.items(), key=lambda kv: -kv[1]["bytes"])[:limit]:
            rows.append({"ts": f["last"], "src_ip": remote if direction == "in" else "local",
                         "dst_ip": "local" if direction == "in" else remote,
                         "src_port": rport if direction == "in" else lport,
                         "dst_port": lport if direction == "in" else rport,
                         "protocol": proto, "direction": direction, "packets": f["packets"], "bytes": f["bytes"],
                         "flags": ",".join(sorted(f["flags"])), "pid": None, "process": None, "is_demo": 0})
        return rows

    def recent_series(self):
        with self.lock:
            return [{"ts": t, "pps": a, "bps": b, "cps": c} for t, a, b, c in self.series]
