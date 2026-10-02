"""Rule-based detectors. Pure logic (no OS calls) so they are unit-testable.

Every detector reports observable behaviour only; none claim to identify an attacker.
Packet dict: {ts, src, dst, sport, dport, proto, flags, size, direction('in'|'out')}
"""
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class Detection:
    kind: str                 # risk/correlation signal kind
    category: str             # human readable category
    severity: str
    source: str | None
    description: str
    details: dict = field(default_factory=dict)


class _Cooldown:
    def __init__(self, seconds: float):
        self.seconds, self.last = seconds, {}

    def ok(self, key, now) -> bool:
        if now - self.last.get(key, 0) >= self.seconds:
            self.last[key] = now
            return True
        return False


def _is_syn(flags: str) -> bool:
    return "S" in flags and "A" not in flags


class PortScanDetector:
    """Many distinct destination ports touched by one peer inside a short window."""

    def __init__(self, window=10, unique_ports=20, cooldown=60):
        self.window, self.unique_ports = window, unique_ports
        self.hits: dict[tuple, deque] = defaultdict(deque)
        self.cd = _Cooldown(cooldown)

    def feed(self, p: dict) -> Detection | None:
        if p["proto"] == "TCP":
            if not _is_syn(p.get("flags", "")):
                return None                       # only connection attempts count
        elif p["proto"] != "UDP":
            return None
        inbound = p["direction"] == "in"
        peer = p["src"] if inbound else p["dst"]
        port = p["dport"] if inbound else p["dport"]
        key = (p["direction"], peer)
        dq = self.hits[key]
        dq.append((p["ts"], port))
        while dq and p["ts"] - dq[0][0] > self.window:
            dq.popleft()
        uniq = {x[1] for x in dq}
        if len(uniq) >= self.unique_ports and self.cd.ok(key, p["ts"]):
            where = "targeting this PC" if inbound else "originating from this PC"
            return Detection(
                "port_scan", "Port Scan", "HIGH" if len(uniq) >= self.unique_ports * 3 else "MEDIUM", peer,
                f"{len(uniq)} unique ports probed by {peer} within {self.window}s ({where})",
                {"unique_ports": len(uniq), "window": self.window, "direction": p["direction"],
                 "sample_ports": sorted(uniq)[:15]})
        return None


class SynFloodDetector:
    """High inbound SYN volume with few completed handshakes (ACK-only packets)."""

    def __init__(self, window=5, min_count=150, ratio=3.0, cooldown=60):
        self.window, self.min_count, self.ratio = window, min_count, ratio
        self.syn: deque = deque()
        self.ack: deque = deque()
        self.cd = _Cooldown(cooldown)
        self._last_check = 0.0

    def feed(self, p: dict) -> Detection | None:
        if p["proto"] != "TCP" or p["direction"] != "in":
            return None
        f = p.get("flags", "")
        if _is_syn(f):
            self.syn.append((p["ts"], p["src"]))
        elif "A" in f and "S" not in f:
            self.ack.append(p["ts"])
        if p["ts"] - self._last_check >= 1:
            self._last_check = p["ts"]
            return self.check(p["ts"])
        return None

    def check(self, now: float) -> Detection | None:
        while self.syn and now - self.syn[0][0] > self.window:
            self.syn.popleft()
        while self.ack and now - self.ack[0] > self.window:
            self.ack.popleft()
        n = len(self.syn)
        ratio = n / max(1, len(self.ack))
        if n >= self.min_count and ratio >= self.ratio and self.cd.ok("syn", now):
            srcs = defaultdict(int)
            for _, s in self.syn:
                srcs[s] += 1
            top = max(srcs, key=srcs.get)
            return Detection("syn_flood", "SYN-Flood-Like Activity", "HIGH", top,
                             f"{n} inbound SYNs in {self.window}s with only {len(self.ack)} completing ACKs "
                             f"(SYN:ACK ratio {ratio:.1f}); {len(srcs)} distinct source(s)",
                             {"syn": n, "ack": len(self.ack), "ratio": round(ratio, 2), "sources": len(srcs)})
        return None


class BruteForceDetector:
    """Repeated authentication failures grouped by source and by account."""

    def __init__(self, failures=5, window=300, cooldown=120):
        self.failures, self.window = failures, window
        self.by_source: dict[str, deque] = defaultdict(deque)
        self.by_user: dict[str, deque] = defaultdict(deque)
        self.cd = _Cooldown(cooldown)
        self.recent_fail_ts: dict[tuple, deque] = defaultdict(deque)

    def feed(self, e: dict) -> Detection | None:
        """e: {ts, success, user, source_ip}. Passwords are never part of the event."""
        now, user = e["ts"], (e.get("user") or "unknown")
        src = e.get("source_ip") or ""
        src = src if src not in ("-", "::1", "127.0.0.1", "") else "local"
        if e["success"]:
            fails = self._count(self.by_user[user], now)
            if fails >= self.failures and self.cd.ok(("ok", user), now):
                return Detection("auth_after_failures", "Authentication Anomaly", "HIGH", src,
                                 f"Successful logon for '{user}' after {fails} recent failures",
                                 {"user": user, "failures": fails})
            return None
        self.by_source[src].append(now)
        self.by_user[user].append(now)
        ns, nu = self._count(self.by_source[src], now), self._count(self.by_user[user], now)
        for label, n, key in (("source", ns, src), ("account", nu, user)):
            if n >= self.failures and self.cd.ok((label, key), now):
                sev = "HIGH" if n >= self.failures * 4 else "MEDIUM"
                return Detection("brute_force", "Authentication Anomaly", sev, src,
                                 f"{n} failed logons within {self.window}s for {label} '{key}'",
                                 {"failures": n, "user": user, "group_by": label})
        return None

    def _count(self, dq: deque, now: float) -> int:
        while dq and now - dq[0] > self.window:
            dq.popleft()
        return len(dq)


class TrafficAnomalyDetector:
    """Packets/bytes/connections per second vs. an adaptive baseline.

    A traffic spike alone is MEDIUM. It is only escalated to HIGH (DoS-like) when the
    host also shows impact: high CPU/memory or degraded local responsiveness.
    """

    def __init__(self, t: dict):
        self.t = t
        self.ema: dict[str, float] = {}
        self.samples = 0
        self.cd = _Cooldown(t.get("alert_cooldown", 30) * 2)

    def check(self, now: float, m: dict, sysm: dict) -> Detection | None:
        """m: {pps, bps, cps}; sysm: {cpu, mem, latency_ms}"""
        spikes = {}
        for k, floor in (("pps", self.t["dos_pps_min"]), ("bps", self.t["dos_pps_min"] * 600), ("cps", 200)):
            base = self.ema.get(k)
            if base is not None and self.samples >= 12 and m[k] > max(floor, base * self.t["dos_multiplier"]):
                spikes[k] = (m[k], base)
        if not spikes:   # only learn from non-anomalous windows
            for k in ("pps", "bps", "cps"):
                self.ema[k] = m[k] if k not in self.ema else 0.9 * self.ema[k] + 0.1 * m[k]
            self.samples += 1
            return None
        impact = []
        if sysm.get("cpu", 0) >= self.t["dos_cpu"]:
            impact.append(f"CPU {sysm['cpu']:.0f}%")
        if sysm.get("mem", 0) >= self.t["dos_mem"]:
            impact.append(f"memory {sysm['mem']:.0f}%")
        if sysm.get("latency_ms", 0) >= self.t["dos_latency_ms"]:
            impact.append(f"responsiveness {sysm['latency_ms']:.0f} ms")
        if not self.cd.ok("traffic", now):
            return None
        detail = ", ".join(f"{k}={v[0]:.0f} (baseline {v[1]:.0f})" for k, v in spikes.items())
        if impact:
            return Detection("dos", "DoS-Like Behavior", "HIGH", None,
                             f"Traffic spike ({detail}) correlated with system impact: {', '.join(impact)}",
                             {"spikes": {k: v[0] for k, v in spikes.items()}, "impact": impact})
        return Detection("network_anomaly", "Abnormal Traffic", "MEDIUM", None,
                         f"Traffic well above learned baseline ({detail}); no system impact observed",
                         {"spikes": {k: v[0] for k, v in spikes.items()}})
