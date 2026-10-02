from detection.process_rules import assess_process
from detection.rules import BruteForceDetector, PortScanDetector, SynFloodDetector, TrafficAnomalyDetector


def pkt(ts, src, dport, flags="S", proto="TCP", direction="in"):
    return {"ts": ts, "src": src, "dst": "192.168.1.20", "sport": 40000, "dport": dport, "proto": proto,
            "flags": flags, "size": 60, "direction": direction}


def test_port_scan_detected():
    d = PortScanDetector(window=10, unique_ports=20)
    hit = None
    for i in range(25):
        hit = d.feed(pkt(100 + i * 0.1, "10.0.0.9", 1000 + i)) or hit
    assert hit and hit.kind == "port_scan" and hit.source == "10.0.0.9"


def test_port_scan_ignores_established_traffic_and_few_ports():
    d = PortScanDetector(window=10, unique_ports=20)
    assert all(d.feed(pkt(i, "10.0.0.9", 443, flags="A")) is None for i in range(100))
    assert all(d.feed(pkt(i * 0.1, "10.0.0.9", 80 + (i % 3))) is None for i in range(100))


def test_port_scan_slow_probe_outside_window_is_not_flagged():
    d = PortScanDetector(window=10, unique_ports=20)
    assert all(d.feed(pkt(i * 5, "10.0.0.9", 1000 + i)) is None for i in range(30))


def test_syn_flood_needs_incomplete_handshakes():
    d = SynFloodDetector(window=5, min_count=150, ratio=3.0)
    hit = None
    for i in range(400):
        hit = d.feed(pkt(5000 + i * 0.01, f"10.1.0.{i % 200}", 80)) or hit
    assert hit and hit.kind == "syn_flood"
    ok = SynFloodDetector(window=5, min_count=150, ratio=3.0)
    res = []
    for i in range(400):       # busy server: every SYN gets a completing ACK
        res.append(ok.feed(pkt(5000 + i * 0.01, "10.1.0.5", 80)))
        res.append(ok.feed(pkt(5000 + i * 0.01, "10.1.0.5", 80, flags="A")))
    assert not any(res)


def test_brute_force_and_success_after_failures():
    d = BruteForceDetector(failures=5, window=300)
    hit = None
    for i in range(6):
        hit = d.feed({"ts": 1000 + i, "success": False, "user": "admin", "source_ip": "10.2.2.2"}) or hit
    assert hit and hit.kind == "brute_force"
    ok = d.feed({"ts": 1010, "success": True, "user": "admin", "source_ip": "10.2.2.2"})
    assert ok and ok.kind == "auth_after_failures"


def test_brute_force_window_expires():
    d = BruteForceDetector(failures=5, window=60)
    assert all(d.feed({"ts": i * 100, "success": False, "user": "u", "source_ip": "1.1.1.1"}) is None for i in range(10))


def test_dos_requires_system_impact_for_high():
    t = {"dos_pps_min": 2000, "dos_multiplier": 5, "dos_cpu": 85, "dos_mem": 90, "dos_latency_ms": 50, "alert_cooldown": 0}
    d = TrafficAnomalyDetector(t)
    for i in range(20):
        assert d.check(i, {"pps": 200, "bps": 1e5, "cps": 5}, {"cpu": 10, "mem": 30, "latency_ms": 1}) is None
    spike = {"pps": 9000, "bps": 9e6, "cps": 400}
    a = d.check(100, spike, {"cpu": 20, "mem": 30, "latency_ms": 1})
    assert a.kind == "network_anomaly" and a.severity == "MEDIUM"
    b = d.check(1000, spike, {"cpu": 96, "mem": 30, "latency_ms": 1})
    assert b.kind == "dos" and b.severity == "HIGH"


def test_process_assessment_is_behavioural_not_name_based():
    assert assess_process("chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe", "explorer.exe") == []
    assert assess_process("mimikatz.exe", r"C:\Program Files\Tools\mimikatz.exe", "explorer.exe") == []   # name alone is not enough
    assert assess_process("tool.exe", r"C:\Users\a\AppData\Local\Temp\tool.exe", "explorer.exe")[0]["kind"] == "unusual_path"
    assert assess_process("powershell.exe", r"C:\Windows\System32\powershell.exe", "WINWORD.EXE")[0]["kind"] == "parent_child_anomaly"
    assert assess_process("svchost.exe", r"C:\Users\a\Downloads\svchost.exe", "explorer.exe")
