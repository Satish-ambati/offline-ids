"""Npcap + Scapy packet capture, limited to traffic involving this PC."""
import logging
import socket
import time

import psutil

log = logging.getLogger("network.sniffer")


class CaptureUnavailable(RuntimeError):
    pass


def local_ips() -> set[str]:
    ips = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                ips.add(a.address.split("%")[0])
    return ips


class PacketSniffer:
    def __init__(self, on_packet, iface: str = ""):
        self.on_packet, self.iface = on_packet, iface or None
        self._sniffer = None
        self._local: set[str] = set()
        self._local_ts = 0.0

    def start(self):
        try:
            from scapy.all import AsyncSniffer, conf
        except Exception as e:  # scapy missing
            raise CaptureUnavailable(f"Scapy could not be loaded: {e}") from e
        if not getattr(conf, "use_pcap", False) and hasattr(conf, "use_npcap") and not conf.use_npcap:
            log.warning("Npcap not detected by Scapy; capture may fail. Install Npcap (WinPcap API-compatible mode).")
        self._local = local_ips()
        self._local_ts = time.time()
        self._sniffer = AsyncSniffer(iface=self.iface, prn=self._handle, store=False, filter="ip or ip6")
        try:
            self._sniffer.start()
            time.sleep(0.6)
            if not self._sniffer.running:
                detail = getattr(self._sniffer, "exception", None)
                raise CaptureUnavailable("Capture could not start"
                                         + (f" ({detail})" if detail else "")
                                         + ". Is Npcap installed and is the engine running as administrator?")
        except Exception as e:
            self._sniffer = None       # thread already died; nothing to stop
            if isinstance(e, CaptureUnavailable):
                raise
            raise CaptureUnavailable(f"Packet capture failed: {e}") from e

    def stop(self):
        try:
            if self._sniffer is not None and self._sniffer.running:
                self._sniffer.stop()
        except Exception:
            log.exception("error stopping sniffer")
        self._sniffer = None

    def _handle(self, pkt):
        try:
            from scapy.all import ICMP, IP, TCP, UDP, IPv6
            now = time.time()
            if now - self._local_ts > 60:
                self._local, self._local_ts = local_ips(), now
            if IP in pkt:
                ip = pkt[IP]
            elif IPv6 in pkt:
                ip = pkt[IPv6]
            else:
                return
            src, dst = ip.src, ip.dst
            if src.startswith("127.") or src == "::1":
                return
            if dst in self._local:
                direction = "in"
            elif src in self._local:
                direction = "out"
            else:
                return    # does not involve this PC
            sport = dport = 0
            flags = ""
            proto = "OTHER"
            if TCP in pkt:
                proto, sport, dport, flags = "TCP", pkt[TCP].sport, pkt[TCP].dport, str(pkt[TCP].flags)
            elif UDP in pkt:
                proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
            elif ICMP in pkt:
                proto = "ICMP"
            self.on_packet({"ts": now, "src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto,
                            "flags": flags, "size": len(pkt), "direction": direction})
        except Exception:
            log.debug("packet parse error", exc_info=True)
