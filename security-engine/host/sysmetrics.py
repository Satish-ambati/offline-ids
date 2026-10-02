import socket
import time

import psutil


def sample() -> dict:
    return {"cpu": psutil.cpu_percent(interval=None), "mem": psutil.virtual_memory().percent,
            "latency_ms": responsiveness_ms()}


def responsiveness_ms() -> float:
    """Proxy for local responsiveness: round-trip time of a tiny loopback message. It rises when the OS is starved."""
    a, b = socket.socketpair()
    try:
        t = time.perf_counter()
        a.sendall(b"x")
        b.recv(1)
        return (time.perf_counter() - t) * 1000
    finally:
        a.close()
        b.close()
