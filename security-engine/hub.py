"""Thread-safe fan-out of engine messages to WebSocket clients."""
import asyncio
import threading


class Hub:
    def __init__(self):
        self.loop: asyncio.AbstractEventLoop | None = None
        self.clients: set[asyncio.Queue] = set()
        self.lock = threading.Lock()

    def attach_loop(self, loop):
        self.loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=2000)
        with self.lock:
            self.clients.add(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            self.clients.discard(q)

    @staticmethod
    def _put(q: asyncio.Queue, msg: dict):
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            pass

    def publish(self, msg: dict):
        if not self.loop or self.loop.is_closed():
            return
        with self.lock:
            targets = list(self.clients)
        for q in targets:
            self.loop.call_soon_threadsafe(self._put, q, msg)
