"""FastAPI layer: REST + WebSocket bound to 127.0.0.1 only, protected by a per-launch token."""
import asyncio
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from config import REPORTS_DIR
from database.db import SEARCH_MAP
from demo.simulator import DemoSimulator
from reports.generator import generate_report

log = logging.getLogger("api")


class FolderBody(BaseModel):
    path: str


class ReportBody(BaseModel):
    hours: int = 24
    include_demo: bool = False


class TrainBody(BaseModel):
    csv_path: str


def create_app(engine, hub, token: str | None = None) -> FastAPI:
    token = token if token is not None else os.environ.get("IDS_TOKEN")

    @asynccontextmanager
    async def lifespan(app):
        hub.attach_loop(asyncio.get_running_loop())
        if engine.settings.get("autostart_protection"):
            engine.start()
        yield
        engine.stop()

    app = FastAPI(title="Offline Endpoint Security Engine", version="1.0.0", lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origin_regex=r"^(http://(localhost|127\.0\.0\.1)(:\d+)?|null|file://.*|app://.*)$",
                       allow_methods=["*"], allow_headers=["*"])

    def auth(x_engine_token: str | None = Header(default=None)):
        if token and not secrets.compare_digest(x_engine_token or "", token):
            raise HTTPException(401, "invalid engine token")

    guard = [Depends(auth)]

    @app.get("/api/health")
    def health():
        return {"ok": True, "time": time.time()}

    @app.get("/api/status", dependencies=guard)
    def status():
        return engine.status()

    @app.get("/api/stats", dependencies=guard)
    def stats():
        return {"stats": engine.stats(), "risk": engine.latest_risk}

    @app.post("/api/protection/start", dependencies=guard)
    def start():
        engine.start()
        return engine.status()

    @app.post("/api/protection/stop", dependencies=guard)
    def stop():
        engine.stop()
        return engine.status()

    @app.get("/api/events/{table}", dependencies=guard)
    def events(table: str, since: float | None = None, until: float | None = None, severity: str | None = None,
               category: str | None = None, source: str | None = None, process: str | None = None,
               event_type: str | None = None, q: str | None = None, limit: int = 200, offset: int = 0):
        if table not in SEARCH_MAP:
            raise HTTPException(404, f"unknown table; choose from {sorted(SEARCH_MAP)}")
        f = dict(since=since, until=until, severity=severity, category=category, source=source, process=process, event_type=event_type, q=q)
        return engine.db.search(table, {k: v for k, v in f.items() if v not in (None, "")}, limit, offset, include_demo=bool(engine.demo))

    @app.post("/api/alerts/{alert_id}/ack", dependencies=guard)
    def ack(alert_id: int):
        engine.ack_alert(alert_id)
        return {"ok": True}

    @app.get("/api/incidents/{incident_id}", dependencies=guard)
    def incident(incident_id: str):
        import json
        r = engine.db.one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not r:
            raise HTTPException(404, "incident not found")
        for k in ("summary", "timeline"):
            r[k] = json.loads(r[k]) if r.get(k) else None
        r["related_alerts"] = engine.db.query("SELECT * FROM alerts WHERE incident_id=? ORDER BY ts", (incident_id,))
        comps = engine.corr.incidents.get(r["key"], {}).get("components") if r.get("key") else None
        r["components"] = comps
        return r

    @app.get("/api/live/processes", dependencies=guard)
    def procs():
        return engine.live_processes()

    @app.get("/api/live/connections", dependencies=guard)
    def conns():
        return engine.connections()

    @app.get("/api/live/network", dependencies=guard)
    def net():
        return {"series": engine.flows.recent_series(), "total_packets": engine.flows.total_packets,
                "module": engine.modules["network"]}

    @app.get("/api/live/services", dependencies=guard)
    def services():
        return engine.services()

    @app.get("/api/risk/history", dependencies=guard)
    def risk_history(limit: int = 240):
        return list(reversed(engine.db.query("SELECT ts,score,level FROM risk_scores ORDER BY ts DESC LIMIT ?", (limit,))))

    @app.get("/api/fim/folders", dependencies=guard)
    def fim_folders():
        return {"folders": engine.fim.folders(), "progress": engine.fim.progress}

    @app.post("/api/fim/folders", dependencies=guard)
    def fim_add(b: FolderBody):
        try:
            engine.fim.add_folder(b.path)
        except ValueError as e:
            raise HTTPException(400, str(e))
        return fim_folders()

    @app.delete("/api/fim/folders", dependencies=guard)
    def fim_del(path: str = Query(...)):
        engine.fim.remove_folder(path)
        return fim_folders()

    @app.post("/api/fim/rebuild", dependencies=guard)
    def fim_rebuild():
        import threading
        threading.Thread(target=engine.fim.build_baseline, daemon=True).start()
        return {"ok": True}

    @app.get("/api/settings", dependencies=guard)
    def get_settings():
        return engine.settings

    @app.put("/api/settings", dependencies=guard)
    def put_settings(patch: dict):
        return engine.update_settings(patch)

    @app.post("/api/ml/relearn", dependencies=guard)
    def relearn():
        engine.ml.relearn()
        return engine.ml.status()

    @app.post("/api/ml/train", dependencies=guard)
    def train(b: TrainBody):
        try:
            return engine.ml.train_supervised(b.csv_path)
        except Exception as e:
            raise HTTPException(400, str(e))

    @app.get("/api/ml/status", dependencies=guard)
    def ml_status():
        return engine.ml.status()

    @app.post("/api/reports", dependencies=guard)
    def make_report(b: ReportBody):
        p = generate_report(engine.db, REPORTS_DIR, b.hours, b.include_demo)
        return {"name": p.name}

    @app.get("/api/reports", dependencies=guard)
    def list_reports():
        return [{"name": p.name, "size": p.stat().st_size, "ts": p.stat().st_mtime}
                for p in sorted(REPORTS_DIR.glob("*.pdf"), key=lambda x: -x.stat().st_mtime)]

    @app.get("/api/reports/{name}", dependencies=guard)
    def get_report(name: str):
        p = (REPORTS_DIR / Path(name).name)
        if not p.exists():
            raise HTTPException(404)
        return FileResponse(p, media_type="application/pdf", filename=p.name)

    @app.post("/api/demo/start", dependencies=guard)
    def demo_start():
        if not engine.demo:
            engine.demo = DemoSimulator(engine)
            engine.demo.start()
        return {"demo": True}

    @app.post("/api/demo/stop", dependencies=guard)
    def demo_stop(purge: bool = True):
        if engine.demo:
            engine.demo.stop()
            engine.demo = None
            if purge:
                engine.db.purge_demo()
                for k in [k for k in engine.corr.incidents if k.startswith("demo:")]:
                    engine.corr.incidents.pop(k, None)
                    engine.corr.groups.pop(k, None)
        return {"demo": False}

    @app.websocket("/ws")
    async def ws(sock: WebSocket, token_q: str | None = Query(default=None, alias="token")):
        if token and not secrets.compare_digest(token_q or "", token):
            await sock.close(code=4401)
            return
        await sock.accept()
        q = hub.subscribe()
        try:
            await sock.send_json({"type": "hello", "status": engine.status(), "stats": engine.stats(), "risk": engine.latest_risk})
            while True:
                msg = await q.get()
                await sock.send_json(msg)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.unsubscribe(q)

    return app
