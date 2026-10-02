"""Entry point: python main.py --port 8765   (Electron launches this and passes IDS_TOKEN)."""
import argparse
import logging
import sys

import uvicorn

from api import create_app
from config import DB_PATH, DATA_DIR, setup_logging
from core import Engine
from database.db import Database
from hub import Hub


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--init-db", action="store_true", help="create the database and exit")
    args = ap.parse_args()
    setup_logging()
    log = logging.getLogger("main")
    db = Database(DB_PATH)
    if args.init_db:
        log.info("database initialised at %s", DB_PATH)
        print(f"Database ready: {DB_PATH}")
        return 0
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        log.error("refusing to bind to non-loopback address %s", args.host)
        return 2
    hub = Hub()
    engine = Engine(db, hub)
    app = create_app(engine, hub)
    log.info("engine listening on %s:%d (data: %s, admin: %s)", args.host, args.port, DATA_DIR, engine.admin)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
