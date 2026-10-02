"""Paths, logging and default settings. All data stays on the local machine."""
import copy
import logging
import logging.handlers
import os
from pathlib import Path

APP_NAME = "OfflineIDS"


def _data_dir() -> Path:
    env = os.environ.get("IDS_DATA_DIR")
    if env:
        p = Path(env)
    elif os.name == "nt":
        p = Path(os.environ.get("APPDATA", str(Path.home()))) / APP_NAME
    else:
        p = Path.home() / f".{APP_NAME.lower()}"
    p.mkdir(parents=True, exist_ok=True)
    return p


DATA_DIR = _data_dir()
DB_PATH = DATA_DIR / "ids.sqlite3"
MODELS_DIR = DATA_DIR / "models"
REPORTS_DIR = DATA_DIR / "reports"
LOG_DIR = DATA_DIR / "logs"
for _d in (MODELS_DIR, REPORTS_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

DEFAULT_SETTINGS = {
    "animations": "full",          # full | reduced | off
    "sound": False,
    "notifications": True,
    "interface": "",               # capture interface, blank = automatic
    "tick_seconds": 5,
    "autostart_protection": False,
    "retention_days": 30,
    "fim_excluded_ext": [".tmp", ".log", ".etl"],
    "fim_max_file_mb": 200,
    "thresholds": {
        "port_scan_unique_ports": 20,
        "port_scan_window": 10,
        "syn_window": 5,
        "syn_min_count": 150,
        "syn_ratio": 3.0,
        "brute_force_failures": 5,
        "brute_force_window": 300,
        "dos_pps_min": 2000,
        "dos_multiplier": 5.0,
        "dos_cpu": 85.0,
        "dos_mem": 90.0,
        "dos_latency_ms": 50.0,
        "mass_file_count": 50,
        "mass_file_window": 10,
        "alert_cooldown": 30,
    },
    "risk": {
        # Application-defined weights. These are NOT attack probabilities.
        "weights": {
            "port_scan": 30, "syn_flood": 35, "dos": 35, "brute_force": 35,
            "auth_after_failures": 40, "network_anomaly": 20, "unusual_path": 12,
            "parent_child_anomaly": 30, "external_connection": 12,
            "file_modification": 12, "fim_change": 25, "mass_file_change": 35,
            "service_change": 20, "ml_anomaly": 12, "suspicious_process": 25,
            "account_change": 20, "audit_tamper": 40,
        },
        "correlation_bonus": 6,
        "levels": {"medium": 30, "high": 60, "critical": 80},
        "correlation_window": 120,
        "incident_min_kinds": 2,
        "incident_ttl": 1800,
    },
    "ml": {"enabled": True, "min_train_windows": 60, "persist_windows": 2, "rf_threshold": 0.8},
}


def merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge(out[k], v)
        else:
            out[k] = v
    return out


def setup_logging() -> None:
    root = logging.getLogger()
    if root.handlers:
        return
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    fh = logging.handlers.RotatingFileHandler(LOG_DIR / "engine.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(fh)
    root.addHandler(sh)
