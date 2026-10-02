"""Local machine learning (scikit-learn). Output is a *signal* that is combined with rules; never proof of attack.

* IsolationForest: unsupervised anomaly detection, trained on this PC's own recent traffic
  (learning period assumes the machine was behaving normally; use "Re-learn baseline" if not).
* RandomForest: optional supervised classifier, used only when a labelled CSV is supplied.
"""
import logging
import threading
from pathlib import Path

import numpy as np

log = logging.getLogger("ml")
FEATURES = ["packet_rate", "byte_rate", "connection_count", "new_flow_rate", "dport_diversity", "syn_ratio",
            "failed_logins", "process_creation_rate", "file_mod_rate", "outbound_conn_freq"]
def to_vector(f: dict) -> list[float]:
    return [float(f.get(k, 0.0)) for k in FEATURES]


class MLDetector:
    def __init__(self, models_dir: Path, get_settings):
        self.dir, self._get = Path(models_dir), get_settings
        self.dir.mkdir(parents=True, exist_ok=True)
        self.buffer: list[list[float]] = []
        self.iso = None
        self.rf = None
        self.thr = None
        self.lo = None
        self.lock = threading.Lock()
        self.streak = 0
        self._load()

    @property
    def cfg(self):
        return self._get()["ml"]

    # -- persistence ------------------------------------------------------------------
    def _load(self):
        try:
            import joblib
            p = self.dir / "isolation_forest.joblib"
            if p.exists():
                d = joblib.load(p)
                self.iso, self.thr, self.lo = d["model"], d["thr"], d["lo"]
            p = self.dir / "random_forest.joblib"
            if p.exists():
                self.rf = joblib.load(p)
        except Exception:
            log.exception("could not load models")

    def status(self) -> dict:
        return {"enabled": self.cfg["enabled"], "isolation_forest": "trained" if self.iso else
                f"learning ({len(self.buffer)}/{self.cfg['min_train_windows']} windows)",
                "random_forest": "trained" if self.rf else "not trained (needs labelled CSV)"}

    def relearn(self):
        with self.lock:
            self.iso = self.thr = self.lo = None
            self.buffer.clear()
            p = self.dir / "isolation_forest.joblib"
            if p.exists():
                p.unlink()

    # -- training ------------------------------------------------------------------------
    def _fit_iso(self, X: np.ndarray):
        import joblib
        from sklearn.ensemble import IsolationForest
        model = IsolationForest(n_estimators=150, contamination="auto", random_state=42).fit(X)
        raw = -model.score_samples(X)
        self.thr = float(np.percentile(raw, 99) * 1.15)
        self.lo = float(np.median(raw))
        self.iso = model
        joblib.dump({"model": model, "thr": self.thr, "lo": self.lo}, self.dir / "isolation_forest.joblib")
        log.info("IsolationForest trained on %d windows", len(X))

    def train_supervised(self, csv_path: str) -> dict:
        import joblib
        import pandas as pd
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import classification_report
        from sklearn.model_selection import train_test_split
        df = pd.read_csv(csv_path)
        missing = [c for c in FEATURES + ["label"] if c not in df.columns]
        if missing:
            raise ValueError(f"CSV is missing columns: {missing}")
        X, y = df[FEATURES].fillna(0), df["label"].astype(int)
        if y.nunique() < 2:
            raise ValueError("label column needs both 0 (benign) and 1 (attack) rows")
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42)
        rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1).fit(Xtr, ytr)
        rep = classification_report(yte, rf.predict(Xte), output_dict=True, zero_division=0)
        joblib.dump(rf, self.dir / "random_forest.joblib")
        self.rf = rf
        return {"rows": int(len(df)), "report": rep}

    # -- inference ---------------------------------------------------------------------------
    def score(self, feats: dict) -> dict:
        """Returns {anomaly: bool, score: 0..1, method, persistent: bool}. Learns during the initial period."""
        vec = to_vector(feats)
        out = {"anomaly": False, "score": 0.0, "method": "none", "persistent": False, "status": self.status()}
        if not self.cfg["enabled"]:
            return out
        with self.lock:
            if self.iso is None:
                self.buffer.append(vec)
                if len(self.buffer) >= self.cfg["min_train_windows"]:
                    try:
                        self._fit_iso(np.array(self.buffer))
                    except Exception:
                        log.exception("IsolationForest training failed")
                out["method"] = "learning"
                return out
            raw = float(-self.iso.score_samples(np.array([vec]))[0])
            span = max(1e-6, self.thr - self.lo)
            out["score"] = float(min(1.0, max(0.0, (raw - self.lo) / span)) * 0.99)
            out["anomaly"] = raw > self.thr
            out["method"] = "isolation_forest"
            if self.rf is not None:
                import pandas as pd
                p = float(self.rf.predict_proba(pd.DataFrame([vec], columns=FEATURES))[0][-1])
                if p >= self.cfg["rf_threshold"]:
                    out["anomaly"], out["method"] = True, "isolation_forest+random_forest"
                out["score"] = max(out["score"], p)
            self.streak = self.streak + 1 if out["anomaly"] else 0
            out["persistent"] = self.streak >= self.cfg["persist_windows"]
        return out