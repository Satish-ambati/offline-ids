"""Configurable, application-defined risk scoring.

The score is a weighted combination of distinct behavioural signals plus a bonus for
correlation across signal types. It is NOT a probability that an attack is happening.
"""
import time


class RiskEngine:
    def __init__(self, get_settings):
        self._get = get_settings

    @property
    def cfg(self) -> dict:
        return self._get()["risk"]

    def level(self, score: float) -> str:
        lv = self.cfg["levels"]
        if score >= lv["critical"]:
            return "CRITICAL"
        if score >= lv["high"]:
            return "HIGH"
        if score >= lv["medium"]:
            return "MEDIUM"
        return "LOW"

    def score(self, signals) -> tuple[int, dict]:
        """signals: objects with .kind and optional .scale. Returns (score 0-100, components)."""
        weights = self.cfg["weights"]
        best: dict[str, float] = {}
        for s in signals:
            w = weights.get(s.kind, 10) * getattr(s, "scale", 1.0)
            best[s.kind] = max(best.get(s.kind, 0), w)
        base = sum(best.values())
        bonus = self.cfg["correlation_bonus"] * max(0, len(best) - 1)
        total = min(100, int(round(base + bonus)))
        comps = {k: round(v, 1) for k, v in best.items()}
        comps["_correlation_bonus"] = bonus
        return total, comps

    def host_risk(self, signals, now: float | None = None, horizon: float = 600) -> tuple[int, dict]:
        """Host-wide value for the gauge: recent signals decay linearly to zero."""
        now = now or time.time()

        class _S:
            def __init__(self, kind, scale):
                self.kind, self.scale = kind, scale

        recent = [_S(s.kind, 1 - (now - s.ts) / horizon) for s in signals if 0 <= now - s.ts < horizon]
        return self.score(recent) if recent else (0, {})
