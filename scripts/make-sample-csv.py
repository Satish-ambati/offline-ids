"""Generate a synthetic labelled CSV for Random Forest training.

The column set is imported from the engine itself so it can never drift from what
security-engine/ml/detector.py scores at inference time. The value ranges mirror the
per-tick features built in security-engine/core.py:329-332, so the resulting model is at
least dimensionally compatible with live data.

This is demo material: it proves the training pipeline works end to end. It teaches the
model the shapes written below and nothing about real traffic, so a model trained on it
will not detect real attacks. Collect labelled data from a real system for that.

    python scripts/make-sample-csv.py                      # 2000 rows -> models/labeled_training.csv
    python scripts/make-sample-csv.py --rows 5000 --out D:/tmp/train.csv --seed 7
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "security-engine"

# Import the authoritative column order from the engine; fall back to a copy if unavailable.
FALLBACK = ["packet_rate", "byte_rate", "connection_count", "new_flow_rate", "dport_diversity",
            "syn_ratio", "failed_logins", "process_creation_rate", "file_mod_rate", "outbound_conn_freq"]
sys.path.insert(0, str(ENGINE / "ml"))
try:
    from detector import FEATURES
except Exception:
    FEATURES = FALLBACK
if list(FEATURES) != FALLBACK:
    print(f"! engine feature order changed:\n  engine: {list(FEATURES)}\n  script: {FALLBACK}", file=sys.stderr)

# Per-column clip bounds, chosen so no generated row is absurd (negative rates, syn_ratio > 1).
CLIP = {
    "packet_rate": (0, 20000), "byte_rate": (0, 80_000_000), "connection_count": (0, 5000),
    "new_flow_rate": (0, 300), "dport_diversity": (0, 2000), "syn_ratio": (0.01, 1.0),
    "failed_logins": (0, 60), "process_creation_rate": (0, 40),
    "file_mod_rate": (0, 60), "outbound_conn_freq": (0, 60),
}

# column -> (mean, stddev) for a normal desktop running the engine's default 5 s tick.
BENIGN = {
    "packet_rate": (320, 180), "byte_rate": (480_000, 350_000), "connection_count": (85, 45),
    "new_flow_rate": (6, 5), "dport_diversity": (9, 6), "syn_ratio": (0.34, 0.14),
    "failed_logins": (0.03, 0.17), "process_creation_rate": (0.12, 0.15),
    "file_mod_rate": (0.05, 0.08), "outbound_conn_freq": (0.35, 0.40),
}

# Attack archetypes, so the model learns more than one attack shape instead of a single blob.
# weight = share of the attack class. Values are overrides on top of BENIGN.
ATTACKS = [
    ("port scan", 0.18, {
        "packet_rate": (900, 400), "new_flow_rate": (55, 18), "dport_diversity": (65, 22),
        "byte_rate": (220_000, 120_000), "syn_ratio": (0.72, 0.10)}),
    ("syn flood", 0.18, {
        "packet_rate": (5200, 1800), "byte_rate": (1_100_000, 500_000), "syn_ratio": (0.97, 0.02),
        "new_flow_rate": (30, 12), "connection_count": (200, 70), "dport_diversity": (12, 6)}),
    ("brute force", 0.16, {
        "failed_logins": (6.5, 3.0), "packet_rate": (260, 120), "new_flow_rate": (3, 2),
        "dport_diversity": (2, 1.5), "byte_rate": (90_000, 60_000), "outbound_conn_freq": (0.2, 0.3)}),
    ("mass file change", 0.16, {
        "file_mod_rate": (6.5, 2.5), "process_creation_rate": (2.6, 1.2), "byte_rate": (3_500_000, 1_400_000),
        "packet_rate": (700, 300)}),
    ("c2 beacon", 0.16, {
        "outbound_conn_freq": (4.5, 1.6), "byte_rate": (5_200_000, 2_000_000), "packet_rate": (1500, 500),
        "new_flow_rate": (1.2, 0.8), "dport_diversity": (1.5, 1.0), "connection_count": (60, 25)}),
    ("dropper", 0.16, {
        "process_creation_rate": (5.5, 2.0), "file_mod_rate": (3.2, 1.4), "outbound_conn_freq": (1.6, 0.9),
        "byte_rate": (1_800_000, 900_000), "packet_rate": (600, 250)}),
]

LABEL_NOISE = 0.03   # flipped labels, so the report shows a realistic score rather than a fake 1.00


def sample(profile: dict, n: int, rng: np.random.Generator) -> dict:
    out = {}
    for col in FEATURES:
        mean, sd = profile[col]
        v = rng.normal(mean, sd, n)
        lo, hi = CLIP[col]
        out[col] = np.clip(v, lo, hi)
    return out


def build(rows: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    n_attack = int(rows * 0.45)
    n_benign = rows - n_attack

    parts = [pd.DataFrame(sample(BENIGN, n_benign, rng))]

    weights = np.array([w for _, w, _ in ATTACKS], dtype=float)
    weights /= weights.sum()
    counts = rng.multinomial(n_attack, weights)
    for (name, _, overrides), n in zip(ATTACKS, counts):
        if n == 0:
            continue
        df = pd.DataFrame(sample({**BENIGN, **overrides}, n, rng))
        df["archetype"] = name
        parts.append(df)

    df = pd.concat(parts, ignore_index=True)

    # label: 0 = benign, 1 = attack (benign block first, attack blocks after)
    df["label"] = np.r_[np.zeros(n_benign, dtype=int), np.ones(n_attack, dtype=int)]
    if "archetype" in df:
        df.loc[df["archetype"].isna(), "archetype"] = "benign"

    flip = rng.random(len(df)) < LABEL_NOISE
    df.loc[flip, "label"] = 1 - df.loc[flip, "label"]

    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rows", type=int, default=2000, help="total rows (default: 2000)")
    ap.add_argument("--out", default=str(ROOT / "models" / "labeled_training.csv"), help="output CSV path")
    ap.add_argument("--seed", type=int, default=42, help="random seed (default: 42)")
    a = ap.parse_args()

    if a.rows < 8:
        print("--rows must be at least 8 (a 75/25 split needs rows in both classes)", file=sys.stderr)
        return 2

    df = build(a.rows, a.seed)

    missing = [c for c in FEATURES + ["label"] if c not in df.columns]
    if missing:
        print(f"internal error: generated CSV is missing {missing}", file=sys.stderr)
        return 1

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df[FEATURES + ["label"]].to_csv(out, index=False)

    n0, n1 = int((df["label"] == 0).sum()), int((df["label"] == 1).sum())
    print(f"wrote {out}  ({len(df)} rows, {n0} benign / {n1} attack)")
    print(f"columns: {','.join(FEATURES + ['label'])}")
    print("\nper-column range (clip bounds the generator enforces):")
    for c in FEATURES:
        print(f"  {c:<22} {df[c].min():>12.2f} .. {df[c].max():>14.2f}")
    print("\nNext: Threat Detection -> paste this path -> 'Train Random Forest'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())