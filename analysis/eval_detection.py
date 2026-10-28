"""Detection metrics on held-out runs, from the shadow scores logged live.

    python analysis/eval_detection.py B C   ->  results/tables/detection_*.csv

Only runs with mode == "none" are used: there no detector alters the traffic, so
every detector is scored on identical, unmitigated traffic. CIs resample whole runs.
"""
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, f1_score, precision_score,
                             recall_score, roc_auc_score)

from analysis.stats import bootstrap_ci, paired
from sdnddos.config import FEATURES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLES = os.path.join(ROOT, "results", "tables")
BOOT_RUNS = 1000


def metrics(y, score, thr):
    pred = score >= thr
    neg = y == 0
    out = {"n": len(y), "n_attack": int(y.sum()),
           "accuracy": float((pred == y).mean()),
           "precision": precision_score(y, pred, zero_division=0),
           "recall": recall_score(y, pred, zero_division=0),
           "f1": f1_score(y, pred, zero_division=0),
           "fpr": float(pred[neg].mean()) if neg.any() else np.nan}
    if 0 < y.sum() < len(y):
        out["roc_auc"] = roc_auc_score(y, score)
        out["pr_auc"] = average_precision_score(y, score)
    return out


def run_bootstrap(df, det, thr, keys, seed=0):
    """95 % CIs of several metrics, resampling whole runs."""
    groups = [(g.label.to_numpy(), g[f"score_{det}"].to_numpy())
              for _, g in df.groupby("run_id")]
    rng = np.random.default_rng(seed)
    vals = {k: [] for k in keys}
    for _ in range(BOOT_RUNS):
        idx = rng.integers(0, len(groups), len(groups))
        y = np.concatenate([groups[i][0] for i in idx])
        s = np.concatenate([groups[i][1] for i in idx])
        m = metrics(y, s, thr)
        for k in keys:
            vals[k].append(m.get(k, np.nan))
    return {k: np.nanquantile(v, [0.025, 0.975]) for k, v in vals.items()}


def first_flag_latency(df, det, thr, confirm):
    """Per (run, attacker): seconds from attack start to the `confirm`-th
    consecutive flagged interval (confirm=1: first detection; 2: simulated block)."""
    out = []
    for (run, src), g in df[df.role == "attacker"].groupby(["run_id", "src"]):
        g = g.sort_values("t")
        att = g[g.label == 1]
        if att.empty:
            continue
        start = att.attack_start.iloc[0]
        flags = (g[f"score_{det}"] >= thr).to_numpy()
        streak, hit = 0, None
        for t, f in zip(g.t, flags):
            if t < start:
                continue
            streak = streak + 1 if f else 0
            if streak >= confirm:
                hit = t - start
                break
        if hit is not None and hit > att.attack_end.iloc[0] - start + 2.0:
            hit = None
        out.append({"run_id": run, "src": src, "latency_s": hit,
                    "condition": g.condition.iloc[0]})
    return pd.DataFrame(out)


def attach_windows(df):
    """Add attack_start/attack_end columns per (run, src) from the manifests."""
    starts, ends = {}, {}
    for run in df.run_id.unique():
        phase = run.split("-")[0]
        with open(os.path.join(ROOT, "results", "runs", phase, run,
                               "manifest.json")) as f:
            m = json.load(f)
        for a in m.get("attacks", []):
            starts[(run, a["ip"])] = a["start"]
            ends[(run, a["ip"])] = a["end"]
    keys = list(zip(df.run_id, df.src))
    df["attack_start"] = [starts.get(k, np.nan) for k in keys]
    df["attack_end"] = [ends.get(k, np.nan) for k in keys]
    return df


def main(phases):
    bundle = joblib.load(os.path.join(ROOT, "models", "detectors.joblib"))
    with open(os.path.join(ROOT, "models", "train_report.json")) as f:
        proposed = json.load(f)["proposed"]
    df = pd.concat([pd.read_parquet(os.path.join(ROOT, "results", "datasets",
                                                 f"{p}.parquet")) for p in phases])
    df = attach_windows(df[df["mode"] == "none"].copy())
    dets = sorted(bundle)
    os.makedirs(TABLES, exist_ok=True)

    # Sanity check: re-scoring the logged features offline reproduces the live
    # decisions. Logged features are rounded to 6 significant digits, so tree scores
    # can move slightly near a split; decisions must still agree (< 0.1 % mismatch).
    X = df[FEATURES].to_numpy(float)
    sanity = []
    for d in dets:
        off, live = bundle[d].score(X), df[f"score_{d}"].to_numpy()
        thr = bundle[d].threshold
        mism = int(((off >= thr) != (live >= thr)).sum())
        sanity.append({"detector": d, "rows": len(df), "decision_mismatches": mism,
                       "max_abs_score_diff": float(np.abs(off - live).max())})
        assert mism <= 0.001 * len(df), (d, mism)
    pd.DataFrame(sanity).to_csv(os.path.join(TABLES, "live_vs_offline.csv"),
                                index=False)

    rows = []
    for d in dets:
        thr = bundle[d].threshold
        m = metrics(df.label.to_numpy(), df[f"score_{d}"].to_numpy(), thr)
        cis = run_bootstrap(df, d, thr, ["f1", "fpr", "recall", "precision",
                                         "roc_auc"])
        for key, (lo, hi) in cis.items():
            m[f"{key}_lo"], m[f"{key}_hi"] = lo, hi
        benign = df[df.role == "benign"]
        server = df[df.role == "server"]
        m["fpr_benign_hosts"] = float((benign[f"score_{d}"] >= thr).mean())
        m["fpr_server"] = float((server[f"score_{d}"] >= thr).mean())
        lat = first_flag_latency(df, d, thr, 1)
        lat2 = first_flag_latency(df, d, thr, 2)
        m["detect_latency_s"] = lat.latency_s.mean()
        m["detect_latency_ci"] = bootstrap_ci(lat.latency_s.dropna())
        m["sim_block_latency_s"] = lat2.latency_s.mean()
        m["attackers_missed_pct"] = 100 * lat2.latency_s.isna().mean()
        rows.append({"detector": d, "threshold": thr, **m})
        print(d, {k: round(v, 3) for k, v in m.items()
                  if isinstance(v, float)}, flush=True)
    pd.DataFrame(rows).to_csv(os.path.join(TABLES, "detection_overall.csv"),
                              index=False)

    # Sensitivity of the static baseline to its one parameter, on held-out data.
    sweep = []
    y = df.label.to_numpy()
    for thr in np.geomspace(5, 20_000, 60):
        m = metrics(y, df.pps.to_numpy(), thr)
        sweep.append({"threshold_pps": thr, "f1": m["f1"], "fpr": m["fpr"],
                      "recall": m["recall"]})
    pd.DataFrame(sweep).to_csv(os.path.join(TABLES, "threshold_sweep.csv"),
                               index=False)

    # Per condition and per attack type / rate.
    per = []
    for keys, g in df.groupby(["condition", "attack_type", "attack_pps",
                               "benign_load", "link_profile", "size"]):
        for d in dets:
            m = metrics(g.label.to_numpy(), g[f"score_{d}"].to_numpy(),
                        bundle[d].threshold)
            per.append({"condition": keys[0], "attack_type": keys[1],
                        "attack_pps": keys[2], "benign_load": keys[3],
                        "link_profile": keys[4], "size": keys[5], "detector": d, **m})
    pd.DataFrame(per).to_csv(os.path.join(TABLES, "detection_by_condition.csv"),
                             index=False)

    # Paired per-run comparison: proposed vs every other detector (F1 and FPR).
    per_run = []
    for run, g in df.groupby("run_id"):
        for d in dets:
            m = metrics(g.label.to_numpy(), g[f"score_{d}"].to_numpy(),
                        bundle[d].threshold)
            per_run.append({"run_id": run, "detector": d, "f1": m["f1"],
                            "fpr": m["fpr"], "recall": m["recall"]})
    pr = pd.DataFrame(per_run).pivot(index="run_id", columns="detector")
    cmp_rows = []
    for d in dets:
        if d == proposed:
            continue
        for key in ["f1", "fpr", "recall"]:
            cmp_rows.append({"proposed": proposed, "baseline": d, "metric": key,
                             **paired(pr[key][proposed], pr[key][d])})
    pd.DataFrame(cmp_rows).to_csv(os.path.join(TABLES, "detection_paired.csv"),
                                  index=False)
    print("wrote detection tables")


if __name__ == "__main__":
    main(sys.argv[1:])
