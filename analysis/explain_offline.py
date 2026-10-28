"""Global SHAP attributions, block-decision attributions, and inference timing.

    python analysis/explain_offline.py  ->  results/tables/shap_*.csv,
                                            results/tables/inference_*.csv,
                                            results/shap_values_<det>.npz
"""
import glob
import json
import os
import time
from collections import Counter

import joblib
import numpy as np
import pandas as pd
import shap

from sdnddos.config import FEATURES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLES = os.path.join(ROOT, "results", "tables")
N_SHAP = 3000
SEED = 3


def global_shap(bundle, df):
    sample = df.sample(min(N_SHAP, len(df)), random_state=SEED)
    X = sample[FEATURES].to_numpy(float)
    rows = []
    for det in ["dt", "rf", "xgb"]:
        vals = np.asarray(shap.TreeExplainer(bundle[det].model).shap_values(X))
        if vals.ndim == 3:   # sklearn: (rows, features, classes) -> attack class
            vals = vals[:, :, 1]
        np.savez_compressed(os.path.join(ROOT, "results", f"shap_values_{det}.npz"),
                            shap=vals, X=X, y=sample.label.to_numpy(),
                            features=np.array(FEATURES))
        imp = np.abs(vals).mean(axis=0)
        for f, v in zip(FEATURES, imp):
            rows.append({"detector": det, "feature": f, "mean_abs_shap": v})
    return pd.DataFrame(rows)


def block_attributions(phases):
    """Top-ranked feature of every block decision logged live by the controller."""
    rows = []
    for phase in phases:
        for ev_path in glob.glob(os.path.join(ROOT, "results", "runs", phase, "*",
                                              "events.csv")):
            ev = pd.read_csv(ev_path)
            for _, r in ev[(ev.event == "block") & ev.attribution.notna()].iterrows():
                attr = json.loads(r.attribution)
                rows.append({"phase": phase, "detector": r.detector, "src": r.src,
                             "top1": attr[0][0], "top2": attr[1][0] if len(attr) > 1
                             else None, "top1_value": attr[0][1]})
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    counts = []
    for det, g in df.groupby("detector"):
        for f, n in Counter(g.top1).most_common():
            counts.append({"detector": det, "top1_feature": f, "blocks": n,
                           "share": n / len(g)})
    return pd.DataFrame(counts)


def bench(bundle, df, reps=300):
    rows = []
    for n in [1, 12]:
        X = df[FEATURES].sample(n, random_state=SEED).to_numpy(float)
        for det, d in sorted(bundle.items()):
            d.score(X)
            ts = []
            for _ in range(reps):
                t = time.perf_counter()
                d.score(X)
                ts.append((time.perf_counter() - t) * 1e3)
            rows.append({"detector": det, "batch": n, "ms_median": np.median(ts),
                         "ms_p95": np.percentile(ts, 95)})
    return pd.DataFrame(rows)


def live_inference(phases):
    """Per-detector inference time measured inside the controller (shadow mode:
    every detector scores every poll), over polls that had sources to score."""
    frames = []
    for phase in phases:
        for path in glob.glob(os.path.join(ROOT, "results", "runs", phase, "*",
                                           "timing.csv")):
            t = pd.read_csv(path)
            frames.append(t[t.n_sources > 0])
    t = pd.concat(frames)
    rows = [{"detector": c[3:], "polls": len(t), "ms_mean": t[c].mean(),
             "ms_p95": t[c].quantile(0.95), "sources_mean": t.n_sources.mean()}
            for c in t.columns if c.startswith("ms_") and c != "ms_total"]
    rows.append({"detector": "total_poll", "polls": len(t),
                 "ms_mean": t.ms_total.mean(), "ms_p95": t.ms_total.quantile(0.95),
                 "sources_mean": t.n_sources.mean()})
    return pd.DataFrame(rows)


def main():
    bundle = joblib.load(os.path.join(ROOT, "models", "detectors.joblib"))
    df = pd.read_parquet(os.path.join(ROOT, "results", "datasets", "B.parquet"))
    df = df[df["mode"] == "none"]
    os.makedirs(TABLES, exist_ok=True)
    global_shap(bundle, df).to_csv(os.path.join(TABLES, "shap_global.csv"),
                                   index=False)
    block_attributions(["B", "C"]).to_csv(
        os.path.join(TABLES, "shap_block_decisions.csv"), index=False)
    bench(bundle, df).to_csv(os.path.join(TABLES, "inference_bench.csv"), index=False)
    live_inference(["B", "C"]).to_csv(os.path.join(TABLES, "inference_live.csv"),
                                      index=False)
    print("wrote shap + bench tables")


if __name__ == "__main__":
    main()
