"""Collect every number the report quotes into report/facts.json.

    python report/facts.py

The report builder (build_report.js) may only quote values from this file, and
this file only reads results/tables, results/datasets, models/ and run manifests.
"""
import glob
import json
import os

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T = os.path.join(ROOT, "results", "tables")
LABEL = {"xgb": "XGBoost", "rf": "Random forest", "dt": "Decision tree",
         "lr": "Logistic regression", "svm": "RBF SVM", "ae": "Autoencoder",
         "threshold": "Static threshold", "none": "No defense"}


def f3(x):
    return "n/a" if pd.isna(x) else f"{x:.3f}"


def f1d(x):
    return "n/a" if pd.isna(x) else f"{x:.1f}"


def f2(x):
    return "n/a" if pd.isna(x) else f"{x:.2f}"


def pct(x, nd=1):
    return "n/a" if pd.isna(x) else f"{100 * x:.{nd}f} %"


def ci(lo, hi, fmt=f3):
    return f"[{fmt(lo)}, {fmt(hi)}]"


def read(name):
    p = os.path.join(T, name)
    return pd.read_csv(p) if os.path.exists(p) else None


def static_facts(F):
    runs = {p: sum(1 for m in glob.glob(os.path.join(ROOT, "results", "runs", p, "*",
                                                     "manifest.json"))
                   if json.load(open(m)).get("status") == "done")
            for p in "ABCO"}
    for p, n in runs.items():
        F[f"runs_{p}"] = n
    F["n_runs_total"] = sum(runs.values())
    with open(os.path.join(ROOT, "models", "train_report.json")) as f:
        tr = json.load(f)
    F["thr_pps"] = f"{tr['thresholds']['threshold']:.0f}"
    F["ae_thr"] = f2(tr["thresholds"]["ae"])
    for name, v in tr["cv"].items():
        F[f"cv_{name}_f1"] = f3(v["f1"])
        F[f"cv_{name}_auc"] = f3(v["roc_auc"])
    clean = os.path.join(ROOT, "models", "retrain_clean", "train_report.json")
    if os.path.exists(clean):
        cr = json.load(open(clean))
        F["clean_proposed"] = LABEL[cr["proposed"]]
        F["clean_thr_pps"] = f"{cr['thresholds']['threshold']:.0f}"
        for name, v in cr["cv"].items():
            F[f"cvclean_{name}_f1"] = f3(v["f1"])
    from sdnddos.topo import ingress_switch
    spurious = 0
    for d in glob.glob(os.path.join(ROOT, "results", "runs", "A", "*")):
        m = json.load(open(os.path.join(d, "manifest.json")))
        f = pd.read_csv(os.path.join(d, "features.csv"), usecols=["src", "dpid"])
        spurious += sum(ingress_switch(m["size"], s) != p for s, p in zip(f.src, f.dpid))
    F["spurious_rows"] = str(spurious)
    F["train_rows"] = f"{tr['rows']:,}"
    F["train_attack_rows"] = f"{tr['attack_rows']:,}"
    F["cv_rows"] = [[LABEL[n], f3(v["f1"]), f3(v["roc_auc"]),
                     F.get(f"cvclean_{n}_f1", "n/a"),
                     ("proposed" if n == tr["proposed"] else "")]
                    for n, v in sorted(tr["cv"].items(), key=lambda kv: -kv[1]["f1"])]

    stats = json.load(open(os.path.join(ROOT, "data", "cic", "cic_sample.stats.json")))
    F["cic_rows"] = f"{stats['rows_out']:,}"
    F["cic_rows_in"] = f"{sum(s['rows_in'] for s in stats['files']):,}"
    counts = read("cic_sample_counts.csv")
    rows = []
    for day, g in counts.groupby("day"):
        ben = int(g[g.Label.str.upper() == "BENIGN"].rows.sum())
        att = g[g.Label.str.upper() != "BENIGN"]
        rows.append([day, f"{ben:,}", f"{int(att.rows.sum()):,}",
                     ", ".join(sorted(att.Label.unique()))])
    F["cic_count_rows"] = rows
    df = pd.read_parquet(os.path.join(ROOT, "data", "cic", "cic_sample.parquet"),
                         columns=None)
    from analysis.cic_experiments import ID_COLS
    F["cic_full_nfeat"] = str(len([c for c in df.columns if c not in ID_COLS]))
    F["cic_benign_share"] = pct((df.Label.str.upper() == "BENIGN").mean())

    mn = []
    for p, use in [("A", "Training and model selection (GroupKFold by run)"),
                   ("B", "Held-out evaluation, core matrix"),
                   ("C", "Held-out evaluation, network conditions")]:
        path = os.path.join(ROOT, "results", "datasets", f"{p}.parquet")
        if os.path.exists(path):
            d = pd.read_parquet(path, columns=["run_id", "label"])
            mn.append([p, str(d.run_id.nunique()), f"{len(d):,}",
                       f"{int(d.label.sum()):,}", use])
    F["mn_data_rows"] = mn


def main():
    F = {}
    static_facts(F)
    try:
        from report.facts_results import results_facts
        results_facts(F)
    except ImportError as e:
        print("results facts not available:", e)
    with open(os.path.join(ROOT, "report", "facts.json"), "w") as f:
        json.dump(F, f, indent=1, default=str)
    print(f"{len(F)} facts written")


if __name__ == "__main__":
    main()
