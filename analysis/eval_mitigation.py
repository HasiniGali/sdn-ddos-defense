"""Closed-loop mitigation results: per-condition summaries and paired comparisons.

    python analysis/eval_mitigation.py B C  ->  results/tables/mitigation_*.csv

Runs of different modes with the same (condition, rep) share a seed, so differences
are computed pairwise. Per-condition n = 5 pairs: a two-sided Wilcoxon test cannot go
below p = 0.0625 at n = 5, so per-condition comparisons report bootstrap CIs of the
mean paired difference, and significance tests are pooled across conditions.
"""
import glob
import json
import os
import sys

import pandas as pd

from analysis.run_metrics import run_metrics
from analysis.stats import mean_ci, paired

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLES = os.path.join(ROOT, "results", "tables")
METRICS = ["tcp_ratio", "tcp_mbps_attack", "udp_loss_pct", "rtt_p50_ms",
           "rtt_p95_ms", "ping_loss_pct", "http_success_pct", "http_p50_ms",
           "ttm_s", "attackers_blocked_frac", "false_blocks", "benign_blocked_s",
           "ctrl_cpu_pct", "ctrl_rss_mb", "poll_ms_mean", "infer_ms_mean"]
# Metrics where a lower value is better (for the direction column).
LOWER_BETTER = {"udp_loss_pct", "rtt_p50_ms", "rtt_p95_ms", "ping_loss_pct",
                "http_p50_ms", "ttm_s", "false_blocks", "benign_blocked_s",
                "ctrl_cpu_pct", "ctrl_rss_mb", "poll_ms_mean", "infer_ms_mean"}


def collect(phase):
    rows = []
    for d in sorted(glob.glob(os.path.join(ROOT, "results", "runs", phase, "*"))):
        if os.path.exists(os.path.join(d, "manifest.json")):
            r = run_metrics(d)
            if r is not None:
                rows.append({"phase": phase, **r})
    return pd.DataFrame(rows)


def summarise(df):
    out = []
    for (phase, cond, mode), g in df.groupby(["phase", "condition", "mode"]):
        row = {"phase": phase, "condition": cond, "mode": mode, "n": len(g)}
        for m in METRICS:
            mean, sd, lo, hi = mean_ci(g[m])
            row.update({f"{m}_mean": mean, f"{m}_sd": sd, f"{m}_lo": lo,
                        f"{m}_hi": hi})
        out.append(row)
    return pd.DataFrame(out)


def compare(df, proposed, baselines, metrics):
    out = []
    for phase, gp in df.groupby("phase"):
        wide = gp.pivot_table(index=["condition", "rep"], columns="mode",
                              values=metrics, dropna=False)
        for base in baselines:
            if base not in wide[metrics[0]].columns or \
                    proposed not in wide[metrics[0]].columns:
                continue
            for m in metrics:
                pooled = paired(wide[m][proposed], wide[m][base])
                out.append({"phase": phase, "condition": "ALL", "proposed": proposed,
                            "baseline": base, "metric": m,
                            "lower_is_better": m in LOWER_BETTER, **pooled})
                for cond in wide.index.get_level_values(0).unique():
                    w = wide.loc[cond]
                    out.append({"phase": phase, "condition": cond,
                                "proposed": proposed, "baseline": base, "metric": m,
                                "lower_is_better": m in LOWER_BETTER,
                                **paired(w[m][proposed], w[m][base])})
    return pd.DataFrame(out)


def main(phases):
    with open(os.path.join(ROOT, "models", "train_report.json")) as f:
        proposed = json.load(f)["proposed"]
    df = pd.concat([collect(p) for p in phases], ignore_index=True)
    os.makedirs(TABLES, exist_ok=True)
    df.to_csv(os.path.join(TABLES, "mitigation_runs.csv"), index=False)
    summarise(df).to_csv(os.path.join(TABLES, "mitigation_summary.csv"), index=False)
    qos = ["tcp_ratio", "udp_loss_pct", "rtt_p50_ms", "rtt_p95_ms", "ping_loss_pct",
           "http_success_pct", "http_p50_ms", "false_blocks", "benign_blocked_s",
           "ttm_s"]
    cmp = compare(df[df.phase != "O"], proposed, ["none", "threshold", "dt"], qos)
    cmp.to_csv(os.path.join(TABLES, "mitigation_paired.csv"), index=False)
    print(f"{len(df)} runs summarised; proposed = {proposed}")


if __name__ == "__main__":
    main(sys.argv[1:])
