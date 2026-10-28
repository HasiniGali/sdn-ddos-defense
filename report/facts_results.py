"""Result facts for the report (called by report/facts.py)."""
import glob
import json
import os
import re

import numpy as np
import pandas as pd

from report.facts import LABEL, ROOT, ci, f1d, f2, f3, pct, read

TYPES = ["syn", "udp", "icmp"]
LEVELS = [("low", 50), ("medium", 500), ("high", 5000)]
MODES_B = ["none", "threshold", "dt", "xgb"]
MODES_C = ["none", "threshold", "xgb"]
OFAT = [("loadhigh", "high benign load"), ("bw50", "50 Mb/s links"),
        ("wan", "WAN: 20 ms, 1 % loss"), ("large", "large topology")]


def pval(p):
    if pd.isna(p):
        return "n/a"
    return "< 0.001" if p < 0.001 else f"{p:.3f}"


def detection(F):
    d = read("detection_overall.csv").set_index("detector")
    order = d.sort_values("f1", ascending=False).index
    F["det_rows"] = [[LABEL[k], f"{f3(r.f1)} {ci(r.f1_lo, r.f1_hi)}", f3(r.precision),
                      f"{f3(r.recall)} {ci(r.recall_lo, r.recall_hi)}",
                      f"{100 * r.fpr:.2f} [{100 * r.fpr_lo:.2f}, {100 * r.fpr_hi:.2f}]",
                      f3(r.roc_auc),
                      f2(r.detect_latency_s), f2(r.sim_block_latency_s),
                      f1d(r.attackers_missed_pct)]
                     for k, r in ((k, d.loc[k]) for k in order)]
    for k, r in d.iterrows():
        F[f"det_{k}_f1"] = f3(r.f1)
        F[f"det_{k}_f1_ci"] = ci(r.f1_lo, r.f1_hi)
        F[f"det_{k}_recall"] = f3(r.recall)
        F[f"det_{k}_precision"] = f3(r.precision)
        F[f"det_{k}_fpr"] = f"{100 * r.fpr:.2f} %"
        F[f"det_{k}_fpr_benign"] = f"{100 * r.fpr_benign_hosts:.1f} %"
        F[f"det_{k}_fpr_server"] = f"{100 * r.fpr_server:.1f} %"
        F[f"det_{k}_auc"] = f3(r.roc_auc)
        F[f"det_{k}_lat"] = f2(r.detect_latency_s)
        F[f"det_{k}_blocklat"] = f2(r.sim_block_latency_s)
        F[f"det_{k}_missed"] = f1d(r.attackers_missed_pct)
    F["det_n"] = f"{int(d.n.iloc[0]):,}"
    F["det_n_attack"] = f"{int(d.n_attack.iloc[0]):,}"

    pc = read("detection_by_condition.csv")
    rows = []
    for t in TYPES:
        for lv, pps in LEVELS:
            g = pc[(pc.condition == f"{t}-{lv}")].set_index("detector")
            if g.empty:
                continue
            rows.append([f"{t.upper()} {lv} ({pps} pps)",
                         *[f3(g.recall.get(k)) for k in ["xgb", "rf", "svm", "dt",
                                                          "threshold"]],
                         *[f"{100 * g.fpr.get(k):.2f}" for k in ["xgb", "dt",
                                                                 "threshold"]]])
    F["det_cond_rows"] = rows
    rows = []
    for t in TYPES:
        for v, lab in OFAT:
            g = pc[pc.condition == f"{t}-{v}"].set_index("detector")
            if g.empty:
                continue
            rows.append([f"{t.upper()}, {lab}",
                         *[f3(g.f1.get(k)) for k in ["xgb", "dt", "threshold"]],
                         *[f"{100 * g.fpr.get(k):.2f}" for k in ["xgb", "dt",
                                                                 "threshold"]]])
    g = pc[pc.condition == "flashcrowd"].set_index("detector")
    if not g.empty:
        rows.append(["Flash crowd (benign only)", "—", "—", "—",
                     *[f"{100 * g.fpr.get(k):.2f}" for k in ["xgb", "dt",
                                                             "threshold"]]])
    F["det_ofat_rows"] = rows

    pr = read("detection_paired.csv")
    F["det_paired_rows"] = [[LABEL[r.baseline], r.metric.upper(), str(r.n),
                             f"{r.mean_diff:+.4f}", ci(r.ci_lo, r.ci_hi,
                                                       lambda x: f"{x:+.4f}"),
                             pval(r.wilcoxon_p)]
                            for r in pr.itertuples() if r.metric in ("f1", "fpr")]
    for r in pr.itertuples():
        F[f"dpair_{r.baseline}_{r.metric}_diff"] = f"{r.mean_diff:+.3f}"
        F[f"dpair_{r.baseline}_{r.metric}_p"] = pval(r.wilcoxon_p)
        F[f"dpair_{r.baseline}_{r.metric}_ci"] = ci(r.ci_lo, r.ci_hi,
                                                    lambda x: f"{x:+.3f}")

    sw = read("threshold_sweep.csv")
    best = sw.loc[sw.f1.idxmax()]
    F["sweep_best_f1"] = f3(best.f1)
    F["sweep_best_thr"] = f"{best.threshold_pps:.0f}"
    F["sweep_best_fpr"] = f"{100 * best.fpr:.1f} %"
    F["sweep_best_recall"] = f3(best.recall)

    lv = read("live_vs_offline.csv")
    F["live_rows"] = f"{int(lv.rows.iloc[0]):,}"
    F["live_mismatch_max"] = str(int(lv.decision_mismatches.max()))


def _fmt_mean_ci(s, cond, mode, metric, fmt):
    r = s[(s.condition == cond) & (s["mode"] == mode)]
    if r.empty:
        return "n/a"
    r = r.iloc[0]
    m, lo, hi = r[f"{metric}_mean"], r[f"{metric}_lo"], r[f"{metric}_hi"]
    if pd.isna(m):
        return "n/a"
    if pd.isna(lo):
        return fmt(m)
    return f"{fmt(m)} ±{fmt((hi - lo) / 2)}"


def mitigation(F):
    s = read("mitigation_summary.csv")
    runs = read("mitigation_runs.csv")
    sb = s[s.phase == "B"]
    for metric, key, fmt in [("tcp_ratio", "tcp", f2), ("rtt_p50_ms", "rtt", f1d),
                             ("http_success_pct", "http", f1d),
                             ("udp_loss_pct", "udp", f1d)]:
        rows = []
        for t in TYPES:
            for lv, pps in LEVELS:
                cond = f"{t}-{lv}"
                rows.append([f"{t.upper()} {lv}",
                             *[_fmt_mean_ci(sb, cond, m, metric, fmt)
                               for m in MODES_B]])
        F[f"mit_{key}_rows"] = rows
    rows = []
    for t in TYPES:
        for lv, pps in LEVELS:
            cond = f"{t}-{lv}"
            row = [f"{t.upper()} {lv}"]
            for m in ["threshold", "dt", "xgb"]:
                row.append(_fmt_mean_ci(sb, cond, m, "ttm_s", f2))
            for m in ["threshold", "dt", "xgb"]:
                r = sb[(sb.condition == cond) & (sb["mode"] == m)]
                row.append(f1d(r.false_blocks_mean.iloc[0]) if len(r) else "n/a")
            rows.append(row)
    F["mit_ttm_rows"] = rows

    sc = s[s.phase == "C"]
    rows = []
    for t in TYPES:
        for v, lab in OFAT:
            cond = f"{t}-{v}"
            rows.append([f"{t.upper()}, {lab}",
                         *[_fmt_mean_ci(sc, cond, m, "tcp_ratio", f2) for m in MODES_C],
                         *[_fmt_mean_ci(sc, cond, m, "rtt_p50_ms", f1d)
                           for m in MODES_C]])
    F["ofat_rows"] = rows
    fc = sc[sc.condition == "flashcrowd"].set_index("mode")
    F["flash_rows"] = [[LABEL[m], f1d(fc.false_blocks_mean.get(m)),
                        f1d(fc.benign_blocked_s_mean.get(m)),
                        _fmt_mean_ci(sc, "flashcrowd", m, "tcp_ratio", f2),
                        _fmt_mean_ci(sc, "flashcrowd", m, "http_success_pct", f1d)]
                       for m in MODES_C if m in fc.index]
    for m in MODES_C:
        if m in fc.index:
            F[f"flash_{m}_fb"] = f1d(fc.false_blocks_mean[m])
            F[f"flash_{m}_blocked_s"] = f1d(fc.benign_blocked_s_mean[m])

    # Pooled paired comparisons (proposed vs baselines), per phase.
    pr = read("mitigation_paired.csv")
    allc = pr[pr.condition == "ALL"]
    names = {"tcp_ratio": "TCP goodput / offered", "rtt_p50_ms": "Ping RTT p50 (ms)",
             "rtt_p95_ms": "Ping RTT p95 (ms)", "ping_loss_pct": "Ping loss (%)",
             "http_success_pct": "HTTP success (%)", "http_p50_ms": "HTTP p50 (ms)",
             "udp_loss_pct": "Benign UDP loss (%)", "false_blocks": "False blocks",
             "benign_blocked_s": "Benign blocked (s)", "ttm_s": "Time to mitigation (s)"}
    for phase in ["B", "C"]:
        rows = []
        for r in allc[allc.phase == phase].itertuples():
            if r.metric not in names or r.n == 0:
                continue
            better = (r.mean_diff < 0) if r.lower_is_better else (r.mean_diff > 0)
            sig = r.wilcoxon_p < 0.05 and not (r.ci_lo <= 0 <= r.ci_hi)
            verdict = ("XGBoost better" if better else "XGBoost worse") if sig \
                else "no significant difference"
            rows.append([LABEL[r.baseline], names[r.metric], str(r.n),
                         f"{r.mean_diff:+.3g}", ci(r.ci_lo, r.ci_hi,
                                                   lambda x: f"{x:+.3g}"),
                         pval(r.wilcoxon_p), verdict])
            F[f"mpair_{phase}_{r.baseline}_{r.metric}"] = f"{r.mean_diff:+.3g}"
            F[f"mpair_{phase}_{r.baseline}_{r.metric}_ci"] = ci(
                r.ci_lo, r.ci_hi, lambda x: f"{x:+.3g}")
            F[f"mpair_{phase}_{r.baseline}_{r.metric}_p"] = pval(r.wilcoxon_p)
            F[f"mpair_{phase}_{r.baseline}_{r.metric}_verdict"] = verdict
        F[f"mpair_{phase}_rows"] = rows
    # Per-condition cases where XGBoost is *worse* (CI entirely on the bad side).
    worse = []
    for r in pr[(pr.condition != "ALL")].itertuples():
        if r.n < 3 or pd.isna(r.ci_lo) or r.metric not in names:
            continue
        bad = (r.ci_lo > 0) if r.lower_is_better else (r.ci_hi < 0)
        if bad:
            worse.append([r.phase, r.condition, LABEL[r.baseline], names[r.metric],
                          f"{r.mean_diff:+.3g}", ci(r.ci_lo, r.ci_hi,
                                                    lambda x: f"{x:+.3g}")])
    other = [w for w in worse if w[2] != LABEL["threshold"]]
    F["worse_rows"] = other or [["—", "none", "—", "—", "—", "—"]]
    F["n_worse"] = str(len(worse))
    F["n_worse_thr"] = str(len(worse) - len(other))
    F["n_worse_other"] = str(len(other))
    by = pd.Series([w[3] for w in worse if w[2] == LABEL["threshold"]]).value_counts()
    F["worse_thr_metrics"] = "; ".join(f"{m} ({n})" for m, n in by.items())

    # Headline numbers for the abstract (phase B, all conditions pooled).
    b = runs[runs.phase == "B"]
    for m in MODES_B:
        g = b[b["mode"] == m]
        F[f"B_{m}_tcp"] = f2(g.tcp_ratio.mean())
        F[f"B_{m}_rtt"] = f1d(g.rtt_p50_ms.mean())
        F[f"B_{m}_http"] = f1d(g.http_success_pct.mean())
        F[f"B_{m}_fb"] = f2(g.false_blocks.mean())
        F[f"B_{m}_ttm"] = f2(g.ttm_s.mean())
        F[f"B_{m}_blockedfrac"] = pct(g.attackers_blocked_frac.mean(), 0)
    hi = b[b.attack_pps == 5000]
    for m in MODES_B:
        F[f"Bhigh_{m}_tcp"] = f2(hi[hi["mode"] == m].tcp_ratio.mean())
        F[f"Bhigh_{m}_rtt"] = f1d(hi[hi["mode"] == m].rtt_p50_ms.mean())

    live = read("inference_live.csv").set_index("detector")
    bench = read("inference_bench.csv")
    bb = bench[bench.batch == 12].set_index("detector")
    F["ovh_rows"] = [[LABEL[m], f3(live.ms_mean[m]), f3(live.ms_p95[m]),
                      f3(bb.ms_median[m])]
                     for m in ["threshold", "dt", "lr", "rf", "xgb", "svm", "ae"]]
    for m in live.index:
        F[f"live_{m}_ms"] = f3(live.ms_mean[m])
    F["live_polls"] = f"{int(live.polls.iloc[0]):,}"
    F["live_sources"] = f1d(live.sources_mean.iloc[0])
    F["poll_total_ms"] = f3(live.ms_mean["total_poll"])
    F["poll_total_p95"] = f3(live.ms_p95["total_poll"])
    F["ctrl_cpu_B"] = f1d(b.ctrl_cpu_pct.mean())
    F["ctrl_cpu_B_max"] = f1d(b.ctrl_cpu_pct.max())
    F["ctrl_rss_B"] = f1d(b.ctrl_rss_mb.mean())
    for m in bb.index:
        F[f"bench_{m}_ms"] = f3(bb.ms_median[m])


def shap_facts(F):
    g = read("shap_global.csv")
    x = g[g.detector == "xgb"].sort_values("mean_abs_shap", ascending=False)
    F["shap_top"] = ", ".join(f"`{r.feature}`" for r in x.head(4).itertuples())
    F["shap_rows"] = [[r.feature, f3(r.mean_abs_shap),
                       f3(g[(g.detector == "rf") & (g.feature == r.feature)]
                          .mean_abs_shap.iloc[0]),
                       f3(g[(g.detector == "dt") & (g.feature == r.feature)]
                          .mean_abs_shap.iloc[0])] for r in x.itertuples()]
    b = read("shap_block_decisions.csv")
    if b is not None and len(b):
        bx = b[b.detector == "xgb"].sort_values("blocks", ascending=False)
        F["block_rows"] = [[r.top1_feature, str(r.blocks), pct(r.share)]
                           for r in bx.itertuples()]
        F["block_n"] = str(int(bx.blocks.sum()))
        F["block_top"] = bx.top1_feature.iloc[0]
        F["block_top_share"] = pct(bx.share.iloc[0])


def cic_facts(F):
    c = read("cic_experiments.csv")
    names = {"FULL/random-01-12": "FULL, random 70/30 (day 01-12)",
             "FULL/day-01-12->03-11": "FULL, train 01-12 / test 03-11",
             "OF/random-01-12": "OF, random 70/30 (day 01-12)",
             "OF/day-01-12->03-11": "OF, train 01-12 / test 03-11"}
    F["cic_rows_tab"] = [[names[r.experiment], LABEL[r.model], f"{r.f1:.4f}",
                          f"{r.recall:.4f}", f"{100 * r.fpr:.2f}",
                          f"{r.balanced_acc:.4f}", f"{r.roc_auc:.4f}"]
                         for r in c.itertuples()]
    for r in c.itertuples():
        k = r.experiment.replace("/", "_").replace("->", "_").replace("-", "")
        F[f"cic_{k}_{r.model}_f1"] = f"{r.f1:.3f}"
        F[f"cic_{k}_{r.model}_recall"] = f"{r.recall:.3f}"
        F[f"cic_{k}_{r.model}_fpr"] = f"{100 * r.fpr:.1f} %"
        F[f"cic_{k}_{r.model}_bal"] = f"{r.balanced_acc:.3f}"
    x = read("xdom_experiments.csv")
    if x is not None:
        names = {"XDOM/CIC->Mininet-B": "CICDDoS2019 (OF) → Mininet phase B",
                 "XDOM/Mininet-A->CIC": "Mininet phase A → CICDDoS2019 (OF)",
                 "XDOM/Mininet-A->Mininet-B": "Mininet A → Mininet B (reference)"}
        F["xdom_rows"] = [[names[r.experiment], LABEL[r.model], str(r.n_test),
                           f"{r.f1:.3f}", f"{r.recall:.3f}", f"{100 * r.fpr:.1f}",
                           f"{r.balanced_acc:.3f}"] for r in x.itertuples()]
        for r in x.itertuples():
            k = r.experiment.split("/")[1].replace("->", "_").replace("-", "")
            F[f"xdom_{k}_{r.model}_bal"] = f"{r.balanced_acc:.3f}"
            F[f"xdom_{k}_{r.model}_f1"] = f"{r.f1:.3f}"


def hping_rates(F):
    """Attack rates: configured, sent by hping3 (its own counter) and seen by the
    controller at the ingress switch (attack intervals, mode none, phase B)."""
    ds = pd.read_parquet(os.path.join(ROOT, "results", "datasets", "B.parquet"))
    seen = ds[(ds["mode"] == "none") & (ds.label == 1) & (ds.role == "attacker")]
    rows = []
    for t in TYPES:
        for lv, pps in LEVELS:
            rates = []
            for run in glob.glob(os.path.join(ROOT, "results", "runs", "B",
                                              f"B-{t}-{lv}-r*-none")):
                mpath = os.path.join(run, "manifest.json")
                if not os.path.exists(mpath):
                    continue
                m = json.load(open(mpath))
                for a in m.get("attacks", []):
                    log = open(os.path.join(run, f"hping3_{a['host']}.log")).read()
                    mm = re.search(r"(\d+) packets transmitted", log)
                    if mm:
                        rates.append(int(mm[1]) / (a["end"] - a["start"]))
            g = seen[seen.condition == f"{t}-{lv}"]
            # Median over intervals: edge intervals are only partly inside the attack.
            if rates:
                rows.append([f"{t.upper()} {lv}", str(pps), f"{np.mean(rates):.0f}",
                             f"{g.pps.median():.0f}" if len(g) else "n/a",
                             str(len(rates))])
                F[f"seen_{t}_{lv}"] = f"{g.pps.median():.0f}"
                F[f"sent_{t}_{lv}"] = f"{np.mean(rates):.0f}"
    F["hping_rows"] = rows


def results_facts(F):
    detection(F)
    mitigation(F)
    shap_facts(F)
    cic_facts(F)
    hping_rates(F)
