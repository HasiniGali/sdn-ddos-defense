"""Every figure in the report, from results/tables (and a few raw runs).

    python analysis/plots.py  ->  results/figures/*.png

Colors follow the entity, never its rank: each detector/mode has one fixed color in
every figure. "none" (no defense) is neutral gray. Palette validated with the dataviz
validator (light mode); light hues are always backed by the report's tables.
"""
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLES = os.path.join(ROOT, "results", "tables")
FIG = os.path.join(ROOT, "results", "figures")

SURFACE = "#ffffff"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
COLORS = {"xgb": "#2a78d6", "threshold": "#eb6834", "dt": "#1baf7a",
          "lr": "#eda100", "svm": "#e87ba4", "rf": "#008300", "ae": "#6250d6",
          "none": "#9a9893"}
LABELS = {"xgb": "XGBoost", "rf": "Random forest", "dt": "Decision tree",
          "lr": "Logistic regression", "svm": "RBF SVM", "ae": "Autoencoder",
          "threshold": "Static threshold", "none": "No defense"}
TYPES = ["syn", "udp", "icmp"]
LEVELS = [("low", 50), ("medium", 500), ("high", 5000)]

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2,
    "ytick.color": INK2, "text.color": INK, "axes.grid": True, "grid.color": GRID,
    "grid.linewidth": 0.8, "axes.axisbelow": True, "axes.spines.top": False,
    "axes.spines.right": False, "font.size": 9, "axes.titlesize": 10,
    "legend.frameon": False, "lines.linewidth": 2, "figure.dpi": 200})


def proposed():
    with open(os.path.join(ROOT, "models", "train_report.json")) as f:
        return json.load(f)["proposed"]


def save(fig, name):
    os.makedirs(FIG, exist_ok=True)
    fig.savefig(os.path.join(FIG, name), bbox_inches="tight")
    plt.close(fig)
    print("figure", name)


def _hbar(ax, names, vals, lo, hi, xlabel, fmt="{:.3f}"):
    y = np.arange(len(names))
    ax.barh(y, vals, height=0.6, color=[COLORS[n] for n in names])
    err = np.array([np.asarray(vals) - lo, hi - np.asarray(vals)])
    ax.errorbar(vals, y, xerr=np.clip(err, 0, None), fmt="none", ecolor=INK,
                elinewidth=1, capsize=2)
    ax.set_yticks(y, [LABELS[n] for n in names])
    ax.set_xlabel(xlabel)
    ax.grid(axis="y", visible=False)
    for yi, v in zip(y, vals):
        ax.text(v, yi + 0.36, fmt.format(v), fontsize=7, color=INK2, ha="center")


def fig_detection_overall():
    d = pd.read_csv(os.path.join(TABLES, "detection_overall.csv"))
    d = d.sort_values("f1")
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.8), sharey=True)
    _hbar(axes[0], list(d.detector), d.f1, d.f1_lo, d.f1_hi, "F1 (attack class)")
    _hbar(axes[1], list(d.detector), 100 * d.fpr, 100 * d.fpr_lo, 100 * d.fpr_hi,
          "False-positive rate (%)", fmt="{:.2f} %")
    axes[0].set_xlim(0, 1.08)
    fig.tight_layout()
    save(fig, "fig_detection_overall.png")


def fig_recall_by_rate():
    d = pd.read_csv(os.path.join(TABLES, "detection_by_condition.csv"))
    d = d[d.condition.str.match(r"^(syn|udp|icmp)-(low|medium|high)$")]
    p = proposed()
    dets = ["none"] if False else [p, "dt", "threshold", "ae"]
    fig, axes = plt.subplots(1, 3, figsize=(7.2, 2.4), sharey=True)
    for ax, t in zip(axes, TYPES):
        for det in dets:
            g = d[(d.attack_type == t) & (d.detector == det)].set_index("attack_pps")
            ys = [g.recall.get(pps, np.nan) for _, pps in LEVELS]
            ax.plot(range(3), ys, marker="o", ms=4, color=COLORS[det],
                    label=LABELS[det])
        ax.set_xticks(range(3), [f"{lv}\n{pps} pps" for lv, pps in LEVELS])
        ax.set_title(f"{t.upper()} flood")
        ax.set_ylim(-0.02, 1.05)
    axes[0].set_ylabel("Recall (attack intervals)")
    axes[-1].legend(loc="lower right", fontsize=7)
    fig.tight_layout()
    save(fig, "fig_recall_by_rate.png")


def _grouped(ax, df, modes, metric, conds, xlabels):
    w = 0.8 / len(modes)
    for i, mode in enumerate(modes):
        g = df[df["mode"] == mode].set_index("condition")
        vals = [g[f"{metric}_mean"].get(c, np.nan) for c in conds]
        lo = [g[f"{metric}_lo"].get(c, np.nan) for c in conds]
        hi = [g[f"{metric}_hi"].get(c, np.nan) for c in conds]
        x = np.arange(len(conds)) + (i - (len(modes) - 1) / 2) * w
        ax.bar(x, vals, width=w * 0.9, color=COLORS[mode], label=LABELS[mode])
        err = np.array([np.subtract(vals, lo), np.subtract(hi, vals)])
        ax.errorbar(x, vals, yerr=np.nan_to_num(np.clip(err, 0, None)), fmt="none",
                    ecolor=INK, elinewidth=0.8, capsize=1.5)
    ax.set_xticks(range(len(conds)), xlabels)
    ax.grid(axis="x", visible=False)


def fig_mitigation_core(metric, ylabel, name, ylim=None):
    s = pd.read_csv(os.path.join(TABLES, "mitigation_summary.csv"))
    s = s[s.phase == "B"]
    modes = ["none", "threshold", "dt", proposed()]
    fig, axes = plt.subplots(1, 3, figsize=(7.2, 2.6), sharey=True)
    for ax, t in zip(axes, TYPES):
        conds = [f"{t}-{lv}" for lv, _ in LEVELS]
        _grouped(ax, s, modes, metric, conds, [lv for lv, _ in LEVELS])
        ax.set_title(f"{t.upper()} flood")
        if ylim:
            ax.set_ylim(*ylim)
    axes[0].set_ylabel(ylabel)
    axes[0].legend(loc="best", fontsize=7)
    fig.tight_layout()
    save(fig, name)


def fig_mitigation_ofat(metric, ylabel, name):
    s = pd.read_csv(os.path.join(TABLES, "mitigation_summary.csv"))
    s = s[s.phase == "C"]
    modes = ["none", "threshold", proposed()]
    variants = [("loadhigh", "high load"), ("bw50", "50 Mb/s"), ("wan", "WAN"),
                ("large", "large topo")]
    fig, axes = plt.subplots(1, 3, figsize=(7.2, 2.6), sharey=True)
    for ax, t in zip(axes, TYPES):
        conds = [f"{t}-{v}" for v, _ in variants]
        _grouped(ax, s, modes, metric, conds, [lab for _, lab in variants])
        ax.set_title(f"{t.upper()} flood (500 pps)")
        ax.tick_params(axis="x", labelsize=7)
    axes[0].set_ylabel(ylabel)
    axes[0].legend(loc="best", fontsize=7)
    fig.tight_layout()
    save(fig, name)


def fig_timeseries(cond="udp-high", rep=0):
    """Benign TCP throughput over time in one condition, all modes, same seed."""
    p = proposed()
    fig, ax = plt.subplots(figsize=(7.2, 2.6))
    shade = None
    for mode in ["none", "threshold", "dt", p]:
        run = os.path.join(ROOT, "results", "runs", "B", f"B-{cond}-r{rep}-{mode}")
        with open(os.path.join(run, "manifest.json")) as f:
            m = json.load(f)
        with open(os.path.join(run, "iperf_tcp_b2.json")) as f:
            ivs = json.load(f)["intervals"]
        t = [(i["sum"]["start"] + i["sum"]["end"]) / 2 for i in ivs]
        v = [i["sum"]["bits_per_second"] / 1e6 for i in ivs]
        ax.plot(t, v, color=COLORS[mode], label=LABELS[mode], lw=1.6)
        shade = (min(a["start"] for a in m["attacks"]) - m["t0"],
                 max(a["end"] for a in m["attacks"]) - m["t0"])
    ax.axvspan(*shade, color="#f2f1ee", zorder=0)
    ax.text(shade[0] + 0.5, ax.get_ylim()[1] * 0.95, "attack", color=INK2, fontsize=7,
            va="top")
    ax.set_xlabel("Time since benign traffic start (s)")
    ax.set_ylabel("Benign iperf3 TCP (Mb/s)")
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), fontsize=7, ncol=4)
    fig.tight_layout()
    save(fig, f"fig_timeseries_{cond}.png")


def fig_latency():
    runs = pd.read_csv(os.path.join(TABLES, "mitigation_runs.csv"))
    runs = runs[(runs.phase == "B") & runs["mode"].isin(["threshold", "dt",
                                                         proposed()])]
    fig, axes = plt.subplots(1, 3, figsize=(7.2, 2.4), sharey=True)
    for ax, t in zip(axes, TYPES):
        for i, mode in enumerate(["threshold", "dt", proposed()]):
            for j, (lv, pps) in enumerate(LEVELS):
                g = runs[(runs.attack_type == t) & (runs.attack_pps == pps)
                         & (runs["mode"] == mode)].ttm_s.dropna()
                x = j + (i - 1) * 0.25
                ax.scatter(np.full(len(g), x), g, s=10, color=COLORS[mode],
                           label=LABELS[mode] if j == 0 and t == "syn" else None)
        ax.set_xticks(range(3), [lv for lv, _ in LEVELS])
        ax.set_title(f"{t.upper()} flood")
    axes[0].set_ylabel("Time to mitigation (s)")
    fig.legend(loc="upper center", ncol=3, fontsize=7, bbox_to_anchor=(0.5, 1.06))
    fig.tight_layout()
    save(fig, "fig_time_to_mitigation.png")


def fig_shap():
    p = proposed()
    g = pd.read_csv(os.path.join(TABLES, "shap_global.csv"))
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.0))
    d = g[g.detector == p].sort_values("mean_abs_shap")
    axes[0].barh(d.feature, d.mean_abs_shap, height=0.6, color=COLORS[p])
    axes[0].set_xlabel(f"Mean |SHAP| ({LABELS[p]}, log-odds)")
    axes[0].grid(axis="y", visible=False)
    z = np.load(os.path.join(ROOT, "results", f"shap_values_{p}.npz"),
                allow_pickle=True)
    feats = list(z["features"])
    order = [feats.index(f) for f in d.feature]
    rng = np.random.default_rng(0)
    for row, fi in enumerate(order):
        vals, xs = z["shap"][:, fi], z["X"][:, fi]
        rank = pd.Series(xs).rank(pct=True).to_numpy()
        axes[1].scatter(vals, row + rng.uniform(-0.25, 0.25, len(vals)), s=2,
                        c=rank, cmap="Blues", vmin=-0.2, vmax=1.0, rasterized=True)
    axes[1].set_yticks(range(len(order)), [feats[i] for i in order])
    axes[1].axvline(0, color=INK2, lw=0.8)
    axes[1].set_xlabel("SHAP value per interval (darker = higher feature value)")
    axes[1].grid(axis="y", visible=False)
    fig.tight_layout()
    save(fig, "fig_shap.png")


def fig_cic():
    d = pd.read_csv(os.path.join(TABLES, "cic_experiments.csv"))
    exps = ["FULL/random-01-12", "OF/random-01-12", "FULL/day-01-12->03-11",
            "OF/day-01-12->03-11"]
    labels = ["FULL\nrandom", "OF\nrandom", "FULL\nday split", "OF\nday split"]
    models = ["xgb", "rf", "dt", "lr", "threshold"]
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.6), sharey=False)
    w = 0.8 / len(models)
    for k, (metric, lab) in enumerate([("f1", "F1 (attack)"),
                                       ("fpr", "False-positive rate")]):
        ax = axes[k]
        for i, m in enumerate(models):
            g = d[d.model == m].set_index("experiment")
            vals = [g[metric].get(e, np.nan) for e in exps]
            ax.bar(np.arange(4) + (i - 2) * w, vals, width=w * 0.9, color=COLORS[m],
                   label=LABELS[m])
        ax.set_xticks(range(4), labels, fontsize=7)
        ax.set_ylabel(lab)
        ax.grid(axis="x", visible=False)
    axes[1].legend(fontsize=7, loc="upper left")
    fig.tight_layout()
    save(fig, "fig_cic.png")


def fig_overhead():
    b = pd.read_csv(os.path.join(TABLES, "inference_bench.csv"))
    live = pd.read_csv(os.path.join(TABLES, "inference_live.csv")).set_index("detector")
    order = ["threshold", "dt", "lr", "rf", "xgb", "svm", "ae"]
    g = b[b.batch == 12].set_index("detector")
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.6), sharey=True)
    for ax, vals, lab in [
            (axes[0], [live.ms_mean[o] for o in order],
             "Inside the controller, mean per poll (ms, log)"),
            (axes[1], [g.ms_median[o] for o in order],
             "Offline benchmark, 12 sources (ms, log)")]:
        ax.barh(range(len(order)), vals, height=0.6, color=[COLORS[o] for o in order])
        ax.set_xscale("log")
        ax.set_xlabel(lab)
        ax.grid(axis="y", visible=False)
    axes[0].set_yticks(range(len(order)), [LABELS[o] for o in order])
    fig.tight_layout()
    save(fig, "fig_overhead.png")


def fig_threshold_sweep():
    d = pd.read_csv(os.path.join(TABLES, "threshold_sweep.csv"))
    fig, ax = plt.subplots(figsize=(4.8, 2.6))
    ax.plot(d.threshold_pps, d.f1, color=COLORS["threshold"], label="F1")
    ax.plot(d.threshold_pps, 1 - d.fpr, color=INK2, lw=1.2, label="1 - FPR")
    ax.plot(d.threshold_pps, d.recall, color="#6250d6", lw=1.2, label="Recall")
    with open(os.path.join(ROOT, "models", "train_report.json")) as f:
        t = json.load(f)["thresholds"]["threshold"]
    ax.axvline(t, color=INK, lw=0.8)
    ax.text(t * 1.05, 0.05, f"tuned on phase A: {t:.0f} pps", fontsize=7, color=INK2)
    ax.set_xscale("log")
    ax.set_xlabel("Static pps threshold (log)")
    ax.set_ylabel("Held-out score")
    ax.legend(fontsize=7, loc="center left")
    fig.tight_layout()
    save(fig, "fig_threshold_sweep.png")


def _box(ax, x, y, w, h, text, fill="#eef3fb", edge="#2a78d6", size=7.5):
    from matplotlib.patches import FancyBboxPatch
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                                fc=fill, ec=edge, lw=1))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size,
            color=INK, wrap=True)


def _arrow(ax, x1, y1, x2, y2, text=None, color=INK2):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", color=color, lw=1, shrinkA=2, shrinkB=2))
    if text:
        ax.text((x1 + x2) / 2 + 0.08, (y1 + y2) / 2, text, fontsize=6.5, color=INK2,
                va="center")


def fig_architecture():
    fig, ax = plt.subplots(figsize=(7.2, 5.0))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 7)
    ax.axis("off")
    ax.grid(False)
    # Data plane
    ax.add_patch(plt.Rectangle((0.1, 0.1), 9.8, 1.9, fc="#f7f7f5", ec=GRID))
    ax.text(0.2, 1.85, "Data plane (Mininet hosts, TCLink bw/delay/loss)", fontsize=7,
            color=INK2)
    _box(ax, 0.3, 1.0, 1.9, 0.65, "Benign hosts: HTTP,\nping, iperf3 TCP+UDP",
         "#ffffff", GRID, 7)
    _box(ax, 0.3, 0.22, 1.9, 0.65, "Attackers: hping3\nSYN/UDP/ICMP + HTTP",
         "#fdeee7", "#eb6834", 7)
    _box(ax, 2.6, 0.35, 2.0, 1.1, "Open vSwitch\nOpenFlow 1.3\n(1 or 2 switches)")
    _box(ax, 5.1, 0.35, 2.2, 1.1, "Server 10.0.0.100\nHTTP + iperf3\n(protected IP)",
         "#ffffff", GRID)
    _arrow(ax, 2.2, 1.32, 2.6, 1.05)
    _arrow(ax, 2.2, 0.55, 2.6, 0.75)
    _arrow(ax, 4.6, 0.9, 5.1, 0.9)
    # Controller
    ax.add_patch(plt.Rectangle((0.1, 2.3), 9.8, 3.0, fc="#fbfbfa", ec=GRID))
    ax.text(0.2, 5.12, "Control plane: os-ken app (sdnddos/controller_app.py)",
            fontsize=7, color=INK2)
    _box(ax, 0.3, 3.95, 1.75, 0.85, "L3 learning switch\n(packet-in -> flows)")
    _box(ax, 2.3, 3.95, 1.75, 0.85, "Stats poll\nevery 2 s")
    _box(ax, 4.3, 3.95, 1.75, 0.85, "Flow delta tracker\n(+ FlowRemoved)")
    _box(ax, 6.3, 3.95, 1.6, 0.85, "Per-source\nfeatures (10)")
    _box(ax, 8.1, 3.95, 1.6, 0.85, "Detectors\n(all in shadow)")
    _box(ax, 8.1, 2.55, 1.6, 0.85, "Mitigation\npolicy", "#e9f6f0", "#1baf7a")
    _box(ax, 6.3, 2.55, 1.6, 0.85, "SHAP\nattribution", "#f0eefb", "#6250d6")
    _box(ax, 4.3, 2.55, 1.75, 0.85, "Drop rule /\nunblock flow-mod", "#e9f6f0",
         "#1baf7a")
    _box(ax, 0.3, 2.55, 2.4, 0.85, "CSV logs: features,\nall scores, events,\n"
         "timing, resources", "#ffffff", GRID, 7)
    for x1, x2 in [(2.05, 2.3), (4.05, 4.3), (6.05, 6.3), (7.9, 8.1)]:
        _arrow(ax, x1, 4.37, x2, 4.37)
    _arrow(ax, 8.9, 3.95, 8.9, 3.4, "active")
    _arrow(ax, 8.1, 2.97, 7.9, 2.97)
    _arrow(ax, 6.3, 2.97, 6.05, 2.97)
    ax.annotate("", xy=(3.4, 3.95), xytext=(3.4, 1.45), arrowprops=dict(
        arrowstyle="<|-|>", color=INK2, lw=1, shrinkA=2, shrinkB=2))
    ax.text(3.0, 2.1, "OpenFlow 1.3\npacket-in, stats", fontsize=6.5, color=INK2,
            ha="right")
    _arrow(ax, 4.6, 2.55, 4.3, 1.45, "flow-mod")
    # Offline
    ax.add_patch(plt.Rectangle((0.1, 5.55), 9.8, 1.35, fc="#f7f7f5", ec=GRID))
    ax.text(0.2, 6.72, "Offline (analysis/): reads the CSV logs of every run",
            fontsize=7, color=INK2)
    _box(ax, 0.3, 5.7, 2.1, 0.85, "Orchestrator\nground-truth attack log", "#ffffff",
         GRID)
    _box(ax, 2.7, 5.7, 2.1, 0.85, "Labelled dataset\n(split by run)", "#ffffff", GRID)
    _box(ax, 5.1, 5.7, 2.1, 0.85, "Training + model\nselection (GroupKFold)",
         "#ffffff", GRID)
    _box(ax, 7.5, 5.7, 2.2, 0.85, "CICDDoS2019 sample\n(FULL vs OF features)",
         "#ffffff", GRID)
    _arrow(ax, 2.4, 6.12, 2.7, 6.12)
    _arrow(ax, 4.8, 6.12, 5.1, 6.12)
    _arrow(ax, 7.5, 6.12, 7.2, 6.12)
    _arrow(ax, 6.15, 5.7, 8.6, 4.8, "model bundle")
    save(fig, "fig_architecture.png")


def fig_timeline():
    fig, ax = plt.subplots(figsize=(7.2, 1.5))
    ax.set_xlim(-2, 58)
    ax.set_ylim(0, 3)
    ax.axis("off")
    ax.grid(False)
    spans = [(0, 10, "warm-up", "#eef3fb"),
             (10, 40, "all attackers flood the server (start jitter < 1 s)", "#fdeee7"),
             (40, 55, "tail: unblock observed", "#eef3fb")]
    for a, b, t, c in spans:
        ax.add_patch(plt.Rectangle((a, 1.2), b - a, 0.9, fc=c, ec=GRID))
        ax.text((a + b) / 2, 1.65, t, ha="center", va="center", fontsize=7)
    for x in range(0, 56, 5):
        ax.plot([x, x], [1.1, 1.2], color=INK2, lw=0.8)
        ax.text(x, 0.8, f"{x}", ha="center", fontsize=6.5, color=INK2)
    ax.text(27.5, 0.3, "seconds since t0 (polling interval 2 s; benign HTTP/ping/iperf3 "
            "run throughout)", ha="center", fontsize=7, color=INK2)
    ax.text(0, 2.45, "Phases B/C run timeline", fontsize=7.5, color=INK)
    save(fig, "fig_timeline.png")


def main():
    for fn in [fig_architecture, fig_timeline, fig_detection_overall, fig_recall_by_rate, fig_threshold_sweep,
               lambda: fig_mitigation_core("tcp_ratio",
                                           "Benign TCP goodput / offered",
                                           "fig_mitigation_tcp.png", (0, 1.15)),
               lambda: fig_mitigation_core("rtt_p50_ms", "Ping RTT p50 (ms)",
                                           "fig_mitigation_rtt.png"),
               lambda: fig_mitigation_core("http_success_pct",
                                           "HTTP success (%)",
                                           "fig_mitigation_http.png", (0, 105)),
               lambda: fig_mitigation_ofat("tcp_ratio",
                                           "Benign TCP goodput / offered",
                                           "fig_ofat_tcp.png"),
               fig_timeseries, fig_latency, fig_shap, fig_cic, fig_overhead]:
        try:
            fn()
        except (FileNotFoundError, KeyError) as e:
            print("skipped figure:", e)


if __name__ == "__main__":
    main()
