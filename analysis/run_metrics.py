"""Per-run service-quality, mitigation and overhead metrics from a run directory.

Windows (all on the controller/orchestrator clock):
  baseline = [t0 + 3, attack start)   attack = [attack start, attack end]
Benign-only runs use the nominal attack window from the spec.
"""
import json
import os
import re

import numpy as np
import pandas as pd

PING_RE = re.compile(r"\[(\d+\.\d+)\].*icmp_seq=(\d+).*time=([\d.]+) ms")
PING_SENT_RE = re.compile(r"(\d+) packets transmitted")
PING_INTERVAL = 0.2
# A block up to two polls after an attacker stops still counts as a true block:
# packets queued at the bottleneck keep arriving for a moment after hping3 exits.
BLOCK_GRACE_S = 4.0


def _load_iperf(path):
    """iperf3 JSON, tolerating stderr lines written around it when the client is
    interrupted (e.g. 'iperf_json_finish: pthread_mutex_lock: Success')."""
    with open(path) as f:
        text = f.read()
    return json.JSONDecoder().raw_decode(text[text.index("{"):])[0]


def windows(m):
    t0 = m["t0"]
    if m.get("attacks"):
        ta = min(a["start"] for a in m["attacks"])
        tb = max(a["end"] for a in m["attacks"])
    else:
        ta, tb = t0 + m["warm_s"], t0 + m["warm_s"] + m["attack_s"]
    return (t0 + 3, ta), (ta, tb)


def _mean_in(times, values, w):
    sel = [(v) for t, v in zip(times, values) if w[0] <= t < w[1]]
    return float(np.mean(sel)) if sel else np.nan


def _iperf_tcp(path, t0, wb, wa):
    """Mean sender Mb/s per window; seconds after an early iperf exit count as 0."""
    try:
        d = _load_iperf(path)
    except (OSError, ValueError):
        return np.nan, np.nan
    mids = [t0 + (i["sum"]["start"] + i["sum"]["end"]) / 2 for i in d["intervals"]]
    mbps = [i["sum"]["bits_per_second"] / 1e6 for i in d["intervals"]]
    last = mids[-1] if mids else t0
    secs = np.arange(int(last - t0) + 1, int(wa[1] - t0) + 1) + t0 + 0.5
    mids += list(secs)
    mbps += [0.0] * len(secs)
    return _mean_in(mids, mbps, wb), _mean_in(mids, mbps, wa)


UDP_RE = re.compile(r"\]\s+([\d.]+)-([\d.]+)\s+sec.*?(\d+)/(\d+) \(")


def _iperf_udp_loss(path, t0, w):
    """Benign UDP loss % in window w, from the server's per-second text report
    (the iperf3 server was not run with --json, so the client embeds plain text)."""
    try:
        text = _load_iperf(path)["server_output_text"]
    except (OSError, ValueError, KeyError, TypeError):
        return np.nan
    lost = total = 0
    for line in text.splitlines():
        mm = UDP_RE.search(line)
        if not mm or "receiver" in line:
            continue
        a, b = float(mm[1]), float(mm[2])
        if b - a > 1.5:         # skip the whole-test summary line
            continue
        if w[0] <= t0 + (a + b) / 2 < w[1]:
            lost += int(mm[3])
            total += int(mm[4])
    return 100 * lost / total if total else np.nan


def _ping(path, w):
    """RTT p50/p95 and loss % of probes *sent* inside window w. Send times of lost
    probes are interpolated between received ones (ping's spacing drifts slightly
    from 0.2 s under load); the total sent comes from ping's own summary line."""
    sent, rtts, n_sent = {}, [], None
    with open(path) as f:
        for line in f:
            mm = PING_RE.search(line)
            if mm:
                t, seq, rtt = float(mm[1]), int(mm[2]), float(mm[3])
                sent[seq] = t - rtt / 1e3
                if w[0] <= sent[seq] < w[1]:
                    rtts.append(rtt)
            mm = PING_SENT_RE.search(line)
            if mm:
                n_sent = int(mm[1])
    if not sent:
        return np.nan, np.nan, 100.0
    seqs = np.array(sorted(sent))
    times = np.array([sent[q] for q in seqs])
    all_seqs = np.arange(1, (n_sent or seqs.max()) + 1)
    est = np.interp(all_seqs, seqs, times)
    est = np.where(all_seqs < seqs[0], times[0] - (seqs[0] - all_seqs) * PING_INTERVAL,
                   est)
    est = np.where(all_seqs > seqs[-1],
                   times[-1] + (all_seqs - seqs[-1]) * PING_INTERVAL, est)
    in_w = (est >= w[0]) & (est < w[1])
    expected = int(in_w.sum())
    received = int(np.isin(all_seqs[in_w], seqs).sum())
    loss = 100 * (1 - received / expected) if expected else np.nan
    if not rtts:
        return np.nan, np.nan, loss
    return float(np.median(rtts)), float(np.percentile(rtts, 95)), loss


def _http(run_dir, hosts, w):
    frames = []
    for h in hosts:
        p = os.path.join(run_dir, f"http_{h}.csv")
        if os.path.exists(p):
            frames.append(pd.read_csv(p))
    if not frames:
        return np.nan, np.nan
    df = pd.concat(frames)
    df = df[(df.t >= w[0]) & (df.t < w[1])]
    if df.empty:
        return np.nan, np.nan
    ok = df[df.ok == 1]
    return 100 * len(ok) / len(df), (float(ok.latency_s.median() * 1e3)
                                     if len(ok) else np.nan)


def _mitigation(run_dir, m, wa):
    """True/false blocks are judged against the manifest, not the address plan:
    a block is true only if its source was attacking at that moment (with
    BLOCK_GRACE_S after the attack end). Blocks of attackers' hosts while they were
    only browsing (e.g. every block in a benign-only run) are false blocks."""
    ev = pd.read_csv(os.path.join(run_dir, "events.csv"))
    win = {a["ip"]: (a["start"], a["end"]) for a in m.get("attacks", [])}
    blocks = ev[ev.event == "block"]

    def true_block(src, t):
        return src in win and win[src][0] <= t <= win[src][1] + BLOCK_GRACE_S

    ttm = []
    for ip, (start, _) in win.items():
        b = blocks[(blocks.src == ip) & (blocks.t >= start)]
        if len(b) and b.t.min() <= wa[1]:
            ttm.append(b.t.min() - start)
    n_false = sum(not true_block(s, t) for s, t in zip(blocks.src, blocks.t))
    # Seconds that sources which never attacked in this run spent blocked
    # (blocks still open at the end run to the end of the run).
    blocked_s = 0.0
    for src, g in ev[~ev.src.isin(list(win))].groupby("src"):
        t_block = None
        for _, r in g.sort_values("t").iterrows():
            if r.event == "block":
                t_block = r.t
            elif t_block is not None:
                blocked_s += r.t - t_block
                t_block = None
        if t_block is not None:
            blocked_s += m["t_end"] - t_block
    n_att = len(win)
    return {
        "attackers_blocked_frac": len(ttm) / n_att if n_att else np.nan,
        "ttm_s": float(np.mean(ttm)) if ttm else np.nan,
        "false_blocks": n_false,
        "benign_blocked_s": blocked_s,
        "unblocks": int((ev.event == "unblock").sum()),
    }


def run_metrics(run_dir):
    with open(os.path.join(run_dir, "manifest.json")) as f:
        m = json.load(f)
    if m.get("status") != "done":
        return None
    t0 = m["t0"]
    wb, wa = windows(m)
    tcp_b, tcp_a = _iperf_tcp(os.path.join(run_dir, "iperf_tcp_b2.json"), t0, wb, wa)
    rtt50, rtt95, ping_loss = _ping(os.path.join(run_dir, "ping_b1.log"), wa)
    benign_hosts = [f[5:-4] for f in os.listdir(run_dir)
                    if f.startswith("http_b") and f.endswith(".csv")]
    http_ok, http_ms = _http(run_dir, benign_hosts, wa)
    res = pd.read_csv(os.path.join(run_dir, "resources.csv"))
    res_a = res[(res.t >= wa[0]) & (res.t < wa[1])]
    tim = pd.read_csv(os.path.join(run_dir, "timing.csv"))
    att = m.get("attack") or {}
    out = {
        "run_id": m["run_id"], "condition": m["condition"], "rep": m["rep"],
        "mode": m["mode"], "seed": m["seed"], "attack_type": att.get("type", "none"),
        "attack_pps": att.get("pps", 0), "benign_load": m["benign_load"],
        "link_profile": m["link_profile"], "size": m["size"],
        "tcp_mbps_base": tcp_b, "tcp_mbps_attack": tcp_a,
        # Goodput during the attack relative to the probe's offered rate (0.4 x B).
        # Not relative to the pre-attack baseline: a false block during warm-up
        # would shrink that denominator and make a harmful defense look good.
        "tcp_ratio": tcp_a / (0.4 * m["link"]["bw"]),
        "tcp_base_ratio": tcp_b / (0.4 * m["link"]["bw"]),
        "udp_loss_pct": _iperf_udp_loss(os.path.join(run_dir, "iperf_udp_b3.json"),
                                        t0, wa),
        "rtt_p50_ms": rtt50, "rtt_p95_ms": rtt95, "ping_loss_pct": ping_loss,
        "http_success_pct": http_ok, "http_p50_ms": http_ms,
        "ctrl_cpu_pct": float(res_a.cpu_percent.mean()),
        "ctrl_rss_mb": float(res.rss_mb.max()),
    }
    # Timing over polls that actually had sources to score.
    tim = tim[tim.n_sources > 0]
    out["poll_ms_mean"] = float(tim.ms_total.mean())
    out["poll_ms_p95"] = float(tim.ms_total.quantile(0.95))
    active = f"ms_{m['mode']}"
    out["infer_ms_mean"] = float(tim[active].mean()) if active in tim else np.nan
    out.update(_mitigation(run_dir, m, wa))
    return out


if __name__ == "__main__":
    import sys
    print(json.dumps(run_metrics(sys.argv[1]), indent=2))
