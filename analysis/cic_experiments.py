"""Offline experiments on the CICDDoS2019 sample (experiment family E-CIC / E-XDOM).

    python analysis/cic_experiments.py cic|xdom  ->  results/tables/<part>_*.csv

E-CIC-1  feature sets: FULL (~80 CICFlowMeter features) vs OF (what an OpenFlow 1.3
         switch can report per unidirectional flow: duration, packets, bytes, protocol,
         plus rates derived from them).
E-CIC-2  splits: random stratified 70/30 within day 01-12 (common in the literature)
         vs train on day 01-12 / test on day 03-11 (no shared capture session).
E-XDOM   cross-domain with OF flow features: CIC -> Mininet flow records and
         Mininet -> CIC, to test whether either data source transfers to the other.
"""
import glob
import json
import os

import numpy as np
import pandas as pd
from sklearn.metrics import (balanced_accuracy_score, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

from analysis.build_dataset import role
from sdnddos.detectors import BUILDERS
from sdnddos.labels import attack_windows
from sdnddos.topo import ingress_switch

IDLE_TIMEOUT_S = 10      # forwarding-rule idle timeout (config.flow_idle_timeout)
OFPRR_IDLE_TIMEOUT = 0

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEED = 7
ID_COLS = ["Unnamed: 0", "Flow ID", "Source IP", "Source Port", "Destination IP",
           "Destination Port", "Timestamp", "SimillarHTTP", "Inbound", "Label",
           "day", "file"]
OF_COLS = ["duration_s", "pkts", "bytes", "pps", "bps", "avg_size",
           "is_tcp", "is_udp", "is_icmp"]
MODELS = ["dt", "lr", "rf", "xgb"]
PROTO = {"tcp": 6, "udp": 17, "icmp": 1, "syn": 6}


def of_features(duration_s, pkts, nbytes, proto):
    d = np.maximum(np.asarray(duration_s, float), 1e-3)
    pkts = np.asarray(pkts, float)
    nbytes = np.asarray(nbytes, float)
    proto = np.asarray(proto)
    return pd.DataFrame({
        "duration_s": d, "pkts": pkts, "bytes": nbytes, "pps": pkts / d,
        "bps": nbytes * 8 / d, "avg_size": nbytes / np.maximum(pkts, 1),
        "is_tcp": (proto == 6).astype(float), "is_udp": (proto == 17).astype(float),
        "is_icmp": (proto == 1).astype(float)})


def load_cic():
    df = pd.read_parquet(os.path.join(ROOT, "data", "cic", "cic_sample.parquet"))
    df["y"] = (df.Label.str.upper() != "BENIGN").astype(int)
    full_cols = [c for c in df.columns if c not in ID_COLS + ["y"]]
    full = df[full_cols].apply(pd.to_numeric, errors="coerce")
    full = full.replace([np.inf, -np.inf], np.nan).fillna(0).clip(-1e12, 1e12)
    # CIC "Total Length of Fwd Packets" counts payload bytes; OpenFlow counts frames.
    # Add per-packet Ethernet+IPv4+L4 headers (54 B TCP, 42 B UDP/ICMP) to
    # approximate frame bytes.
    proto = pd.to_numeric(df["Protocol"], errors="coerce").fillna(0)
    hdr = np.where(proto == 6, 54, 42)
    pkts = df["Total Fwd Packets"].astype(float)
    of = of_features(df["Flow Duration"].astype(float) / 1e6, pkts,
                     df["Total Length of Fwd Packets"].astype(float) + hdr * pkts,
                     proto)
    return df[["day", "file", "Label", "y"]], full, of


def evaluate(name, Xtr, ytr, Xte, yte):
    rows = []
    for m in MODELS + ["threshold"]:
        if m == "threshold":
            pps_i = list(Xtr.columns).index("pps") if "pps" in Xtr.columns else None
            if pps_i is None:
                continue
            s_tr, s_te = Xtr["pps"].to_numpy(), Xte["pps"].to_numpy()
            cands = np.unique(np.quantile(s_tr, np.linspace(0, 1, 201)))
            thr = cands[int(np.argmax([f1_score(ytr, s_tr >= c) for c in cands]))]
            score, pred = s_te, s_te >= thr
        else:
            d = BUILDERS[m](SEED)
            d.fit(Xtr.to_numpy(float), ytr)
            score = d.score(Xte.to_numpy(float))
            pred = score >= d.threshold
        neg = yte == 0
        rows.append({"experiment": name, "model": m, "n_train": len(ytr),
                     "n_test": len(yte), "test_benign": int(neg.sum()),
                     "f1": f1_score(yte, pred, zero_division=0),
                     "precision": precision_score(yte, pred, zero_division=0),
                     "recall": recall_score(yte, pred, zero_division=0),
                     "fpr": float(pred[neg].mean()) if neg.any() else np.nan,
                     "balanced_acc": balanced_accuracy_score(yte, pred),
                     "roc_auc": roc_auc_score(yte, score)
                     if 0 < yte.sum() < len(yte) else np.nan})
        print(rows[-1], flush=True)
    return rows


def mininet_flows(phase, only_none=True):
    """OpenFlow flow records (FlowRemoved) from a phase, labelled from manifests."""
    frames = []
    for run_dir in sorted(glob.glob(os.path.join(ROOT, "results", "runs", phase, "*"))):
        try:
            with open(os.path.join(run_dir, "manifest.json")) as f:
                m = json.load(f)
        except OSError:
            continue
        if m.get("status") != "done" or (only_none and m["mode"] != "none"):
            continue
        fr = pd.read_csv(os.path.join(run_dir, "flows_removed.csv"))
        fr = fr[(fr.priority == 10) & (fr.packets > 0)]
        fr = fr[[ingress_switch(m["size"], s) == d for s, d in zip(fr.src, fr.dpid)]]
        if fr.empty:
            continue
        # An idle-timeout removal reports a duration that includes the idle period
        # after the last packet; remove it to get the flow's active duration.
        idle = fr.reason == OFPRR_IDLE_TIMEOUT
        fr.loc[idle, "duration"] = (fr.loc[idle, "duration"] - IDLE_TIMEOUT_S).clip(
            lower=1e-3)
        w = attack_windows(m)
        att_proto = PROTO.get((m.get("attack") or {}).get("type"), -1)
        start = fr.t - fr.duration
        fr["y"] = [int(s in w and p == att_proto and a < w[s][1] and b > w[s][0])
                   for s, p, a, b in zip(fr.src, fr.proto, start, fr.t)]
        fr["role"] = fr.src.map(role)
        fr["run_id"] = m["run_id"]
        frames.append(fr)
    df = pd.concat(frames, ignore_index=True)
    return df, of_features(df.duration, df.packets, df.bytes, df.proto)


def run_cic():
    meta, full, of = load_cic()
    rows = []
    d1 = (meta.day == "01-12").to_numpy()
    d2 = (meta.day == "03-11").to_numpy()
    y = meta.y.to_numpy()
    for fs_name, X in [("FULL", full), ("OF", of)]:
        Xtr, Xte, ytr, yte = train_test_split(X[d1], y[d1], test_size=0.3,
                                              stratify=y[d1], random_state=SEED)
        rows += evaluate(f"{fs_name}/random-01-12", Xtr, ytr, Xte, yte)
        rows += evaluate(f"{fs_name}/day-01-12->03-11", X[d1], y[d1], X[d2], y[d2])
    counts = meta.groupby(["day", "Label"]).size().rename("rows").reset_index()
    return rows, counts


def run_xdom():
    meta, _, of = load_cic()
    y = meta.y.to_numpy()
    mA, XA = mininet_flows("A", only_none=False)
    mB, XB = mininet_flows("B")
    rows = evaluate("XDOM/CIC->Mininet-B", of, y, XB, mB.y.to_numpy())
    rows += evaluate("XDOM/Mininet-A->CIC", XA, mA.y.to_numpy(), of, y)
    rows += evaluate("XDOM/Mininet-A->Mininet-B", XA, mA.y.to_numpy(), XB,
                     mB.y.to_numpy())
    return rows


def main(part):
    out = os.path.join(ROOT, "results", "tables")
    os.makedirs(out, exist_ok=True)
    if part == "cic":
        rows, counts = run_cic()
        counts.to_csv(os.path.join(out, "cic_sample_counts.csv"), index=False)
    else:
        rows = run_xdom()
    pd.DataFrame(rows).to_csv(os.path.join(out, f"{part}_experiments.csv"),
                              index=False)
    print(f"wrote {part} tables")


if __name__ == "__main__":
    import sys
    main(sys.argv[1])
