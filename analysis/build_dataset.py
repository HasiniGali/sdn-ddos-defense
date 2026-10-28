"""Join controller feature logs with ground truth for one phase.

    python analysis/build_dataset.py <phase>   ->  results/datasets/<phase>.parquet
"""
import glob
import json
import os
import sys

import pandas as pd

from sdnddos.labels import attack_windows, label_interval
from sdnddos.topo import SERVER_IP, ingress_switch

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "results")


def role(ip):
    if ip == SERVER_IP:
        return "server"
    return "attacker" if int(ip.rsplit(".", 1)[1]) > 200 else "benign"


def load_run(run_dir):
    try:
        with open(os.path.join(run_dir, "manifest.json")) as f:
            m = json.load(f)
    except FileNotFoundError:   # run not executed (yet)
        return None
    if m.get("status") != "done":
        return None
    df = pd.read_csv(os.path.join(run_dir, "features.csv"))
    # Runs before the transit-switch FlowRemoved fix (CHANGELOG) logged spurious rows
    # on non-ingress switches in the two-switch topology; keep ingress rows only.
    df = df[[ingress_switch(m["size"], s) == d for s, d in zip(df.src, df.dpid)]]
    if df.empty:
        return None
    w = attack_windows(m)
    df["label"] = [label_interval(s, t, dt, w)
                   for s, t, dt in zip(df.src, df.t, df.dt)]
    df["role"] = df.src.map(role)
    df["t_rel"] = df.t - m["t0"]
    att = m.get("attack") or {}
    df = df.assign(run_id=m["run_id"], condition=m["condition"], rep=m["rep"],
                   mode=m["mode"], attack_type=att.get("type", "none"),
                   attack_pps=att.get("pps", 0), benign_load=m["benign_load"],
                   link_profile=m["link_profile"], size=m["size"], seed=m["seed"])
    return df


def build(phase):
    runs = sorted(glob.glob(os.path.join(ROOT, "runs", phase, "*")))
    frames = [f for f in map(load_run, runs) if f is not None]
    df = pd.concat(frames, ignore_index=True)
    out = os.path.join(ROOT, "datasets", f"{phase}.parquet")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    df.to_parquet(out, index=False)
    print(f"{phase}: {len(frames)}/{len(runs)} runs, {len(df)} rows, "
          f"{int(df.label.sum())} attack rows -> {out}")
    return df


if __name__ == "__main__":
    build(sys.argv[1])
