"""Generate run specs for every experiment phase.

    python experiments/plan.py <phase> [--proposed xgb]

Writes results/runs/<phase>/<run_id>/spec.json for each run. Seeds depend on the
condition and repetition, never on the defense mode, so runs of different modes with
the same (condition, rep) see identical benign/attack randomness and can be compared
pairwise.
"""
import argparse
import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sdnddos.traffic import RATES  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "results", "runs")
TYPES = ["syn", "udp", "icmp"]
LINKS = {
    "default": {"bw": 10, "delay_ms": 2, "loss": 0.0},
    "bw50": {"bw": 50, "delay_ms": 2, "loss": 0.0},
    "wan": {"bw": 10, "delay_ms": 20, "loss": 1.0},
}
REPS = 5
TIMING = {"warm_s": 10, "attack_s": 30, "tail_s": 15}


def spec(run_id, seed, attack, load="medium", link="default", size="small",
         mode="none", shadow=True, condition=None, rep=0, timing=TIMING):
    return {"run_id": run_id, "seed": seed, "condition": condition, "rep": rep,
            "mode": mode, "attack": attack, "benign_load": load, "link_profile": link,
            "link": LINKS[link], "size": size, **timing,
            "controller": {"active_detector": mode, "shadow": shadow}}


def phase_train():
    """Diverse monitor-only runs for training: continuous attack rates."""
    rng = random.Random(1000)
    out = []
    for i in range(60):
        pps = round(math.exp(rng.uniform(math.log(30), math.log(8000))))
        out.append(spec(f"A{i:03d}", 1000 + i,
                        {"type": rng.choice(TYPES), "pps": pps},
                        load=rng.choice(["low", "medium", "high"]),
                        link=rng.choice(list(LINKS)),
                        size=rng.choices(["small", "large"], [3, 1])[0],
                        shadow=False, condition="train", timing={
                            "warm_s": 10, "attack_s": 30, "tail_s": 10}))
    for i in range(12):
        out.append(spec(f"A{60 + i:03d}", 1060 + i, None,
                        load=rng.choice(["low", "medium", "high"]),
                        link=rng.choice(list(LINKS)),
                        size=rng.choices(["small", "large"], [3, 1])[0],
                        shadow=False, condition="train-benign", timing={
                            "warm_s": 10, "attack_s": 30, "tail_s": 10}))
    return out


def _grid(prefix, seed_base, conditions, modes):
    out = []
    for c, (cond, kw) in enumerate(conditions):
        for rep in range(REPS):
            seed = seed_base + 10 * c + rep
            for mode in modes:
                out.append(spec(f"{prefix}-{cond}-r{rep}-{mode}", seed, mode=mode,
                                condition=cond, rep=rep, **kw))
    return out


def phase_core(proposed):
    conds = [(f"{t}-{lvl}", {"attack": {"type": t, "pps": RATES[lvl]}})
             for t in TYPES for lvl in RATES]
    return _grid("B", 5000, conds, ["none", "threshold", "dt", proposed])


def phase_ofat(proposed):
    conds = []
    for t in TYPES:
        att = {"type": t, "pps": RATES["medium"]}
        conds += [(f"{t}-loadhigh", {"attack": att, "load": "high"}),
                  (f"{t}-bw50", {"attack": att, "link": "bw50"}),
                  (f"{t}-wan", {"attack": att, "link": "wan"}),
                  (f"{t}-large", {"attack": att, "size": "large"})]
    conds.append(("flashcrowd", {"attack": None, "load": "high"}))
    return _grid("C", 7000, conds, ["none", "threshold", proposed])


def phase_overhead(proposed):
    conds = [("udp-medium", {"attack": {"type": "udp", "pps": RATES["medium"]}})]
    out = []
    for c, (cond, kw) in enumerate(conds):
        for rep in range(REPS):
            for mode in ["none", "threshold", "dt", "lr", "rf", "xgb", "svm", "ae"]:
                out.append(spec(f"O-{cond}-r{rep}-{mode}", 9000 + rep, mode=mode,
                                shadow=False, condition=cond, rep=rep, **kw))
    return out


PHASES = {"A": lambda p: phase_train(), "B": phase_core, "C": phase_ofat,
          "O": phase_overhead}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=PHASES)
    ap.add_argument("--proposed", default="xgb")
    a = ap.parse_args()
    specs = PHASES[a.phase](a.proposed)
    for s in specs:
        d = os.path.join(ROOT, a.phase, s["run_id"])
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "spec.json"), "w") as f:
            json.dump(s, f, indent=2)
    print(f"phase {a.phase}: {len(specs)} runs")


if __name__ == "__main__":
    main()
