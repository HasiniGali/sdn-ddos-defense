"""Run every pending spec of a phase, in a seeded random order (inside the container).

    python experiments/run_phase.py <phase> [--worker i --workers n]

Runs whose manifest says "done" are skipped, so an interrupted phase resumes.
A failed run is retried twice before it is left as failed.
"""
import argparse
import glob
import json
import os
import random
import subprocess
import sys
import time

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "results", "runs")


def done(run_dir):
    try:
        with open(os.path.join(run_dir, "manifest.json")) as f:
            return json.load(f).get("status") == "done"
    except (OSError, ValueError):
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("phase")
    ap.add_argument("--worker", type=int, default=0)
    ap.add_argument("--workers", type=int, default=1)
    a = ap.parse_args()
    specs = sorted(glob.glob(os.path.join(ROOT, a.phase, "*", "spec.json")))
    random.Random(42).shuffle(specs)
    specs = specs[a.worker::a.workers]
    pending = [s for s in specs if not done(os.path.dirname(s))]
    print(f"{len(pending)}/{len(specs)} runs pending", flush=True)
    for i, s in enumerate(pending, 1):
        for attempt in range(3):
            t = time.time()
            rc = subprocess.call([sys.executable, "-m", "sdnddos.orchestrator", s])
            ok = rc == 0 and done(os.path.dirname(s))
            print(f"[{i}/{len(pending)}] {os.path.basename(os.path.dirname(s))} "
                  f"attempt={attempt + 1} ok={ok} {time.time() - t:.0f}s", flush=True)
            if ok:
                break


if __name__ == "__main__":
    main()
