"""Benign HTTP client run inside a Mininet host: Poisson requests, logged per request."""
import argparse
import csv
import random
import time
import urllib.request

from sdnddos.traffic import HTTP_FILES

WEIGHTS = [0.5, 0.3, 0.2]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", required=True)
    p.add_argument("--think", type=float, required=True)
    p.add_argument("--duration", type=float, required=True)
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args()

    rng = random.Random(a.seed)
    names = list(HTTP_FILES)
    end = time.time() + a.duration
    with open(a.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t", "file", "ok", "latency_s", "bytes"])
        while time.time() < end:
            time.sleep(rng.expovariate(1 / a.think))
            name = rng.choices(names, WEIGHTS)[0]
            t0 = time.time()
            ok, n = 0, 0
            try:
                with urllib.request.urlopen(f"http://{a.server}/{name}",
                                            timeout=5) as r:
                    n = len(r.read())
                    ok = int(n == HTTP_FILES[name])
            except OSError:
                pass
            w.writerow([f"{t0:.3f}", name, ok, f"{time.time() - t0:.4f}", n])
            f.flush()


if __name__ == "__main__":
    main()
