"""Stream the CICDDoS2019 CSV zips into one stratified sample (no full extraction).

    python -I analysis/cic_prepare.py data/raw/cicddos2019 data/cic/cic_sample.parquet

Keeps every BENIGN row (benign is <1 % of the dataset) and a Bernoulli sample of
attack rows sized to roughly ATTACK_ROWS_PER_FILE per CSV. Seed fixed for
reproducibility; per-file input/kept counts are written next to the output.
"""
import json
import sys
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

SEED = 2019
ATTACK_ROWS_PER_FILE = 40_000
BYTES_PER_ROW = 470          # measured average CSV row size, used to size the sample
CHUNK = 250_000


def main(src_dir, out_path):
    rng = np.random.default_rng(SEED)
    parts, stats = [], []
    for zpath in sorted(Path(src_dir).glob("CSV-*.zip")):
        day = zpath.stem.replace("CSV-", "")
        with zipfile.ZipFile(zpath) as z:
            for info in sorted(z.infolist(), key=lambda i: i.filename):
                if not info.filename.endswith(".csv"):
                    continue
                p = min(1.0, ATTACK_ROWS_PER_FILE * BYTES_PER_ROW / info.file_size)
                n_in = n_benign = n_attack = 0
                with z.open(info) as fh:
                    for chunk in pd.read_csv(fh, chunksize=CHUNK, low_memory=False,
                                             encoding_errors="replace"):
                        chunk.columns = [c.strip() for c in chunk.columns]
                        n_in += len(chunk)
                        benign = chunk["Label"].astype(str).str.upper() == "BENIGN"
                        keep = benign | (rng.random(len(chunk)) < p)
                        kept = chunk[keep].copy()
                        n_benign += int(benign.sum())
                        n_attack += int((~benign[keep]).sum())
                        kept["day"] = day
                        kept["file"] = Path(info.filename).name
                        parts.append(kept)
                stats.append({"day": day, "file": info.filename, "rows_in": n_in,
                              "benign_kept": n_benign, "attack_kept": n_attack,
                              "attack_keep_prob": p})
                print(stats[-1], flush=True)
    df = pd.concat(parts, ignore_index=True)
    # Mixed-type identifier columns break parquet; keep them as strings.
    for c in df.columns:
        if df[c].dtype == object:
            df[c] = df[c].astype(str)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    with open(out.with_suffix(".stats.json"), "w") as f:
        json.dump({"seed": SEED, "files": stats, "rows_out": len(df)}, f, indent=2)
    print(f"wrote {len(df)} rows to {out}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
