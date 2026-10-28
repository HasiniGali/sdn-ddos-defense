"""Train every detector on phase-A runs and pick the proposed model.

    python analysis/train.py [out_dir]  ->  <out_dir or models>/detectors.joblib,
                                            train_report.json

Model selection uses 5-fold GroupKFold over *runs* (rows of one run never span
train and validation). The selection rule was fixed before looking at results:
proposed = the tree ensemble (rf or xgb) with the higher out-of-fold F1.
The static-threshold baseline gets the pps cut-off that maximises F1 on the
training data, which makes it a strong (tuned) baseline rather than a straw man.
"""
import hashlib
import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.model_selection import GroupKFold

from sdnddos.config import FEATURES
from sdnddos.detectors import BUILDERS

SEED = 7
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AE_QUANTILE = 0.99


def tune_threshold(scores, y):
    """Cut-off on a raw score maximising F1 (candidates: observed attack scores)."""
    cands = np.unique(np.quantile(scores[y == 1], np.linspace(0, 1, 201)))
    f1s = [f1_score(y, scores >= c) for c in cands]
    return float(cands[int(np.argmax(f1s))])


def fit_detector(name, X, y):
    d = BUILDERS[name](SEED)
    d.fit(X, y)
    if name == "threshold":
        d.threshold = tune_threshold(d.score(X), y)
    elif name == "ae":
        d.threshold = float(np.quantile(d.score(X[y == 0]), AE_QUANTILE))
    return d


def main(out_dir):
    df = pd.read_parquet(os.path.join(ROOT, "results", "datasets", "A.parquet"))
    X, y, groups = df[FEATURES].to_numpy(float), df.label.to_numpy(), df.run_id
    report = {"seed": SEED, "rows": len(df), "attack_rows": int(y.sum()),
              "runs": int(groups.nunique()),
              "data_sha256": hashlib.sha256(
                  pd.util.hash_pandas_object(df[FEATURES + ["label"]]).values
              ).hexdigest(), "cv": {}}
    for name in BUILDERS:
        oof_score, oof_pred = np.zeros(len(y)), np.zeros(len(y), bool)
        for tr, va in GroupKFold(5).split(X, y, groups):
            d = fit_detector(name, X[tr], y[tr])
            oof_score[va] = d.score(X[va])
            oof_pred[va] = d.predict(X[va])
        report["cv"][name] = {"f1": f1_score(y, oof_pred),
                              "roc_auc": roc_auc_score(y, oof_score)}
        print(name, report["cv"][name], flush=True)

    bundle = {name: fit_detector(name, X, y) for name in BUILDERS}
    proposed = max(["rf", "xgb"], key=lambda n: report["cv"][n]["f1"])
    report["proposed"] = proposed
    report["thresholds"] = {n: float(d.threshold) for n, d in bundle.items()}
    os.makedirs(out_dir, exist_ok=True)
    joblib.dump(bundle, os.path.join(out_dir, "detectors.joblib"))
    with open(os.path.join(out_dir, "train_report.json"), "w") as f:
        json.dump(report, f, indent=2)
    print("proposed:", proposed)


if __name__ == "__main__":
    import sys
    # Default: the deployed bundle. Never overwrite it after evaluation runs exist;
    # pass another directory for sensitivity re-training.
    main(os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
         else os.path.join(ROOT, "models"))
