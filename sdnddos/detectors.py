"""Detector registry shared by training (analysis/train.py) and the controller.

Every detector maps a feature matrix (columns = config.FEATURES) to a score and
flags rows whose score >= threshold. Adding a detector means adding a builder to
BUILDERS; nothing else changes.
"""
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPRegressor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

from sdnddos.config import FEATURES


class Detector:
    """kind: 'threshold' (score = one raw feature), 'proba' (P(attack)),
    'anomaly' (autoencoder reconstruction error, trained on benign rows only)."""

    def __init__(self, name, kind, model=None, threshold=0.5, feature=None):
        self.name = name
        self.kind = kind
        self.model = model
        self.threshold = threshold
        self.feature = feature
        self.meta = {}

    def fit(self, X, y):
        if self.kind == "proba":
            self.model.fit(X, y)
        elif self.kind == "anomaly":
            Xb = X[y == 0]
            self.model.fit(Xb, self.model[:-1].fit_transform(Xb))
        return self

    def score(self, X):
        X = np.asarray(X, dtype=float)
        if self.kind == "threshold":
            return X[:, FEATURES.index(self.feature)]
        if self.kind == "proba":
            return self.model.predict_proba(X)[:, 1]
        target = self.model[:-1].transform(X)
        return ((self.model.predict(X) - target) ** 2).mean(axis=1)

    def predict(self, X):
        return self.score(X) >= self.threshold


def signed_log1p(X):
    # Heavy-tailed rates need a log; CICFlowMeter also emits negatives (e.g. -1).
    return np.sign(X) * np.log1p(np.abs(X))


def _log_scaled(est):
    return make_pipeline(FunctionTransformer(signed_log1p), StandardScaler(), est)


def build_threshold(seed):
    return Detector("threshold", "threshold", feature="pps", threshold=np.inf)


def build_dt(seed):
    return Detector("dt", "proba", DecisionTreeClassifier(
        max_depth=6, class_weight="balanced", random_state=seed))


def build_lr(seed):
    return Detector("lr", "proba", _log_scaled(LogisticRegression(
        class_weight="balanced", max_iter=2000, random_state=seed)))


def build_svm(seed):
    # Platt-calibrated RBF SVM (SVC(probability=True) is deprecated in sklearn 1.9).
    return Detector("svm", "proba", _log_scaled(CalibratedClassifierCV(
        SVC(kernel="rbf", C=1.0, class_weight="balanced", random_state=seed),
        ensemble=False)))


def build_rf(seed):
    return Detector("rf", "proba", RandomForestClassifier(
        n_estimators=200, min_samples_leaf=2, class_weight="balanced",
        n_jobs=1, random_state=seed))


def build_xgb(seed):
    return Detector("xgb", "proba", XGBClassifier(
        n_estimators=300, max_depth=4, learning_rate=0.1, subsample=0.9,
        colsample_bytree=0.9, eval_metric="logloss", n_jobs=1,
        random_state=seed))


def build_ae(seed):
    # Bottleneck autoencoder; the last pipeline step reconstructs the scaled input.
    return Detector("ae", "anomaly", _log_scaled(MLPRegressor(
        hidden_layer_sizes=(8, 3, 8), max_iter=500, random_state=seed)))


BUILDERS = {
    "threshold": build_threshold,
    "dt": build_dt,
    "lr": build_lr,
    "svm": build_svm,
    "rf": build_rf,
    "xgb": build_xgb,
    "ae": build_ae,
}
