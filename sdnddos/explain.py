"""Per-decision feature attributions (SHAP for tree models).

Used by the controller to record *why* a source was blocked. Tree models use exact
TreeSHAP; logistic regression uses coefficient x standardised value (its exact SHAP
values under feature independence, up to a constant); the threshold rule reports its
margin. SVM and the autoencoder have no cheap exact method and return None.
"""
import numpy as np

from sdnddos.config import FEATURES

_explainers = {}


def _tree_explainer(det):
    if det.name not in _explainers:
        import shap
        _explainers[det.name] = shap.TreeExplainer(det.model)
    return _explainers[det.name]


def attributions(det, x):
    """Return [(feature, contribution)] sorted by |contribution|, or None."""
    x = np.asarray(x, dtype=float).reshape(1, -1)
    if det.kind == "threshold":
        i = FEATURES.index(det.feature)
        contrib = np.zeros(len(FEATURES))
        contrib[i] = x[0, i] - det.threshold
    elif det.name in ("dt", "rf", "xgb"):
        values = _tree_explainer(det).shap_values(x)
        values = np.asarray(values)
        # sklearn classifiers: (1, n_features, n_classes) or [class0, class1]
        if values.ndim == 3:
            contrib = values[0, :, 1] if values.shape[-1] == 2 else values[1][0]
        elif isinstance(values, list):
            contrib = np.asarray(values[1])[0]
        else:
            contrib = values[0]
    elif det.name == "lr":
        pipe = det.model
        z = pipe[:-1].transform(x)[0]
        contrib = pipe[-1].coef_[0] * z
    else:
        return None
    order = np.argsort(-np.abs(contrib))
    return [(FEATURES[i], float(contrib[i])) for i in order]
