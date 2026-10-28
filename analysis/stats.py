"""Small statistics helpers: t-based CIs, bootstrap CIs, paired tests."""
import numpy as np
from scipy import stats

BOOT = 10_000
SEED = 11


def mean_ci(x, level=0.95):
    """(mean, sd, lo, hi) with a Student-t interval; NaNs dropped."""
    x = np.asarray(x, float)
    x = x[~np.isnan(x)]
    n = len(x)
    if n == 0:
        return np.nan, np.nan, np.nan, np.nan
    m = x.mean()
    if n == 1:
        return m, np.nan, np.nan, np.nan
    sd = x.std(ddof=1)
    h = stats.t.ppf(0.5 + level / 2, n - 1) * sd / np.sqrt(n)
    return m, sd, m - h, m + h


def bootstrap_ci(x, stat=np.mean, level=0.95, seed=SEED):
    x = np.asarray(x, float)
    x = x[~np.isnan(x)]
    if len(x) == 0:
        return np.nan, np.nan
    rng = np.random.default_rng(seed)
    boots = stat(x[rng.integers(0, len(x), (BOOT, len(x)))], axis=1)
    a = (1 - level) / 2
    return float(np.quantile(boots, a)), float(np.quantile(boots, 1 - a))


def paired(a, b):
    """Compare paired samples a vs b: mean diff, bootstrap CI, Wilcoxon p, n."""
    a, b = np.asarray(a, float), np.asarray(b, float)
    ok = ~(np.isnan(a) | np.isnan(b))
    d = a[ok] - b[ok]
    if len(d) == 0:
        return {"n": 0, "mean_diff": np.nan, "ci_lo": np.nan, "ci_hi": np.nan,
                "wilcoxon_p": np.nan}
    lo, hi = bootstrap_ci(d)
    p = stats.wilcoxon(d).pvalue if np.any(d != 0) else 1.0
    return {"n": int(len(d)), "mean_diff": float(d.mean()), "ci_lo": lo,
            "ci_hi": hi, "wilcoxon_p": float(p)}
