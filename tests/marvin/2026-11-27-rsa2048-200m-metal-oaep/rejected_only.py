"""Friedman test, pairwise sign tests and mean differences over a subset of classes, in chunks.
Reads CSV on stdin. Usage: rejected_only.py OUTDIR  (drops columns starting with valid_oaep)"""
import sys, json, itertools
import numpy as np, pandas as pd
from scipy import stats
out = sys.argv[1]
k = None; n = 0
for chunk in pd.read_csv(sys.stdin, chunksize=2_000_000, dtype=np.float64):
    cols = [c for c in chunk.columns if not c.startswith("valid_oaep")]
    a = chunk[cols].to_numpy()
    if k is None:
        k = len(cols); names = cols
        R = np.zeros(k); sq = 0.0; s = np.zeros(k); pairs = list(itertools.combinations(range(k), 2))
        gt = np.zeros(len(pairs), dtype=np.int64); lt = np.zeros(len(pairs), dtype=np.int64)
        d1 = np.zeros(len(pairs)); d2 = np.zeros(len(pairs))
        first = a[:1_000_000].copy()
    r = stats.rankdata(a, axis=1)
    R += r.sum(axis=0); sq += float((r * r).sum()); s += a.sum(axis=0); n += len(a)
    for i, (x, y) in enumerate(pairs):
        d = a[:, y] - a[:, x]
        gt[i] += int((d > 0).sum()); lt[i] += int((d < 0).sum()); d1[i] += d.sum(); d2[i] += float((d * d).sum())
    print(n, file=sys.stderr, flush=True)
ties = 12 * (n * k * (k + 1) * (2 * k + 1) / 6 - sq)          # sum over rows of sum(t^3 - t)
Q = (12 * (R ** 2).sum() / (n * k * (k + 1)) - 3 * n * (k + 1)) / (1 - ties / (n * k * (k * k - 1)))
p = stats.chi2.sf(Q, k - 1)
chk = stats.friedmanchisquare(*first.T)
res = {"rows": n, "classes": names, "friedman_chi2": Q, "friedman_p": p,
       "check_first_1M_scipy_p": chk.pvalue, "class_mean_ns": dict(zip(names, (s / n * 1e9).tolist())), "pairs": []}
for i, (x, y) in enumerate(pairs):
    m = d1[i] / n; sd = (d2[i] / n - m * m) ** 0.5; se = sd / n ** 0.5
    sp = stats.binomtest(int(gt[i]), int(gt[i] + lt[i]), 0.5).pvalue
    res["pairs"].append({"a": names[x], "b": names[y], "mean_diff_ns": m * 1e9, "ci95_ns": 1.96 * se * 1e9,
                         "sign_p": sp, "t_p": float(2 * stats.norm.sf(abs(m / se)))})
json.dump(res, open(out + "/rejected-only-local.json", "w"), indent=1)
sp = [q["sign_p"] for q in res["pairs"]]
print("rows", n, "classes", k, "Friedman p", p, "(scipy on first 1M:", chk.pvalue, ")")
print("sign tests: min p %.4g, pairs < 0.05: %d of %d" % (min(sp), sum(x < 0.05 for x in sp), len(sp)))
w = max(res["pairs"], key=lambda q: abs(q["mean_diff_ns"]))
print("largest mean difference: %s vs %s %.2f ns +-%.2f, sign p %.3g" % (w["a"], w["b"], w["mean_diff_ns"], w["ci95_ns"], w["sign_p"]))
