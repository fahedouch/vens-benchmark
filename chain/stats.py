"""The statistics of the demo scan's targets, as 0B's preregistered inference defines them (venslabs/vens#310).

A cell is an array of shape (runs, CVEs): the scores of one model's runs in one context and arm, over the CVEs every
compared cell holds. Whole runs are the exchangeable units. Every random draw comes from SeedSequence([310,
crc32(key)]), so that a test's figures are the same on each reading.

- W, a run's within-project spread: the SD (n - 1) of its scores over its CVEs.
- H, a run's ranking entropy: the Shannon entropy in bits of its scores rounded to two decimals, equal rounded scores
  counting as one value (0 when all tie, log2 of the CVE count when all differ).
- The non-inferiority bound of mean(arm) / mean(control): its one-sided 95% lower bound on the log scale, by the
  two-sample delete-one jackknife; a control mean of 0 passes (spread cannot fall below 0), an arm mean of 0 against a
  positive control fails, and so does a leave-one-out mean of 0. 0B passed it at 0.90; the gate is set before a run.
- MPD, a model's within-model mean pairwise difference: the mean over its run pairs of the mean |difference| over
  the CVEs; the cross-model one over the run pairs that take one run from each model.
- Delta: the cross-model MPD less the mean of the two within-model ones, half the energy distance between the two
  models' runs as a U-statistic, 0 when they are identically distributed.
- The gap test: whole runs permuted between the two models, 10,000 permutations; p is the share of permuted Delta at
  or above the observed, the observed counted. When the relabellings are no more than that, all are enumerated.
- The floor: a model's MPD, its 3-run spread (the mean over the CVEs of max - min over three runs) averaged over every
  triple of its runs, with the smallest and the largest, and its N-run spread over all its runs.
- Agreement: the mean over run pairs of the share of CVEs whose two labels (severities, answers) are equal.
A matrix without a column, no CVE every compared run rates, gives none of these: each is None, never a NaN that a
comparison would read as a figure.
"""
import itertools
import math
import zlib

import numpy as np

SEED = 310
N_PERM = 10_000
Z = 1.6448536269514722  # one-sided 95% normal quantile
MARGIN = 0.90  # 0B's non-inferiority margin, printed beside the bound


def rng_for(key):
    """A generator fixed by the test's key, e.g. 'gap|after|internal|a|b'."""
    return np.random.default_rng(np.random.SeedSequence([SEED, zlib.crc32(key.encode())]))


def cell(rows):
    return np.asarray(rows, dtype=float)


def pair_matrix(runs):
    """D[i, j] = mean over CVEs of |run i - run j|."""
    runs = cell(runs)
    return np.abs(runs[:, None, :] - runs[None, :, :]).mean(axis=2)


def _no_cve(m):
    return m.ndim != 2 or m.shape[1] == 0


def mpd(runs):
    """The within-cell mean pairwise difference; None below two runs or without a CVE."""
    runs = cell(runs)
    if len(runs) < 2 or _no_cve(runs):
        return None
    return float(pair_matrix(runs)[np.triu_indices(len(runs), 1)].mean())


def cross_mpd(runs_a, runs_b):
    a, b = cell(runs_a), cell(runs_b)
    if not len(a) or not len(b) or _no_cve(a) or _no_cve(b):
        return None
    return float(np.abs(a[:, None, :] - b[None, :, :]).mean())


def _delta_labels(D, labels):
    a = labels.astype(float)
    b = 1.0 - a
    na, nb = a.sum(axis=1), b.sum(axis=1)
    cross = np.einsum("pi,ij,pj->p", a, D, b) / (na * nb)
    wa = np.einsum("pi,ij,pj->p", a, D, a) / (na * (na - 1))
    wb = np.einsum("pi,ij,pj->p", b, D, b) / (nb * (nb - 1))
    return cross - (wa + wb) / 2


def delta(runs_a, runs_b):
    """Delta; None unless each model has two runs, and without a CVE."""
    a, b = cell(runs_a), cell(runs_b)
    if len(a) < 2 or len(b) < 2 or _no_cve(a) or _no_cve(b):
        return None
    D = pair_matrix(np.vstack([a, b]))
    return float(_delta_labels(D, np.r_[np.ones(len(a)), np.zeros(len(b))][None, :])[0])


def _relabellings(n, k):
    first = list(itertools.combinations(range(n), k))
    return np.array([list(c) + [i for i in range(n) if i not in c] for c in first])


def drawn(n_a, n_b, n_perm=N_PERM):
    """Whether the gap test draws its permutations, its p then the key's: two runs a side at least, and more
    relabellings than n_perm, all enumerated otherwise."""
    return n_a >= 2 and n_b >= 2 and math.comb(n_a + n_b, n_a) > n_perm


def gap_test(runs_a, runs_b, rng, n_perm=N_PERM):
    """(Delta, p); (None, None) unless each model has two runs, and without a CVE."""
    a, b = cell(runs_a), cell(runs_b)
    if len(a) < 2 or len(b) < 2 or _no_cve(a) or _no_cve(b):
        return None, None
    D = pair_matrix(np.vstack([a, b]))
    na, n = len(a), len(a) + len(b)
    obs = float(_delta_labels(D, np.r_[np.ones(na), np.zeros(n - na)][None, :])[0])
    if not drawn(na, n - na, n_perm):
        order = _relabellings(n, na)
        lab = np.zeros((len(order), n))
        np.put_along_axis(lab, order[:, :na], 1.0, axis=1)
        return obs, float((_delta_labels(D, lab) >= obs - 1e-12).mean())
    lab = np.zeros((n_perm, n))
    idx = np.argsort(rng.random((n_perm, n)), axis=1)[:, :na]
    np.put_along_axis(lab, idx, 1.0, axis=1)
    perm = _delta_labels(D, lab)
    return obs, (1 + int((perm >= obs - 1e-12).sum())) / (1 + n_perm)


def run_spread(runs):
    """W per run; a run of one CVE has none (nan)."""
    runs = cell(runs)
    if runs.ndim != 2 or runs.shape[1] < 2:
        return np.full(len(runs), np.nan)
    return runs.std(axis=1, ddof=1)


def run_entropy(runs):
    """H per run, its scores rounded to two decimals, equal rounded scores one value; a run without a CVE has none
    (nan)."""
    out = []
    for row in np.round(cell(runs), 2):
        if not len(row):
            out.append(float("nan"))
            continue
        _, counts = np.unique(row, return_counts=True)
        p = counts / counts.sum()
        out.append(float(-(p * np.log2(p)).sum()) + 0.0)
    return np.asarray(out)


def entropy(values):
    """H of one run's scores, as run_entropy."""
    return float(run_entropy([values])[0]) if len(values) else float("nan")


def jackknife_se(theta, cells):
    var = 0.0
    for c, one in enumerate(cells):
        n = len(one)
        loo = []
        for i in range(n):
            reduced = list(cells)
            reduced[c] = np.delete(one, i, axis=0)
            loo.append(theta(reduced))
        loo = np.asarray(loo)
        var += (n - 1) / n * ((loo - loo.mean()) ** 2).sum()
    return float(np.sqrt(var))


def noninferiority(per_run_arm, per_run_ctrl, margin=MARGIN, z=Z):
    """(ratio, lower bound, 'pass' | 'fail' at margin) of mean(arm) / mean(control); (ratio, None, None) when a cell
    has fewer than two runs, the jackknife needing one left out; (None, None, None) when a run has no figure (nan: W
    below two CVEs, H without one)."""
    x, y = np.asarray(per_run_arm, float), np.asarray(per_run_ctrl, float)
    if not len(x) or not len(y) or np.isnan(x).any() or np.isnan(y).any():
        return None, None, None
    if y.mean() == 0:
        return None, None, "pass"
    if x.mean() == 0:
        return 0.0, 0.0, "fail"
    ratio = float(x.mean() / y.mean())
    if len(x) < 2 or len(y) < 2:
        return ratio, None, None
    for one in (x, y):
        if any(np.delete(one, i).mean() == 0 for i in range(len(one))):
            return ratio, 0.0, "fail"
    se = jackknife_se(lambda c: np.log(c[0].mean()) - np.log(c[1].mean()), [x, y])
    bound = float(np.exp(np.log(ratio) - z * se))
    return ratio, bound, "pass" if bound >= margin else "fail"


def floor(runs):
    """{mpd, tri_mean, tri_min, tri_max, spread, runs, cves}; the triples' figures None below three runs, the MPD
    and the N-run spread None below two, all of them None without a CVE."""
    m = cell(runs)
    if _no_cve(m):
        return {"mpd": None, "tri_mean": None, "tri_min": None, "tri_max": None, "spread": None, "runs": len(m),
                "cves": 0}
    tri = [float((m[list(t)].max(0) - m[list(t)].min(0)).mean()) for t in itertools.combinations(range(len(m)), 3)]
    return {"mpd": mpd(m), "tri_mean": float(np.mean(tri)) if tri else None, "tri_min": min(tri, default=None),
            "tri_max": max(tri, default=None),
            "spread": float((m.max(0) - m.min(0)).mean()) if len(m) > 1 else None, "runs": len(m),
            "cves": m.shape[1]}


def _share_equal(x, y):
    return sum(1 for p, q in zip(x, y) if p == q) / len(x)


def agreement(labels_a, labels_b):
    """The mean over cross run pairs of the share of CVEs with equal labels; None without a pair."""
    pairs = [(x, y) for x in labels_a for y in labels_b]
    return sum(_share_equal(x, y) for x, y in pairs) / len(pairs) if pairs and len(pairs[0][0]) else None


def within_agreement(labels):
    """The same over a cell's own run pairs; None below two runs."""
    pairs = list(itertools.combinations(labels, 2))
    return sum(_share_equal(x, y) for x, y in pairs) / len(pairs) if pairs and len(pairs[0][0]) else None
