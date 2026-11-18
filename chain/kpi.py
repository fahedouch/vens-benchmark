"""The per-release KPI measures defined so far, from the same records as the targets: the demo scan's runs in their
three contexts, a cell being one model in one context and arm. Vectors are compared within an arm only, the two arms
writing them in different representations. None of these measures validity: they measure stability, sensitivity
and conformance, not whether a score is right.

- Stability: each model's own MPD and run spreads (the floor, chain/demo.py), the agreement of each factor's level
  and of the whole vector over its run pairs, the share of CVEs whose severity is the same in every run at the cell's
  N, and for the after each question's answer agreement over the run pairs that asked it.
- Model sensitivity: per CVE, the gap between the two models' mean scores, averaged over the CVEs, and the CVEs whose
  two ranges over the runs do not overlap; against each model's own variation by Delta's gap test and band agreement
  (chain/demo.py). It measures agreement, neither independence nor correctness.
- Context sensitivity: the expected likelihood order, internal at most internal-api at most internet-facing, on each
  CVE's mean L over the runs; the mean gap in L between two contexts against the noise floor, the mean of the two
  contexts' own MPDs of L, unavailable unless both give one; and for the after, each question's answer agreement
  across two contexts against within one.
- Discrimination: the spread of scores across CVEs (W and H per run, chain/demo.py) and across contexts, the SD
  (n - 1) of the per-CVE mean scores pooled over the contexts.
- Failures, apart from cannot_tell: complete attempts without their full record, every one of them whether its
  replicate's run or not, the run summaries' defects, failed attempts by cause, and replicates left without a complete
  attempt; then cannot_tell, a designed answer, per question: its rate over the questions answered, its repeat-run
  agreement, and the share of CVEs a run left with one.
- Cost: calls per run and per CVE, the recovery calls per run, vens generate's wall time per run, and the estimated
  dollars per run and per CVE (chain/cost.py, an estimate); the measured spend is the usage exports' (chain/usage.py).
Conformance's checks with mechanically known expectations are vens's own Go tests, run on each commit, and the Java
check's targets; no record here measures them.
"""
import collections
import itertools
import statistics

from chain import attempt as attemptmod
from chain import cdx, demo, diagnostics, ledger, stats
from chain import cells as cellmod

CONTEXT_ORDER = ("internal", "internal-api", "internet-facing")
CANNOT_TELL = "cannot_tell"


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def _answers(rec):
    return {vid: e for vid, e in ((rec.get("answers") or {}).get("per_cve") or {}).items() if not e["unrated"]}


def _answer(entry, f):
    got = entry["factors"].get(f) or {}
    a = got.get("answer")
    return tuple(sorted(a)) if isinstance(a, list) else a


def _given(per, v, f):
    """The answers to question f on CVE v over the runs that gave one."""
    return [x for x in (_answer(a[v], f) for a in per if v in a) if x is not None]


def _reps(runs):
    return sorted(r["what"]["replicate"] for r in runs)


def _by_arm(cells):
    """{(model, arm): {context: runs}} of the demo scan."""
    out = collections.defaultdict(dict)
    for (campaign, model, ctx), arms in demo.by_model(cells).items():
        for arm, c in arms.items():
            out[(campaign, model, arm)][ctx] = demo.runs_of(c)
    return dict(out)


def stability(cells):
    """Per (model, context, arm): factor and vector agreement, the share of severities unchanged, and the after's
    answer agreement per question."""
    out = {}
    for (campaign, model, ctx), arms in sorted(demo.by_model(cells).items(), key=lambda kv: str(kv[0])):
        for arm, c in sorted(arms.items()):
            runs = demo.runs_of(c)
            ids = cellmod.common(runs)
            vecs, sevs = [cellmod.scores(r, "vector") for r in runs], [cellmod.scores(r, "severity") for r in runs]
            levels = [cellmod.scores(r, "levels") for r in runs]
            row = {"replicates": sorted(c["runs"]), "cves": len(ids),
                   "factor": {f: _mean([diagnostics.agreement([lv[v][f] for lv in levels]) for v in ids])
                              for f in cdx.FACTORS},
                   "vector": _mean([diagnostics.agreement([x[v] for x in vecs]) for v in ids]),
                   "severity_unchanged": (sum(1 for v in ids if len({s[v] for s in sevs}) == 1) / len(ids)
                                          if ids and len(runs) > 1 else None)}
            if arm == "after":
                per = [_answers(r) for r in runs]
                row["answers"] = {f: a for f in cdx.FACTORS if (a := _mean(
                    [diagnostics.agreement(_given(per, v, f)) for v in ids])) is not None}
            out[(campaign, model, ctx, arm)] = row
    return out


def model_sensitivity(cells):
    """Per (context, arm, model a, model b): the mean per-CVE gap of the two mean scores and the CVEs whose ranges
    over the runs do not overlap."""
    out = {}
    for (campaign, ctx, arm), cs in sorted(demo.model_pairs(cells).items(), key=lambda kv: str(kv[0])):
        models = {m: demo.runs_of(c) for m, c in cs.items()}
        for a, b in itertools.combinations(sorted(models), 2):
            ids = cellmod.common(models[a] + models[b])
            sa, sb = [cellmod.scores(r) for r in models[a]], [cellmod.scores(r) for r in models[b]]
            gaps, apart = [], 0
            for v in ids:
                xa, xb = [s[v] for s in sa], [s[v] for s in sb]
                gaps.append(abs(statistics.mean(xa) - statistics.mean(xb)))
                apart += max(xa) < min(xb) or max(xb) < min(xa)
            out[(campaign, ctx, arm, a, b)] = {"cves": len(ids), "gap": _mean(gaps), "apart": apart,
                                               "replicates": (_reps(models[a]), _reps(models[b]))}
    return out


def context_sensitivity(cells):
    """Per (model, arm) with the three contexts: the CVEs they all rate, the share of them in the expected
    likelihood order, and per context pair the mean gap in L against the noise floor, with the after's answer
    agreement across the pair against within it."""
    out = {}
    for (campaign, model, arm), ctxs in sorted(_by_arm(cells).items(), key=lambda kv: str(kv[0])):
        if not set(CONTEXT_ORDER) <= set(ctxs):
            continue
        ids = cellmod.common([r for c in CONTEXT_ORDER for r in ctxs[c]])
        means = {c: {v: statistics.mean(s[v] for s in (cellmod.scores(r, "L") for r in ctxs[c])) for v in ids}
                 for c in CONTEXT_ORDER}
        order = sum(1 for v in ids if means["internal"][v] <= means["internal-api"][v] <= means["internet-facing"][v])
        pairs = {}
        for x, y in itertools.combinations(CONTEXT_ORDER, 2):
            mpds = [stats.mpd(cellmod.matrix(ctxs[c], ids, "L")) for c in (x, y)]
            pairs[(x, y)] = {"gap": _mean([abs(means[y][v] - means[x][v]) for v in ids]),
                             "noise": None if None in mpds else sum(mpds) / 2}
            if arm == "after":
                pairs[(x, y)]["answers"] = answers_across(ctxs[x], ctxs[y], ids)
        out[(campaign, model, arm)] = {"cves": len(ids), "in_order": order / len(ids) if ids else None, "pairs": pairs,
                             "replicates": {c: _reps(ctxs[c]) for c in CONTEXT_ORDER}}
    return out


def answers_across(runs_x, runs_y, ids):
    """{question: (agreement across the two contexts, mean agreement within each)}, averaged over the CVEs."""
    ax, ay = [_answers(r) for r in runs_x], [_answers(r) for r in runs_y]
    out = {}
    for f in cdx.FACTORS:
        cross, within = [], []
        for v in ids:
            gx, gy = _given(ax, v, f), _given(ay, v, f)
            if gx and gy:
                cross.append(sum(p == q for p in gx for q in gy) / (len(gx) * len(gy)))
            within += [diagnostics.agreement(gx), diagnostics.agreement(gy)]
        if cross:
            out[f] = (_mean(cross), _mean(within))
    return out


def discrimination(cells):
    """Per (model, arm): the SD of each CVE's mean score pooled over the contexts, and what it read."""
    out = {}
    for (campaign, model, arm), ctxs in sorted(_by_arm(cells).items(), key=lambda kv: str(kv[0])):
        pooled = []
        for ctx, runs in sorted(ctxs.items()):
            ss = [cellmod.scores(r) for r in runs]
            pooled += [statistics.mean(s[v] for s in ss) for v in cellmod.common(runs)]
        out[(campaign, model, arm)] = {"contexts": sorted(ctxs), "values": len(pooled),
                             "replicates": {c: _reps(runs) for c, runs in ctxs.items()},
                             "sd": statistics.stdev(pooled) if len(pooled) > 1 else None}
    return out


def failures(cells):
    """Per cell: complete attempts without their full record, the replicate's run or another, the defects, failed
    attempts by cause, replicates left without a complete attempt, and cannot_tell per question."""
    out = {}
    for k, c in sorted(cells.items(), key=lambda kv: str(kv[0])):
        defects = collections.Counter()
        for rec in c["attempts"]:
            defects.update((rec.get("summary") or {}).get("defects") or {})
        attempted = {r["what"]["replicate"] for r in c["attempts"] if isinstance(r["what"].get("replicate"), int)}
        out[k] = {"incomplete": sum(1 for rec in c["attempts"]
                                    if rec["outcome"] == attemptmod.COMPLETE and rec["incomplete"]),
                  "defects": dict(defects), "failed": dict(ledger.tally(c)["failed"]),
                  "without_complete": sorted(attempted - set(c["runs"]) - set(c["unusable"])),
                  "cannot_tell": cannot_tell(demo.runs_of(c))}
    return out


def cannot_tell(runs):
    """{"questions": {question: {rate, asked, agreement}}, "cves_affected": mean share over the runs}."""
    per = [_answers(r) for r in runs]
    affected = [sum(1 for e in a.values() if any(f.get("answer") == CANNOT_TELL for f in e["factors"].values()))
                / len(a) for a in per if a]
    ids = sorted(set().union(*[set(a) for a in per])) if per else []
    out = {}
    for f in cdx.FACTORS:
        flags = [[x == CANNOT_TELL for x in _given(per, v, f)] for v in ids]
        asked = sum(len(x) for x in flags)
        if asked:
            out[f] = {"rate": sum(sum(x) for x in flags) / asked, "asked": asked,
                      "agreement": _mean([diagnostics.agreement(x) for x in flags])}
    return {"questions": out, "cves_affected": _mean(affected)}


def _ratio(xs, ns):
    pairs = [(x, n) for x, n in zip(xs, ns) if x is not None and n]
    return sum(x for x, _ in pairs) / sum(n for _, n in pairs) if pairs else None


def cost(cells):
    """Per cell with runs: calls, recovery calls and wall time per run, calls per CVE, and the estimated dollars per
    run and per CVE."""
    out = {}
    for k, c in sorted(cells.items(), key=lambda kv: str(kv[0])):
        runs = demo.runs_of(c)
        if not runs:
            continue
        n_cves = [len(r["ratings"] or {}) for r in runs]
        calls = [(r.get("recovery") or {}).get("llm_calls") for r in runs]
        usd = [(r.get("cost_estimate") or {}).get("total") for r in runs]
        out[k] = {"runs": len(runs), "replicates": _reps(runs), "calls_per_run": _mean(calls),
                  "calls_per_cve": _ratio(calls, n_cves),
                  "recovery_per_run": _mean([(r.get("recovery") or {}).get("recovery_calls") for r in runs]),
                  "wall_seconds": _mean([ledger.wall_seconds(r) for r in runs]),
                  "usd_per_run": _mean(usd), "usd_per_cve": _ratio(usd, n_cves)}
    return out
