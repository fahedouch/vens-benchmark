"""Step 5's statistics, per run and per cell, on the runs chain/cells.py selects: the targets on both corpora, the
spreads, the cross-model figures, the floor and #340's report on the demo scan.

- Legal-vector share, target (i): per run, the CVEs of the scanner's report whose rating the Java check accepts
  (chain/legal.py), over those CVEs, a CVE without a rating counting as not legal.
- Recomputable-score share, target (ii): per run, the report's CVEs whose published score equals exactly the score
  the arm's own formula gives from the vector, over those CVEs; beside it, the severity's agreement with the arm's
  own rule. The after: L x max(T, B), and OWASP's matrix on the likelihood band and the band of max(T, B), Note
  written info. The before (vens main): ((TA + VU) / 2) x ((T + B) / 2) on its group levels, and its 60/40/20/5
  thresholds on that score.
- Within-project spread and ranking entropy: per run, W and H (chain/stats.py); per model and context, the after
  against the before by the non-inferiority bound on mean(after) / mean(before). The two arms score with two formulas
  over two level grids, so beside it, a diagnostic: W and H of the before rescored under L x max(T, B) from its own
  vector, and their ratio to the after's.
- Cross-model spread: per context and arm, for each model pair, the cross-model MPD, Delta and its gap test.
- Band agreement: per context, arm and model pair, the mean over the cross-model run pairs of the share of CVEs whose
  two severities are equal; the same over each model's own run pairs is its floor.
- #340's report: per run, the distinct values of T, B and max(T, B), the shares of CVEs where B > T, T > B and B = T,
  the share of low severities, and the collapse check, the share whose impact is HIGH because of B alone (B at 6 or
  above with T below 6).
- The floor: per model, context and arm, its MPD and its 3-run and N-run spreads over its runs.
- Opportunity's answers on CVEs no draw has used: per model and context, the after's answers to Opportunity on the
  CVEs of a given list apart from the others, a diagnostic.
Every figure names its cell and the replicates it read.
"""
import collections
import itertools
from fractions import Fraction

from chain import cdx, stats
from chain import cells as cellmod

MATRIX = (("info", "low", "medium"), ("low", "medium", "high"), ("medium", "high", "critical"))
LIKELIHOOD, TECHNICAL, BUSINESS = cdx.FACTORS[:8], cdx.FACTORS[8:12], cdx.FACTORS[12:]
IN, OUT = "in the list", "outside it"


def band(x):
    """OWASP's band of a likelihood or an impact: LOW below 3, MEDIUM below 6, HIGH otherwise."""
    return 0 if x < 3 else 1 if x < 6 else 2


def _mean(levels, names):
    return Fraction(sum(levels[f] for f in names), len(names))


def own_rule(rating, arm):
    """(score, severity) the arm's own rule gives from the rating's vector, the score as an exact fraction."""
    lv = rating["levels"]
    if arm == "after":
        lik, impact = _mean(lv, LIKELIHOOD), max(_mean(lv, TECHNICAL), _mean(lv, BUSINESS))
        return lik * impact, MATRIX[band(lik)][band(impact)]
    ta, vu, t, b = (_mean(lv, cdx.FACTORS[i:i + 4]) for i in (0, 4, 8, 12))
    score = (ta + vu) / 2 * ((t + b) / 2)
    return score, cdx.main_severity(float(score))


def rescored(rating):
    """The before's rating rescored under the after's L x max(T, B), from its own vector."""
    lv = rating["levels"]
    return float(_mean(lv, LIKELIHOOD) * max(_mean(lv, TECHNICAL), _mean(lv, BUSINESS)))


def run_targets(rec, arm, report_ids, legal=None):
    """Targets (i) and (ii) of one run: {cves, over, legal, recomputable, severity_ok}. report_ids None: over the
    run's rated CVEs, the report not given. legal: {CVE: accepted}, None when the Java check did not run."""
    ratings = rec["ratings"] or {}
    over = "the report's CVEs" if report_ids is not None else "the VEX's rated CVEs (no report given)"
    ids = sorted(report_ids) if report_ids is not None else sorted(ratings)
    recomputable = severity_ok = 0
    for vid in ids:
        r = ratings.get(vid)
        if r is None or r["score"] is None:
            continue
        score, severity = own_rule(r, arm)
        recomputable += Fraction(r["score"]) == score
        severity_ok += r["severity"] == severity
    n_legal = None if legal is None else sum(1 for vid in ids if legal.get(vid))
    return {"cves": len(ids), "over": over, "legal": n_legal, "recomputable": recomputable,
            "severity_ok": severity_ok}


def targets(cells, report_of, legal_of=None):
    """{cell: {replicate: run_targets}} over every replicate's run that published a VEX. report_of(rec): the
    report's CVE ids or None; legal_of(rec): {CVE: accepted} or None."""
    out = {}
    for k, c in sorted(cells.items(), key=lambda kv: str(kv[0])):
        runs = cellmod.complete_runs(c)
        if runs:
            out[k] = {rep: run_targets(rec, k[1], report_of(rec), legal_of(rec) if legal_of else None)
                      for rep, rec in runs.items()}
    return out


def by_model(cells, corpus=cellmod.DEMO):
    """{(model, unit): {arm: cell}} of one corpus's cells with runs, the model as provider/model."""
    out = collections.defaultdict(dict)
    for k, c in cells.items():
        if k[0] == corpus and c["runs"]:
            out[(cellmod.model_of(k), k[4])][k[1]] = c
    return dict(out)


def model_pairs(cells, corpus=cellmod.DEMO):
    """{(unit, arm): {model: cell}} of one corpus's cells with runs, the models paired only at one batch size."""
    per = collections.defaultdict(dict)
    for k, c in cells.items():
        if k[0] == corpus and c["runs"]:
            per[(k[4], k[1], k[5])][cellmod.model_of(k)] = c
    return {(u, arm): models for (u, arm, _), models in per.items()} if len({b for _, _, b in per}) <= 1 else \
        {(u, f"{arm}, batch {b}"): models for (u, arm, b), models in per.items()}


def runs_of(c):
    return [c["runs"][r] for r in sorted(c["runs"])]


def _wh(runs, ids, value="score"):
    m = cellmod.matrix(runs, ids, value)
    return {"W": [float(x) for x in stats.run_spread(m)], "H": [float(x) for x in stats.run_entropy(m)],
            "replicates": [r["what"]["replicate"] for r in runs], "cves": len(ids)}


def spreads(cells):
    """Per (model, context): W and H per run in each arm over the CVEs both arms rate, and the after against the
    before and against the before rescored."""
    out = {}
    for (model, ctx), arms in sorted(by_model(cells).items()):
        ids = cellmod.common([r for c in arms.values() for r in runs_of(c)])
        row = {arm: _wh(runs_of(c), ids) for arm, c in arms.items()}
        if "before" in arms:
            row["before rescored"] = _wh(runs_of(arms["before"]), ids, rescored)
        for base in ("before", "before rescored"):
            if "after" in row and base in row:
                row[f"after / {base}"] = {s: stats.noninferiority(row["after"][s], row[base][s]) for s in ("W", "H")}
        out[(model, ctx)] = row
    return out


def cross_model(cells):
    """Per (context, arm, model a, model b): the CVEs, the two within-model MPDs, the cross MPD, Delta and its p,
    and the band agreement, cross and within each model."""
    out = {}
    for (ctx, arm), models in sorted(model_pairs(cells).items()):
        for a, b in itertools.combinations(sorted(models), 2):
            ra, rb = runs_of(models[a]), runs_of(models[b])
            ids = cellmod.common(ra + rb)
            ma, mb = cellmod.matrix(ra, ids), cellmod.matrix(rb, ids)
            d, p = stats.gap_test(ma, mb, stats.rng_for(f"gap|{arm}|{ctx}|{a}|{b}"))
            sa, sb = cellmod.matrix(ra, ids, "severity"), cellmod.matrix(rb, ids, "severity")
            out[(ctx, arm, a, b)] = {
                "cves": len(ids), "replicates": (sorted(models[a]["runs"]), sorted(models[b]["runs"])),
                "mpd": (stats.mpd(ma), stats.mpd(mb)), "cross": stats.cross_mpd(ma, mb), "delta": d, "p": p,
                "bands": stats.agreement(sa, sb),
                "bands_within": (stats.within_agreement(sa), stats.within_agreement(sb))}
    return out


def impact_report(rec):
    """#340's figures for one run."""
    rs = [r for r in (rec["ratings"] or {}).values() if r.get("score") is not None]
    n = len(rs)
    share = lambda pred: sum(1 for r in rs if pred(r)) / n if n else None
    return {"cves": n, "distinct_T": len({r["T"] for r in rs}), "distinct_B": len({r["B"] for r in rs}),
            "distinct_max": len({r["impact"] for r in rs}),
            "B>T": share(lambda r: r["B"] > r["T"]), "T>B": share(lambda r: r["T"] > r["B"]),
            "B=T": share(lambda r: r["B"] == r["T"]), "low": share(lambda r: r["severity"] == "low"),
            "collapse": share(lambda r: r["B"] >= 6 and r["T"] < 6)}


def impacts(cells):
    return {k: {rep: impact_report(rec) for rep, rec in sorted(c["runs"].items())}
            for k, c in sorted(cells.items(), key=lambda kv: str(kv[0])) if k[0] == cellmod.DEMO and c["runs"]}


def floors(cells):
    """Per (model, context, arm): stats.floor over its runs."""
    out = {}
    for (model, ctx), arms in sorted(by_model(cells).items()):
        for arm, c in sorted(arms.items()):
            runs = runs_of(c)
            out[(model, ctx, arm)] = {**stats.floor(cellmod.matrix(runs, cellmod.common(runs))),
                                      "replicates": sorted(c["runs"])}
    return out


def opportunity(cells, listed):
    """Per (model, context): for the CVEs in the list and outside it, the count of CVEs, the after's Opportunity
    answers over its runs and their mean level; an unrated entry and a CVE with no answer to it are left out."""
    out = {}
    for (model, ctx), arms in sorted(by_model(cells).items()):
        if "after" not in arms:
            continue
        tally = {IN: collections.Counter(), OUT: collections.Counter()}
        levels, cves = {IN: [], OUT: []}, {IN: set(), OUT: set()}
        for rec in runs_of(arms["after"]):
            for vid, e in ((rec["answers"] or {}).get("per_cve") or {}).items():
                o = e["factors"].get("O")
                if o is None or e["unrated"] or o["answer"] is None:
                    continue
                side = IN if vid in listed else OUT
                tally[side][str(o["answer"])] += 1
                levels[side].append(o["level"])
                cves[side].add(vid)
        out[(model, ctx)] = {s: {"cves": len(cves[s]), "answers": dict(sorted(tally[s].items())),
                                 "mean_level": sum(levels[s]) / len(levels[s]) if levels[s] else None}
                             for s in (IN, OUT)}
        out[(model, ctx)]["replicates"] = sorted(arms["after"]["runs"])
    return out
