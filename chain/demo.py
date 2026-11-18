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
- Cross-model spread: per context and arm, for each model pair, over the CVEs both models' runs rate, the
  cross-model MPD, Delta and its gap test; a pair with no such CVE is unavailable, none of them computed.
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
    """Targets (i) and (ii) of one complete run over its report's CVEs, a CVE the VEX does not rate failing both, and
    a run without a VEX failing every CVE: {cves, vex, legal, recomputable, severity_ok}. legal: {CVE: accepted},
    None when the Java check did not run."""
    ratings = rec["ratings"] or {}
    ids = sorted(report_ids)
    recomputable = severity_ok = 0
    for vid in ids:
        r = ratings.get(vid)
        if r is None or r["score"] is None:
            continue
        score, severity = own_rule(r, arm)
        recomputable += Fraction(r["score"]) == score
        severity_ok += r["severity"] == severity
    n_legal = None if legal is None else sum(1 for vid in ids if legal.get(vid))
    return {"cves": len(ids), "vex": rec["ratings"] is not None, "legal": n_legal, "recomputable": recomputable,
            "severity_ok": severity_ok}


NO_REPORT = "unavailable: the scanner's report is not given (--demo names the vens-demo tree that holds it)"


def targets(cells, report_of, legal_of=None):
    """{cell: {replicate: run_targets, or {"unavailable": why}}} over every replicate's complete run. report_of(rec):
    the report's CVE ids, None when not given; legal_of(rec): {CVE: accepted}, None without the Java check."""
    out = {}
    for k, c in sorted(cells.items(), key=lambda kv: str(kv[0])):
        if k.arm not in cellmod.ARMS:
            continue
        per = {}
        for rep, rec in cellmod.complete_runs(c).items():
            ids = report_of(rec)
            per[rep] = {"unavailable": NO_REPORT} if ids is None else \
                run_targets(rec, k.arm, ids, legal_of(rec) if legal_of else None)
        if per:
            out[k] = per
    return out


def by_model(cells, corpus=cellmod.DEMO):
    """{(campaign, model, unit): {arm: cell}} of one corpus's cells with runs, the model as provider/model; a group
    whose arm holds two vens commits is left out, compared with nothing."""
    out, clash = collections.defaultdict(dict), set()
    for k, c in cells.items():
        if k.corpus == corpus and c["runs"] and k.arm in cellmod.ARMS:
            g = (k.campaign, cellmod.model_of(k), k.unit)
            if k.arm in out[g]:
                clash.add(g)
            out[g][k.arm] = c
    return {g: arms for g, arms in out.items() if g not in clash}


def model_pairs(cells, corpus=cellmod.DEMO):
    """{(campaign, unit, arm): {model: cell}} of one corpus's cells with runs, models paired only at one batch size,
    the arm labelled with it where a campaign holds several."""
    per = collections.defaultdict(dict)
    for (campaign, model, u), arms in by_model(cells, corpus).items():
        for arm, c in arms.items():
            batch = next(k.batch for k, x in cells.items() if x is c)
            per[(campaign, u, arm, batch)][model] = c
    batches = collections.defaultdict(set)
    for campaign, _, _, b in per:
        batches[campaign].add(b)
    return {(cp, u, arm if len(batches[cp]) <= 1 else f"{arm}, batch {b}"): models
            for (cp, u, arm, b), models in per.items()}


def runs_of(c):
    return [c["runs"][r] for r in sorted(c["runs"])]


def _wh(runs, value="score"):
    """W and H of each run over its own CVEs."""
    per = [list(cellmod.scores(r, value).values()) for r in runs]
    return {"W": [float(stats.run_spread([x])[0]) for x in per], "H": [stats.entropy(x) for x in per],
            "replicates": [r["what"]["replicate"] for r in runs], "cves": [len(x) for x in per]}


def cohort(arms):
    """The CVEs one arm's runs rate and the other's do not, each way, and the runs whose CVEs differ from their
    arm's."""
    sets = {arm: [set(cellmod.scores(r)) for r in runs_of(c)] for arm, c in arms.items()}
    union = {arm: set().union(*xs) for arm, xs in sets.items()}
    out = {"only": {arm: sorted(union[arm] - union[other]) for arm, other in (("after", "before"), ("before", "after"))
                    if arm in union and other in union},
           "uneven": {arm: sum(1 for x in xs if x != union[arm]) for arm, xs in sets.items()}}
    return out


def spreads(cells):
    """Per (campaign, model, context): W and H of each run over its own CVEs in each arm, the cohorts' mismatch, and
    the after against the before and against the before rescored."""
    out = {}
    for g, arms in sorted(by_model(cells).items(), key=lambda kv: str(kv[0])):
        row = {arm: _wh(runs_of(c)) for arm, c in arms.items()}
        if "before" in arms:
            row["before rescored"] = _wh(runs_of(arms["before"]), rescored)
        row["cohort"] = cohort(arms)
        for base in ("before", "before rescored"):
            if "after" in row and base in row:
                row[f"after / {base}"] = {s: stats.noninferiority(row["after"][s], row[base][s]) for s in ("W", "H")}
        out[g] = row
    return out


NO_COMMON = "unavailable: no CVE both models' runs rate"


def cross_model(cells):
    """Per (campaign, context, arm, model a, model b): the CVEs, the two within-model MPDs, the cross MPD, Delta and
    its p with the gap test's key, and the band agreement, cross and within each model; without a CVE both models'
    runs rate, none of them, the pair unavailable."""
    out = {}
    key_of = {id(c): k for k, c in cells.items()}
    for (campaign, ctx, arm), models in sorted(model_pairs(cells).items(), key=lambda kv: str(kv[0])):
        for a, b in itertools.combinations(sorted(models), 2):
            ra, rb = runs_of(models[a]), runs_of(models[b])
            ids = cellmod.common(ra + rb)
            key = gap_key(key_of[id(models[a])], key_of[id(models[b])])
            row = {"cves": len(ids), "replicates": (sorted(models[a]["runs"]), sorted(models[b]["runs"])),
                   "key": key, "mpd": (None, None), "cross": None, "delta": None, "p": None, "bands": None,
                   "bands_within": (None, None)}
            if not ids:
                out[(campaign, ctx, arm, a, b)] = {**row, "unavailable": NO_COMMON}
                continue
            ma, mb = cellmod.matrix(ra, ids), cellmod.matrix(rb, ids)
            d, p = stats.gap_test(ma, mb, stats.rng_for(key))
            sa, sb = cellmod.matrix(ra, ids, "severity"), cellmod.matrix(rb, ids, "severity")
            out[(campaign, ctx, arm, a, b)] = {
                **row, "mpd": (stats.mpd(ma), stats.mpd(mb)), "cross": stats.cross_mpd(ma, mb), "delta": d, "p": p,
                "bands": stats.agreement(sa, sb),
                "bands_within": (stats.within_agreement(sa), stats.within_agreement(sb))}
    return out


def gap_key(cell_a, cell_b):
    """The gap test's key, from the two cells' own fields, never their labels: its draws come from
    SeedSequence([310, crc32(key)]). A campaign enters by its name, an unnamed one by its input's own name, the same
    wherever the input lies."""
    return (f"gap|{cell_a.campaign}|{cell_a.arm}|{cell_a.batch}|{cell_a.unit}|{cell_a.provider}/{cell_a.model}|"
            f"{cell_b.provider}/{cell_b.model}")


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
            for k, c in sorted(cells.items(), key=lambda kv: str(kv[0])) if k.corpus == cellmod.DEMO and c["runs"]}


def floors(cells):
    """Per (campaign, model, context, arm): stats.floor over its runs."""
    out = {}
    for (campaign, model, ctx), arms in sorted(by_model(cells).items(), key=lambda kv: str(kv[0])):
        for arm, c in sorted(arms.items()):
            runs = runs_of(c)
            out[(campaign, model, ctx, arm)] = {**stats.floor(cellmod.matrix(runs, cellmod.common(runs))),
                                                "replicates": sorted(c["runs"])}
    return out


def _o_answers(rec):
    """{CVE: (answer, level)} of a run's Opportunity answers: a rated entry whose question was asked."""
    out = {}
    for vid, e in ((rec["answers"] or {}).get("per_cve") or {}).items():
        o = e["factors"].get("O")
        if o is not None and not e["unrated"] and o["answer"] is not None:
            out[vid] = (str(o["answer"]), o["level"])
    return out


def opportunity(cells, listed, report_of=lambda rec: None):
    """Per (campaign, model, context): for the CVEs in the list and outside it, the CVEs (the report's, else the
    runs' rated ones), those an Opportunity answer was read for, the others (not asked, unrated or not rated), and the
    after's answers over its runs with their mean level."""
    out = {}
    for (campaign, model, ctx), arms in sorted(by_model(cells).items(), key=lambda kv: str(kv[0])):
        if "after" not in arms:
            continue
        runs = runs_of(arms["after"])
        cves = set().union(*[report_of(r) or set(r["ratings"] or {}) for r in runs])
        tally, levels, answered = {IN: collections.Counter(), OUT: collections.Counter()}, {IN: [], OUT: []}, set()
        for rec in runs:
            for vid, (answer, level) in _o_answers(rec).items():
                side = IN if vid in listed else OUT
                tally[side][answer] += 1
                levels[side].append(level)
                answered.add(vid)
        row = {}
        for side in (IN, OUT):
            mine = {v for v in cves if (v in listed) == (side == IN)}
            row[side] = {"cves": len(mine), "answered": len(mine & answered), "dropped": len(mine - answered),
                         "answers": dict(sorted(tally[side].items())),
                         "mean_level": sum(levels[side]) / len(levels[side]) if levels[side] else None}
        out[(campaign, model, ctx)] = {**row, "replicates": sorted(arms["after"]["runs"]), "cves_read": cves}
    return out
