"""The scenarios' diagnostics that read no contrast: consistency, the wrong YAML, and the table against the null
model with the after's conservative fallback. Each is printed and judged by nothing.

- Consistency: per model, scenario and arm, the SD (n - 1) of the score over the replicates' runs, and their mean over
  the scenarios; for the after, per question, the agreement of its answers, the mean over replicate pairs of whether
  the two answers are the same, averaged over the scenarios that ask it.
- The wrong YAML: the runs of wrong_yaml, whose context contradicts its CVE's text, as published.
- The table against the null model (baseline.py, frozen): per scenario, its four aggregates scored under each arm's
  own rule, the before's ((TA + VU) / 2) x ((T + B) / 2) and its 60/40/20/5 thresholds, the after's L x max(T, B)
  with L = (TA + VU) / 2 and OWASP's matrix; beside them each arm's median score and most common severity per model,
  over the runs that give one, and the after's fallback: the after's own binary with every answer forced to
  cannot_tell (vens's mock with VENS_MOCK_LLM_CANNOT_TELL), every model-answered factor at its worst case. The
  fallback is not a null model and measures no benefit of the model's answers.
"""
import collections
import itertools
import statistics
from fractions import Fraction

from chain import cdx, demo, families
from chain import cells as cellmod

WRONG_YAML = "wrong_yaml"


def null_rules(null):
    """{before: (score, severity), after: (score, severity)} of the null model's four aggregates."""
    ta, vu, ti, bi = (null[k] for k in ("threat_agent", "vulnerability", "technical_impact", "business_impact"))
    lik = Fraction(ta + vu, 2)
    before = lik * Fraction(ti + bi, 2)
    after = lik * max(ti, bi)
    return {"before": (before, cdx.main_severity(float(before))),
            "after": (after, demo.MATRIX[demo.band(lik)][demo.band(max(ti, bi))])}


def _sd(values):
    values = [v for v in values if v is not None]
    return statistics.stdev(values) if len(values) > 1 else None


def agreement(answers):
    """The mean over pairs of whether two answers are the same; None below two answers."""
    pairs = list(itertools.combinations(answers, 2))
    return sum(1 for a, b in pairs if a == b) / len(pairs) if pairs else None


def _runs(r):
    return [r["runs"][k] for k in sorted(r["runs"])]


def consistency(cells):
    """{"score_sd": {(model, arm): (mean SD, scenarios)}, "answers": {(model, question): (mean agreement,
    scenarios)}, "per": {(model, scenario, arm): SD}}."""
    per, answers = {}, collections.defaultdict(list)
    for (model, sid, arm), r in sorted(families.scenario_runs(cells).items()):
        recs = _runs(r)
        per[(model, sid, arm)] = _sd([families.value(x, "score") for x in recs])
        if arm != "after":
            continue
        by_q = collections.defaultdict(list)
        for x in recs:
            for f, e in (families.factors(x) or {}).items():
                if e["answer"] is not None:
                    by_q[f].append(families.norm(e["answer"]))
        for f, got in by_q.items():
            a = agreement(got)
            if a is not None:
                answers[(model, f)].append(a)
    sds = collections.defaultdict(list)
    for (model, _, arm), sd in per.items():
        if sd is not None:
            sds[(model, arm)].append(sd)
    return {"score_sd": {k: (sum(v) / len(v), len(v)) for k, v in sorted(sds.items())},
            "answers": {k: (sum(v) / len(v), len(v)) for k, v in sorted(answers.items())}, "per": per}


def wrong_yaml(cells):
    """{(model, arm): [(replicate, score, severity, {factor: (level, source)} or None)]}."""
    out = {}
    for (model, sid, arm), r in sorted(families.scenario_runs(cells).items()):
        if sid != WRONG_YAML:
            continue
        rows = []
        for rep, x in sorted(r["runs"].items()):
            fs = families.factors(x)
            rows.append((rep, families.value(x, "score"), families.value(x, "severity"),
                         None if fs is None else {f: (e["level"], e["source"]) for f, e in fs.items()}))
        out[(model, arm)] = rows
    return out


def summary(recs):
    """(median score, most common severity or None on a tie, runs with a score, runs), over the runs that give each:
    a run whose one CVE carries no score or no severity gives none."""
    scores = [v for v in (families.value(x, "score") for x in recs) if v is not None]
    sevs = collections.Counter(v for v in (families.value(x, "severity") for x in recs) if v is not None).most_common()
    mode = sevs[0][0] if sevs and (len(sevs) == 1 or sevs[0][1] > sevs[1][1]) else None
    return (statistics.median(scores) if scores else None), mode, len(scores), len(recs)


def null_table(cells, scen, fallback=None):
    """[{scenario, null, rules, arms: {(model, arm): summary}, fallback: summary or None}] in scenario order;
    fallback: the cells of a fallback campaign."""
    runs = families.scenario_runs(cells)
    fb = families.scenario_runs(fallback or {})
    out = []
    for sid in sorted(scen):
        arms = {(m, a): summary(_runs(r)) for (m, s, a), r in sorted(runs.items()) if s == sid and r["runs"]}
        found = [summary(_runs(r)) for (m, s, a), r in sorted(fb.items()) if s == sid and a == "after" and r["runs"]]
        out.append({"scenario": sid, "null": scen[sid]["null"], "rules": null_rules(scen[sid]["null"]),
                    "arms": arms, "fallback": found[0] if found else None})
    return out


def fallback_cells(records):
    """The cells of a fallback campaign's after."""
    return cellmod.group([r for r in records if r["what"].get("arm") == "after"])
