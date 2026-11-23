"""The scenarios' families on what vens published: each check of chain/verdicts.py read on the runs of a scenario
campaign, both arms on the sub-scores of the published vector and the after on its factors, each level with the
source answers.json gives it.

A check reads one quantity of its scenarios' one CVE: the score, the severity, a sub-score (L, TA, VU, T, B), a
factor's level, or a factor's answer as the reply wrote it. On a pair it reads the difference b - a, replicate by
replicate, the two runs of one replicate and model paired; on one scenario, the value against its target or against
the null model's aggregate (baseline.py). A replicate without a run of both scenarios is missing, and so is a value
its run does not give (a factor the before does not publish, an answer not asked). Beside the replicates, the
verdict on the medians over each scenario's runs (the most common value for a severity or an answer), as the old
analysis read them. The kind is the check's: carried and new say pass or fail, a diagnostic prints its values and is
judged by nothing; which statistic over replicates a verdict takes is written before the run.

On one scenario, each replicate's value comes with the levels of the quantity's factors in the after and the source of
each. The move between two runs of the after: none when no factor of the quantity changes level; Go's when every
factor that changes took its level from Go in both runs (constant, config, floor), or the same answer in both, which
Go crossed with a declared field (Loss of confidentiality's column, Loss of accountability's traceability, Privacy
violation's cap), reachability's not_reachable in both included (310-step3b 19b333a); the model's when every factor
that changes was answered in both runs, the two answers differing; mixed otherwise, a factor Go set in one run and the
model answered in the other among them, reachability's among them. The before publishes four aggregates copied into
its vector, with no source: its moves are not attributed. "answer R" reads the reachability answer, which no run
before 19b333a gives. A row read on a run that asks reachability is marked certified False: the checks' kinds come
from chain/verdicts.py's b7c0435 rules, which certify none of it.

With the after's contract pinned to C1 + C2 (310-c1c2 2de5d34; ctx_analyze --rules c1c2), every model is read on
CHECKS_C1C2, each row marked rules c1c2 and certified where every after run it reads follows C1 + C2; Go's moves then
include source cvss. "status" reads the VEX
status of the run's CVE, () for none, which an implementation check compares with the one the scenario's config
declares (chain.contract.status); "rating" whether the published levels are those C1 + C2's rules give the run's
answers, which no reachability input reaches. every_replicate() reads plan Z0's showcase contract on a row, every
replicate; gates() keeps read5's eligibility rule, an item the before does not pass in FAMILY_ROBUST of its replicates
printing not gated. A row whose scenarios hold a CVE without a usable v3 vector, LC, LI and LAV at 9 under C2, is
tagged vectorless, so that a regression there is reported apart.
"""
import collections
import statistics
from fractions import Fraction

from chain import cdx, contract, verdicts
from chain import cells as cellmod

GROUPS = {"L": cdx.FACTORS[:8], "TA": cdx.FACTORS[:4], "VU": cdx.FACTORS[4:8], "T": cdx.FACTORS[8:12],
          "B": cdx.FACTORS[12:], "score": cdx.FACTORS, "severity": cdx.FACTORS}
GO_SOURCES = ("constant", "config", "floor", contract.CVSS_SOURCE)
FAMILY_ROBUST = 0.8
ANSWER = "answer"
NONE, GO, MODEL, MIXED = "none", "Go's", "the model's", "mixed"
NULL_FIELD = {"T": "technical_impact", "B": "business_impact"}


def who(cell):
    """A campaign's model: the campaign, then provider/model."""
    return f"{cell.campaign} · {cellmod.model_of(cell)}"


def scenario_runs(cells):
    """{(campaign's model, scenario, arm): {"runs": {replicate: record}, "replicates": every replicate attempted}}; a
    scenario whose arm holds complete runs at two vens commits in one campaign is left out, as cells.conflicts() finds
    it, and attempts that never completed at another commit only count as attempted."""
    out, read, clash = {}, set(), set()
    for k, c in cells.items():
        if k.corpus == cellmod.SCENARIOS and k.arm in cellmod.ARMS:
            g = (who(k), k.unit, k.arm)
            r = out.setdefault(g, {"runs": {}, "replicates": set()})
            r["replicates"] |= {x["what"]["replicate"] for x in c["attempts"]
                                if isinstance(x["what"].get("replicate"), int)} | set(c["runs"])
            if c["runs"] or c["unusable"]:
                clash |= {g} if g in read else set()
                read.add(g)
                r["runs"] = c["runs"]
    return {g: r for g, r in out.items() if g not in clash}


def _cve(rec):
    ids = sorted(rec["ratings"] or {})
    return ids[0] if len(ids) == 1 else None


def factors(rec):
    """{factor: {answer, reading, level, source, adjusted}} of the run's one CVE, from answers.json; None without."""
    vid = _cve(rec)
    entry = ((rec.get("answers") or {}).get("per_cve") or {}).get(vid)
    return None if entry is None or entry["unrated"] else entry["factors"]


def reachability(rec):
    """{answer, reading} of the run's one CVE's reachability, None without, or before 19b333a."""
    vid = _cve(rec)
    entry = ((rec.get("answers") or {}).get("per_cve") or {}).get(vid)
    return None if entry is None or entry["unrated"] else entry.get("reachability")


def norm(answer):
    return tuple(sorted(answer)) if isinstance(answer, list) else answer


def rerated(rec, scenario):
    """Whether the run's published levels are the ones C1 + C2's rules give its answers on its scenario, with no
    reachability input; None without answers.json."""
    fs = factors(rec)
    if fs is None:
        return None
    answers = {f: x["answer"] for f, x in fs.items()}
    adjusted = {f: (fs.get(f) or {}).get("adjusted") for f in ("O", "PV")}
    got = contract.c1c2_levels(scenario["dep"], scenario["impact"], scenario["described"], answers, adjusted)
    return all(rec["ratings"][_cve(rec)]["levels"][f] == got[f][0] for f in cdx.FACTORS)


def value(rec, quantity, scenario=None):
    """The quantity in one run, None where the run does not give it; "rating" reads the run's scenario."""
    vid = _cve(rec)
    if vid is None:
        return None
    r = rec["ratings"][vid]
    if quantity in ("score", "severity", "L", "TA", "VU", "T", "B"):
        return r[quantity]
    if quantity == "status":
        return verdicts.status_tuple(r.get("analysis"))
    if quantity == "rating":
        return None if scenario is None else rerated(rec, scenario)
    fs = factors(rec)
    if quantity == f"answer {contract.R}":
        reach = reachability(rec)
        return None if reach is None else norm(reach["answer"])
    if quantity.startswith("answer "):
        f = (fs or {}).get(quantity.split()[1])
        return None if f is None else norm(f["answer"])
    if fs is not None:
        return (fs.get(quantity) or {}).get("level")
    return r["levels"].get(quantity) if rec["what"].get("arm") == "before" else None


def moved(rec_a, rec_b, quantity):
    """[(factor, level a, level b, source a, source b, same answer)] of the quantity's factors whose level changes;
    None when a run has no answers.json entry."""
    fa, fb = factors(rec_a), factors(rec_b)
    if fa is None or fb is None:
        return None
    out = []
    for f in GROUPS.get(quantity, (quantity,)):
        x, y = fa.get(f), fb.get(f)
        if x is None or y is None:
            return None
        if x["level"] != y["level"]:
            # Both from reachability: one answer, not_reachable, which Go crossed with traceability.
            same = (x["answer"] is not None and norm(x["answer"]) == norm(y["answer"])) or (
                x["source"] == y["source"] == contract.REACH_SOURCE)
            out.append((f, x["level"], y["level"], x["source"], y["source"], same))
    return out


def _names(quantity):
    return (quantity.split()[1],) if quantity.startswith("answer ") else GROUPS.get(quantity, (quantity,))


def sources(rec_a, rec_b, quantity):
    """{(source a, source b): [factors]} of the quantity's factors, None without answers.json."""
    fa, fb = factors(rec_a), factors(rec_b)
    if fa is None or fb is None:
        return None
    out = {}
    for f in _names(quantity):
        out.setdefault(((fa.get(f) or {}).get("source"), (fb.get(f) or {}).get("source")), []).append(f)
    return out


def levels(rec, quantity):
    """{factor: (level, source)} of the quantity's factors in one run, None without answers.json."""
    fs = factors(rec)
    if fs is None:
        return None
    return {f: (fs[f]["level"], fs[f]["source"]) for f in _names(quantity) if f in fs}


def _by(source_a, source_b, same):
    """Whose a changed factor's move is: Go's, the model's, or neither alone (mixed)."""
    if same or (source_a in GO_SOURCES and source_b in GO_SOURCES):
        return GO
    return MODEL if source_a == source_b == ANSWER else MIXED


def move(rec_a, rec_b, quantity):
    """none, Go's, the model's or mixed (above); None when it cannot be told."""
    if quantity.startswith("answer "):
        return None
    m = moved(rec_a, rec_b, quantity)
    if m is None:
        return None
    if not m:
        return NONE
    by = {_by(sa, sb, same) for _, _, _, sa, sb, same in m}
    return by.pop() if len(by) == 1 else MIXED


def _numeric(v):
    return isinstance(v, (int, float, Fraction)) and not isinstance(v, bool)


def _ok_pair(check, va, vb, sa=None):
    if va is None or vb is None:
        return None
    if check.quantity == "status":
        return verdicts.status_pair_ok(va, vb, (sa or {}).get("status", ()))
    if check.quantity.startswith("answer ") or check.quantity == "severity":
        return va == vb
    return verdicts.PAIR_TESTS[check.test](Fraction(vb) - Fraction(va))


def _summary(values):
    """The median of numbers, the most common value otherwise (None when two tie for it)."""
    values = [v for v in values if v is not None]
    if not values:
        return None
    if all(_numeric(v) for v in values):
        return statistics.median(values)
    top = collections.Counter(values).most_common()
    return top[0][0] if len(top) == 1 or top[0][1] > top[1][1] else None


EMPTY = {"runs": {}, "replicates": set()}


def pair(check, arm, a, b, model, runs, scen=None):
    """One pair of one check in one arm for one model; None when neither scenario was run."""
    ra, rb = runs.get((model, a, arm)), runs.get((model, b, arm))
    if ra is None and rb is None:
        return None
    ra, rb = ra or EMPTY, rb or EMPTY
    sa = (scen or {}).get(a)
    per, missing = [], []
    for rep in sorted(ra["replicates"] | rb["replicates"]):
        x, y = ra["runs"].get(rep), rb["runs"].get(rep)
        va, vb = (value(x, check.quantity), value(y, check.quantity)) if x and y else (None, None)
        ok = _ok_pair(check, va, vb, sa)
        if ok is None:
            missing.append(rep)
            continue
        per.append({"replicate": rep, "a": va, "b": vb, "ok": ok,
                    "move": move(x, y, check.quantity) if arm == "after" else None,
                    "moved": moved(x, y, check.quantity) if arm == "after" else None,
                    "sources": sources(x, y, check.quantity) if arm == "after" else None})
    ma = _summary([value(r, check.quantity) for r in ra["runs"].values()])
    mb = _summary([value(r, check.quantity) for r in rb["runs"].values()])
    return {"item": (a, b), "per": per, "missing": missing, "median": (ma, mb, _ok_pair(check, ma, mb, sa))}


def _ok_single(check, arm, sid, v, scen):
    if v is None:
        return None
    if check.test == "any":
        return True
    if check.quantity == "status":
        return verdicts.status_ok(check.test, v, scen[sid]["status"])
    if check.quantity == "rating":
        return v is True
    if check.test in ("below_null", "above_null"):
        null = Fraction(scen[sid]["null"][NULL_FIELD[check.quantity]])
        return Fraction(v) < null if check.test == "below_null" else Fraction(v) > null
    return v in dict(check.target)[arm]


def single(check, arm, sid, model, runs, scen):
    """One scenario of one check in one arm for one model, each replicate's value with, in the after, the levels of
    the quantity's factors and their sources; None when it was not run."""
    r = runs.get((model, sid, arm))
    if r is None:
        return None
    per, missing = [], []
    for rep in sorted(r["replicates"]):
        x = r["runs"].get(rep)
        v = None if x is None else value(x, check.quantity, scen.get(sid))
        ok = _ok_single(check, arm, sid, v, scen)
        if ok is None:
            missing.append(rep)
        else:
            per.append({"replicate": rep, "value": v, "ok": ok,
                        "levels": levels(x, check.quantity) if arm == "after" else None})
    m = _summary([p["value"] for p in per])
    return {"item": sid, "per": per, "missing": missing, "median": (m, _ok_single(check, arm, sid, m, scen))}


def run_rules(rec):
    """The contract an after run's answers.json shows, read off the record to certify a row against the pinned one,
    never to choose the checks: 5f797bf's (reachability asked), C1 + C2's (a declared block or a level from source
    cvss), b7c0435's; None without one."""
    per = (rec.get("answers") or {}).get("per_cve")
    if not per:
        return None
    if verdicts.asks_reachability(rec):
        return contract.REACH_RULES
    if any(e.get("declared") is not None or any((x or {}).get("source") == contract.CVSS_SOURCE
                                                for x in e["factors"].values()) for e in per.values()):
        return contract.C1C2
    return contract.B7C0435


def _sids(item):
    return item if isinstance(item, tuple) else (item,)


def _certified(runs, model, item, arm, rules):
    """Whether every after run a row reads follows the rules its kinds come from; a before row always is."""
    if arm != "after":
        return True
    found = {run_rules(x) for sid in _sids(item) for x in (runs.get((model, sid, arm)) or EMPTY)["runs"].values()}
    return found - {None} <= {rules}


def _vectorless(item, scen):
    return any("impact" in (scen.get(sid) or {}) and scen[sid]["impact"].usable == 0 for sid in _sids(item))


def evaluate(cells, scen, checks=None, rules=contract.B7C0435):
    """[{check, arm, kind, model, row, rules, certified, vectorless}] for every check, arm it reads, model with runs,
    and pair or scenario. The checks are the pinned after contract's (rules, preregistered, never read off the runs;
    verdicts.checks_for), or checks; certified False where an after run a row reads follows another contract, a run
    asking reachability under b7c0435's among them."""
    runs = scenario_runs(cells)
    models = sorted({m for m, _, _ in runs})
    out = []
    for c in (checks or verdicts.checks_for(rules)):
        for arm, kind in c.kinds:
            for model in models:
                for item in c.scenarios:
                    row = pair(c, arm, *item, model, runs, scen) if c.pairs() else \
                        single(c, arm, item, model, runs, scen)
                    if row is not None:
                        out.append({"check": c, "arm": arm, "kind": kind, "model": model, "row": row,
                                    "rules": rules, "certified": _certified(runs, model, item, arm, rules),
                                    "vectorless": _vectorless(item, scen)})
    return out


def every_replicate(row):
    """Plan Z0's reading of an implementation check: fail when a replicate fails, pass when every replicate passes
    and none is missing, inconclusive otherwise."""
    if any(not p["ok"] for p in row["per"]):
        return "fail"
    return "pass" if row["per"] and not row["missing"] else "inconclusive"


def family_item(before_ok, after_ok, robust=FAMILY_ROBUST):
    """read5's family_item: (the before's pass share, the after's fail share, verdict). Gated where the before passes
    in at least robust of its replicates; there failed when the after fails in at least robust of its own, weakened
    when it fails in more than 1 - robust and fewer than robust, kept otherwise; not gated elsewhere."""
    nb, na = len(before_ok), len(after_ok)
    if not nb or not na:
        return None, None, "inconclusive"
    pb = sum(1 for x in before_ok if x) / nb
    fa = sum(1 for x in after_ok if not x) / na
    if pb < robust - 1e-12:
        return pb, fa, "not gated"
    if fa >= robust - 1e-12:
        return pb, fa, "fail"
    return pb, fa, "weakened" if fa > 1 - robust + 1e-12 else "pass"


GATED = (verdicts.CARRIED, verdicts.NEW, verdicts.IMPLEMENTATION)


def gates(rows):
    """{(family, label, item, model): (the before's pass share, the after's fail share, verdict)} by read5's rule,
    for every check whose after is carried, new or implementation and whose before is read beside it; inconclusive
    where a row misses a replicate."""
    by = collections.defaultdict(dict)
    for r in rows:
        by[(r["check"].family, r["check"].label, r["row"]["item"], r["model"])][r["arm"]] = r
    out = {}
    for key, arms in by.items():
        if "before" not in arms or "after" not in arms or arms["after"]["kind"] not in GATED:
            continue
        b, a = arms["before"]["row"], arms["after"]["row"]
        out[key] = (None, None, "inconclusive") if b["missing"] or a["missing"] else \
            family_item([p["ok"] for p in b["per"]], [p["ok"] for p in a["per"]])
    return out


def family_moves(rows):
    """{(family, model): Counter of the after's moves} over every replicate of its pair rows."""
    out = collections.defaultdict(collections.Counter)
    for r in rows:
        if r["arm"] == "after" and r["check"].pairs():
            for p in r["row"]["per"]:
                if p["move"] is not None:
                    out[(r["check"].family, r["model"])][p["move"]] += 1
    return dict(out)


def all_gos(counter):
    """A family whose every move is Go's or none, with one Go's at least."""
    return counter.get(GO, 0) > 0 and set(counter) <= {GO, NONE}
