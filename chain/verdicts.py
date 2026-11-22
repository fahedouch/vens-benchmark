"""Which verdicts the scenarios' contrasts can decide.

The families the analysis reads, each check labelled: carried, the old chain's verdict restated on the new record;
new, a verdict the old chain did not make, whose expected direction the preregistration writes before the run;
diagnostic, printed and judged by nothing. A check stays carried or new only if both a pass and a fail are attainable
through what its two scenarios differ in or, on one scenario, through its answers. This module works that out on the
corpus as written and fails while a check labelled carried or new has one outcome only.

The after: each factor's levels from chain.contract, the axes each report's vector floors, and the questions whose
prompts the after's mock renders differently for the two scenarios. An answer whose prompt is the same in both is held
equal, the idealisation the check rests on: a model that samples can answer it differently, which is sampling, not
the contrast. The before (vens main) asks one call per CVE for four aggregates of 0 to 9, each copied into its group's
four levels: two scenarios whose prompts differ can get any two sets, otherwise the same one.

    python3 -m chain.verdicts --after BIN --before BIN --work DIR [--scenarios DIR]

prints each contrast and check and exits 1 when a check labelled carried or new has one outcome only.

The after's rules here are chain.contract's at 310-step3 b7c0435 (reach=None), which asks no reachability: they hold
for historical runs alone and certify no run that asks R (310-step3b 19b333a on). after_prompts refuses such a run,
and chain/families.py marks every row read on one.
"""
import argparse
import functools
import itertools
import json
import os
import sys
from dataclasses import dataclass, field
from fractions import Fraction

import yaml

from chain import calls, contract, runvens
from chain.cdx import main_severity

CARRIED, NEW, DIAGNOSTIC = "carried", "new", "diagnostic"
BOTH = lambda kind: (("before", kind), ("after", kind))
AFTER = lambda kind: (("after", kind),)


@dataclass(frozen=True)
class Check:
    family: str
    label: str
    kinds: tuple  # ((arm, kind), ...), the arms the check reads
    scenarios: tuple  # (a, b) pairs, or scenario ids for a check on one scenario
    quantity: str  # a group (L, TA, VU, T, B), "score", a factor's level, "answer F", or "severity"
    # On a pair: le, lt, eq, or gap (b above a by more than 0.5). On one scenario: in or is (target), below_null or
    # above_null (the null model's aggregate), or any (printed only).
    test: str
    target: tuple = field(default=())  # ((arm, values), ...)

    def kind(self, arm):
        return dict(self.kinds).get(arm)

    def pairs(self):
        return all(isinstance(s, tuple) for s in self.scenarios)


EXPO = (("expo_internal", "expo_private"), ("expo_private", "expo_internet"))
CTRL = (("ctrl_on", "ctrl_off"),)
SENS = (("sens_low", "sens_high"), ("sens_high", "sens_critical"))
CRIT = (("crit_low", "crit_critical"),)
COMP = (("comp_none", "comp_gdpr"),)
# Each irrelevant-WAF pair differs in the WAF alone, the scenario without it first.
WAF = (("disc_ctrl_off_local", "disc_ctrl_irrelevant"), ("disc_ctrl_off_local_nt", "disc_ctrl_irrelevant_nt"))
DOS_TWINS = (("disc_dos", "disc_dos_nt"), ("disc_dos2", "disc_dos_nt2"))
AUDIT_TWINS = (("disc_audit", "disc_audit_nt"), ("disc_audit2", "disc_audit_nt2"))
ACCOUNTABILITY = ("disc_audit", "disc_audit2", "disc_audit3", "disc_audit_nt", "disc_audit_nt2")
REACH = (("reach_no", "reach_yes"), ("reach2_no", "reach2_yes"), ("reach3_no", "reach3_yes"))
# The generator's copies of the DoS and accountability scenarios and twins without a CVSS vector.
NOVEC = "_novec"
DOS_COPIES = tuple(s + NOVEC for s in ("disc_dos", "disc_dos2", "disc_dos3", "disc_dos_nt", "disc_dos_nt2"))
AUDIT_COPIES = tuple(s + NOVEC for s in ACCOUNTABILITY)
DOS_COPY_TWINS = tuple((a + NOVEC, b + NOVEC) for a, b in DOS_TWINS)
AUDIT_COPY_TWINS = tuple((a + NOVEC, b + NOVEC) for a, b in AUDIT_TWINS)
BEFORE_ONLY = (("before", CARRIED), ("after", DIAGNOSTIC))

# The families, read twice: on the sub-scores of the published vector, both arms, and for the after on the factors
# that carry the contrast. A kind follows what the contrast can move, the comments saying why where it is not plain.
CHECKS = (
    Check("1 Exposure", "the score not falling", BOTH(CARRIED), EXPO, "score", "le"),
    # Size's step is Go's, from exposure.
    Check("1 Exposure", "L not falling", BOTH(DIAGNOSTIC), EXPO, "L", "le"),
    Check("1 Exposure", "TA not falling", BOTH(DIAGNOSTIC), EXPO, "TA", "le"),
    Check("1 Exposure", "M not falling", AFTER(NEW), EXPO, "M", "le"),
    Check("1 Exposure", "O not falling", AFTER(NEW), EXPO, "O", "le"),
    # ctrl_on changes three controls and a note at once: the claim is theirs together.
    Check("2 Controls", "VU, ctrl_on at most ctrl_off", BOTH(CARRIED), CTRL, "VU", "le"),
    Check("2 Controls", "EE, ctrl_on at most ctrl_off", AFTER(NEW), CTRL, "EE", "le"),
    # The before's prompts differ, so it can decide. In the after the leak's vector floors integrity: Loss of
    # integrity is 1 on both sides and T rises with Go's column alone.
    Check("3 Data sensitivity", "T not falling", BEFORE_ONLY, SENS, "T", "le"),
    # Loss of confidentiality's question does not show data sensitivity, so the contrast cannot move its answer.
    Check("3 Data sensitivity", "LC's extent answer the same", AFTER(DIAGNOSTIC), SENS, "answer LC", "eq"),
    Check("3 Data sensitivity", "LI not falling", AFTER(DIAGNOSTIC), SENS, "LI", "le"),
    Check("4 Business criticality", "B not falling", BOTH(CARRIED), CRIT, "B", "le"),
    Check("4 Business criticality", "FD not falling", AFTER(DIAGNOSTIC), CRIT, "FD", "le"),
    Check("4 Business criticality", "RD not falling", AFTER(DIAGNOSTIC), CRIT, "RD", "le"),
    # The before's prompts differ, so it can decide. In the after the framework reaches Non-compliance alone, 2
    # without it: B's rise is Go's and FD, RD and PV cannot move.
    Check("5 Compliance", "B not falling", BEFORE_ONLY, COMP, "B", "le"),
    Check("5 Compliance", "NC's answer under GDPR, at least Go's 2 without", AFTER(DIAGNOSTIC), COMP, "NC", "le"),
    Check("5 Compliance", "FD not lower with the framework", AFTER(DIAGNOSTIC), COMP, "FD", "le"),
    Check("5 Compliance", "RD not lower with the framework", AFTER(DIAGNOSTIC), COMP, "RD", "le"),
    Check("5 Compliance", "PV not lower with the framework", AFTER(DIAGNOSTIC), COMP, "PV", "le"),
    # In the after the vector floors C and I: T's drop is Go's.
    Check("6 DoS discriminator", "T below the null model's", (("before", CARRIED), ("after", DIAGNOSTIC)),
          ("disc_dos",), "T", "below_null"),
    Check("6 DoS discriminator", "LAV's answer", AFTER(DIAGNOSTIC), ("disc_dos",), "LAV", "any"),
    # Without a vector every impact question is asked: the model's reading of confidentiality and integrity.
    Check("6 DoS discriminator", "without a vector: T below the null model's", BOTH(DIAGNOSTIC), DOS_COPIES, "T",
          "below_null"),
    Check("6 DoS discriminator", "without a vector: LC's extent answer", AFTER(DIAGNOSTIC), DOS_COPIES,
          "answer LC", "any"),
    Check("6 DoS discriminator", "without a vector: LI's answer", AFTER(DIAGNOSTIC), DOS_COPIES, "LI", "any"),
    # The old verdict on T is retired: its successor reads the answer under traceability per_individual.
    Check("7 Accountability discriminator", "T above the null model's", BOTH(DIAGNOSTIC), ("disc_audit",), "T",
          "above_null"),
    Check("7 Accountability discriminator", "LAC's answer defeats_attribution, traceability per_individual",
          AFTER(NEW), ACCOUNTABILITY, "answer LAC", "is", (("after", ("defeats_attribution",)),)),
    Check("7 Accountability discriminator", "without a vector: T above the null model's", BOTH(DIAGNOSTIC),
          AUDIT_COPIES, "T", "above_null"),
    Check("7 Accountability discriminator", "without a vector: LC's extent answer", AFTER(DIAGNOSTIC), AUDIT_COPIES,
          "answer LC", "any"),
    Check("7 Accountability discriminator", "without a vector: LI's answer", AFTER(DIAGNOSTIC), AUDIT_COPIES, "LI",
          "any"),
    Check("8 Relevant against irrelevant control", "VU, ctrl_on below ctrl_off", BOTH(DIAGNOSTIC), CTRL, "VU", "lt"),
    Check("8 Relevant against irrelevant control", "EE, ctrl_on below ctrl_off", AFTER(NEW), CTRL, "EE", "lt"),
    Check("8 Relevant against irrelevant control", "EE the same with and without the irrelevant WAF", AFTER(NEW),
          WAF[:1], "EE", "eq"),
    Check("9 DoS, telegraphed or not", "T's drift", BOTH(DIAGNOSTIC), DOS_TWINS, "T", "eq"),
    Check("9 DoS, telegraphed or not", "LAV's drift", AFTER(DIAGNOSTIC), DOS_TWINS, "LAV", "eq"),
    Check("9 DoS, telegraphed or not", "without a vector: T's drift", BOTH(DIAGNOSTIC), DOS_COPY_TWINS, "T", "eq"),
    Check("9 DoS, telegraphed or not", "without a vector: LC's extent answer's drift", AFTER(DIAGNOSTIC),
          DOS_COPY_TWINS, "answer LC", "eq"),
    Check("9 DoS, telegraphed or not", "without a vector: LI's drift", AFTER(DIAGNOSTIC), DOS_COPY_TWINS, "LI", "eq"),
    Check("10 Accountability, telegraphed or not", "T's drift", BOTH(DIAGNOSTIC), AUDIT_TWINS, "T", "eq"),
    Check("10 Accountability, telegraphed or not", "LAC's answer's drift", AFTER(DIAGNOSTIC), AUDIT_TWINS,
          "answer LAC", "eq"),
    Check("10 Accountability, telegraphed or not", "without a vector: T's drift", BOTH(DIAGNOSTIC), AUDIT_COPY_TWINS,
          "T", "eq"),
    Check("10 Accountability, telegraphed or not", "without a vector: LC's extent answer's drift", AFTER(DIAGNOSTIC),
          AUDIT_COPY_TWINS, "answer LC", "eq"),
    Check("10 Accountability, telegraphed or not", "without a vector: LI's drift", AFTER(DIAGNOSTIC),
          AUDIT_COPY_TWINS, "LI", "eq"),
    Check("11 Irrelevant WAF on the local bug", "VU not lower with the WAF", BOTH(DIAGNOSTIC), WAF, "VU", "le"),
    Check("11 Irrelevant WAF on the local bug", "EE not lower with the WAF", AFTER(NEW), WAF, "EE", "le"),
    # The after never publishes info: its likelihood is never below 4.25.
    Check("showcases", "showcase_high_to_low low", BOTH(CARRIED), ("showcase_high_to_low",), "severity", "in",
          (("before", ("info", "low")), ("after", ("low",)))),
    Check("showcases", "showcase_med_to_high high or critical", BOTH(CARRIED), ("showcase_med_to_high",),
          "severity", "in", (("before", ("high", "critical")), ("after", ("high", "critical")))),
    Check("reachability", "the score above the unreachable one's by more than 0.5", BOTH(CARRIED), REACH, "score",
          "gap"),
    Check("reachability", "O, unreachable at most reachable", AFTER(NEW), REACH, "O", "le"),
    Check("reachability", "EE, unreachable at most reachable", AFTER(NEW), REACH, "EE", "le"),
)


@dataclass(frozen=True)
class Named:
    """A diagnostic that reads no contrast: printed with its scenarios' factors by the source of their level."""
    name: str
    reads: str
    scenarios: tuple  # () for every scenario


NAMED = (
    Named("consistency", "the score's spread over replicates, both arms; for the after, each answer's agreement", ()),
    Named("wrong YAML", "printed, both arms", ("wrong_yaml",)),
    Named("the table against the null model", "each score against the null model's, each arm under its own rule, "
          "and the after's fallback with every answer cannot_tell", ()),
)

# A test on a pair reads the difference b - a.
PAIR_TESTS = {"le": lambda d: d >= 0, "lt": lambda d: d > 0, "eq": lambda d: d == 0,
              "gap": lambda d: d > Fraction(1, 2)}
SEVERITY = (("info", "low", "medium"), ("low", "medium", "high"), ("medium", "high", "critical"))
SEVERITIES = ("info", "low", "medium", "high", "critical")
AGGREGATE = range(10)


def band(x):
    return 0 if x < 3 else 1 if x < 6 else 2


# ---- the after ----

def _levels(f, s, g=None):
    dep = dict(s["dep"], **(g or {}))
    return contract.options(f, dep, s["floors"], s["described"])


def _level_pairs(f, sa, sb, reached, g):
    """The (a, b) levels factor f can take: one answer for both where the contrast does not reach its question,
    any two where it does or where Go treats the two scenarios differently."""
    ma, mb = _levels(f, sa, g.get(sa["id"])), _levels(f, sb, g.get(sb["id"]))
    if f not in reached and set(ma) == set(mb):
        return {(ma[x], mb[x]) for x in ma}
    return {(x, y) for x in set(ma.values()) for y in set(mb.values())}


def _diffs(factors, sa, sb, reached, g):
    """The values b - a a sum of levels can take, each factor's pair chosen on its own."""
    out = {0}
    for f in factors:
        ds = {y - x for x, y in _level_pairs(f, sa, sb, reached, g)}
        out = {d + e for d in out for e in ds}
    return out


def _front(pairs):
    """The pairs (x, y) that no other pair beats with an x as low and a y as high."""
    out, best = [], None
    for x, y in sorted(pairs, key=lambda p: (p[0], -p[1])):
        if best is None or y > best:
            out.append((x, y))
            best = y
    return out


def _sum_front(factors, sa, sb, reached, g, flip):
    out = [(0, 0)]
    for f in factors:
        ps = _level_pairs(f, sa, sb, reached, g)
        if flip:
            ps = {(y, x) for x, y in ps}
        out = _front({(p + x, q + y) for p, q in out for x, y in ps})
    return out


def score_range(sa, sb, reached, g=None):
    """The lowest and the highest b - a of the score, L x max(T, B). The score never falls as a level rises, so
    its b - a is highest on pairs no other beats with a lower a and a higher b, sums and impacts alike: _front."""
    g = g or {}
    G = contract.GROUPS
    ends = []
    for flip in (False, True):  # the highest b - a, then the highest a - b
        lf, tf, bf = (_sum_front(G[k], sa, sb, reached, g, flip) for k in ("L", "T", "B"))
        imp = _front({(max(t1, b1), max(t2, b2)) for t1, t2 in tf for b1, b2 in bf})
        ends.append(max(Fraction(l2 * i2 - l1 * i1, 32) for l1, l2 in lf for i1, i2 in imp))
    return -ends[1], ends[0]


def after_diffs(q, sa, sb, reached, g=None):
    """The values b - a quantity q can take in the after; for the score, its lowest and highest only. g maps a
    scenario id to deployment values that replace its own."""
    g = g or {}
    G = contract.GROUPS
    if q == "score":
        return set(score_range(sa, sb, reached, g))
    if q in G:
        return {Fraction(d, len(G[q])) for d in _diffs(G[q], sa, sb, reached, g)}
    return {Fraction(d) for d in _diffs((q,), sa, sb, reached, g)}


def after_answer_pairs(f, sa, sb, reached, g=None):
    """The (a, b) answers factor f's question can get; none where it is not asked."""
    g = g or {}
    ka = {x for x in _levels(f, sa, g.get(sa["id"])) if x is not None}
    kb = {x for x in _levels(f, sb, g.get(sb["id"])) if x is not None}
    if f in reached:
        return {(x, y) for x in ka for y in kb}
    return {(x, x) for x in ka & kb}


def _sums(factors, s, g=None):
    out = {0}
    for f in factors:
        out = {p + x for p in out for x in set(_levels(f, s, g).values())}
    return out


def after_single(q, s, g=None):
    G = contract.GROUPS
    if q == "severity":
        return {SEVERITY[band(Fraction(lsum, 8))][band(Fraction(max(t, b), 4))]
                for lsum in _sums(G["L"], s, g) for t in _sums(G["T"], s, g) for b in _sums(G["B"], s, g)}
    if q in G:
        return {Fraction(x, len(G[q])) for x in _sums(G[q], s, g)}
    if q.startswith("answer "):
        return {x for x in _levels(q.split()[1], s, g) if x is not None}
    return set(_levels(q, s, g).values())


# ---- the before ----

@functools.lru_cache(maxsize=None)
def before_values(q):
    """The values quantity q takes over every set of four aggregates, one per group."""
    out = set()
    for ta, vu, t, b in itertools.product(AGGREGATE, repeat=4):
        v = {"TA": ta, "VU": vu, "T": t, "B": b, "L": Fraction(ta + vu, 2),
             "score": Fraction(ta + vu, 2) * Fraction(t + b, 2)}
        out.add(main_severity(float(v["score"])) if q == "severity" else Fraction(v[q]))
    return frozenset(out)


def before_diffs(q, differs):
    """b - a: any two of the values where the two prompts differ, the same value otherwise."""
    if not differs:
        return {0}
    values = before_values(q)
    lo, hi = min(values), max(values)
    return {lo - hi, 0, hi - lo}


# ---- outcomes ----

def outcome(check, arm, item, scen, reach, before_differs, g=None):
    """(pass attainable, fail attainable) of a check, in one arm, on one pair or one scenario."""
    q = check.quantity
    if check.pairs():
        a, b = item
        if q.startswith("answer "):
            if check.test != "eq":
                raise ValueError(f"{check.label}: an answer is compared for equality only")
            pairs = after_answer_pairs(q.split()[1], scen[a], scen[b], reach[item][0], g)
            return any(x == y for x, y in pairs), any(x != y for x, y in pairs)
        if q == "score" and check.test == "eq":
            raise ValueError(f"{check.label}: the score's range cannot tell an exact tie")
        ds = after_diffs(q, scen[a], scen[b], reach[item][0], g) if arm == "after" else \
            before_diffs(q, before_differs[item])
        ok = PAIR_TESTS[check.test]
        return any(ok(d) for d in ds), any(not ok(d) for d in ds)
    s = scen[item]
    vals = after_single(q, s, (g or {}).get(item)) if arm == "after" else before_values(q)
    if check.test == "any":
        return bool(vals), bool(vals)
    if check.test in ("below_null", "above_null"):
        null = Fraction(s["null"][{"T": "technical_impact", "B": "business_impact"}[q]])
        ok = (lambda v: v < null) if check.test == "below_null" else (lambda v: v > null)
    else:
        target = set(dict(check.target)[arm])
        ok = lambda v: v in target
    return any(ok(v) for v in vals), any(not ok(v) for v in vals)


WORDS = {(True, True): "pass and fail", (True, False): "pass only", (False, True): "fail only",
         (False, False): "neither"}


def _name(item):
    return " / ".join(item) if isinstance(item, tuple) else item


def check(scen, reach, before_differs, checks=CHECKS):
    """(rows, problems): a row (check, arm, kind, scenarios, outcome) per check, arm it reads and pair or scenario;
    a problem per carried or new row with one outcome only."""
    rows, problems = [], []
    for c in checks:
        for arm, kind in c.kinds:
            for item in c.scenarios:
                res = outcome(c, arm, item, scen, reach, before_differs)
                rows.append((c, arm, kind, item, res))
                if kind in (CARRIED, NEW) and res != (True, True):
                    problems.append(f"{c.family}, {c.label}, {arm}, {_name(item)}: labelled {kind}, {WORDS[res]}")
    return rows, problems


# The corpus-wide values: detection undeclared or one level on the three channels, traceability (the accountability
# family keeps per_individual), data_subjects above the floor's band.
DETECTIONS = (None, "not_logged", "logged", "logged_and_reviewed", "active_in_application")
TRACEABILITIES = ("none", "per_request", "per_individual")
SUBJECTS = ("hundreds", "thousands", "millions")


def _detection(level):
    return None if level is None else {c: level for c in contract.CHANNELS}


def _values(scen, det, trace, subj):
    return {sid: {"detection": _detection(det), "data_subjects": subj,
                  "traceability": s["dep"]["traceability"] if sid in ACCOUNTABILITY else trace}
            for sid, s in scen.items()}


def corpus_wide(scen, reach, checks=CHECKS, unfloored=False):
    """The after's pair outcomes that any of the 45 corpus-wide combinations changes; with unfloored, every vector
    read as flooring nothing. The enumeration runs on chain.contract's Python rules: Go's levels are checked on four
    alternative assignments (three within the 45 and one outside), on six scenarios, in tests/test_verdicts.py."""
    if unfloored:
        scen = {k: dict(s, floors=frozenset()) for k, s in scen.items()}
    changes = []
    for c in checks:
        if not c.pairs() or c.kind("after") is None:
            continue
        for item in c.scenarios:
            base = outcome(c, "after", item, scen, reach, {})
            for det, trace, subj in itertools.product(DETECTIONS, TRACEABILITIES, SUBJECTS):
                got = outcome(c, "after", item, scen, reach, {}, _values(scen, det, trace, subj))
                if got != base:
                    changes.append((c.family, c.label, _name(item), det, trace, subj, WORDS[got]))
    return changes


def showcase_by_detection(scen):
    """{showcase: {detection: the severities attainable in the after}}, the other values as declared."""
    return {sid: {det: sorted(after_single("severity", scen[sid], {"detection": _detection(det)}),
                              key=SEVERITIES.index) for det in DETECTIONS}
            for sid in ("showcase_high_to_low", "showcase_med_to_high") if sid in scen}


# ---- the corpus and the runs ----

def load(scenarios):
    """{id: scenario}: its config, deployment, floored axes, whether its CVE has a description, and the null model's
    aggregates."""
    import baseline  # the frozen null model, at the repository's root

    out = {}
    for sid in sorted(os.listdir(scenarios)):
        d = os.path.join(scenarios, sid)
        if not os.path.isdir(d):
            continue
        with open(os.path.join(d, "config.yaml"), encoding="utf-8") as fh:
            config = yaml.safe_load(fh)
        with open(os.path.join(d, "report.json"), encoding="utf-8") as fh:
            rep = json.load(fh)
        f = contract.finding(os.path.join(d, "report.json"))
        out[sid] = {"id": sid, "config": config, "dep": contract.deployment(config),
                    "floors": contract.floors(contract.vectors(f)),
                    "described": bool((f.get("Description") or "").strip()), "null": baseline.score(config, rep)}
    return out


def needed(checks=CHECKS):
    ids = set()
    for c in checks:
        for item in c.scenarios:
            ids.update(item if isinstance(item, tuple) else (item,))
    return sorted(ids)


def run_dir(folder):
    found = calls.run_folders(os.path.join(folder, "calls"))
    if len(found) != 1:
        raise RuntimeError(f"{folder}: {len(found)} debug runs, one expected")
    return found[0]


def asks_reachability(rec):
    """Whether an attempt's answers.json holds reachability: a run these rules do not certify."""
    return any(e.get("reachability") for e in ((rec.get("answers") or {}).get("per_cve") or {}).values())


def after_prompts(folder):
    """{question: (system prompt, human prompt)} of a batch-1 run on one CVE; refused for a run that asks
    reachability, which b7c0435's rules do not hold for."""
    out = {}
    for c in calls.load(run_dir(folder)):
        q = contract.question_of(c.text("human"))
        if q == contract.R:
            raise RuntimeError(f"{folder}: call {c.number} asks reachability (R): chain.verdicts holds b7c0435's "
                               f"rules, for historical runs only")
        if q is None or q in out:
            raise RuntimeError(f"{folder}: call {c.number} is not one question asked once")
        out[q] = (c.text("system"), c.text("human"))
    return out


def before_prompt(folder):
    found = calls.load(run_dir(folder))
    if len(found) != 1:
        raise RuntimeError(f"{folder}: {len(found)} calls, the before asks one per CVE here")
    return found[0].text("system"), found[0].text("human")


def contrasts(after_runs, before_runs, checks=CHECKS):
    """From run folders, {id: folder} per arm: for every pair the checks read, the after's (questions whose prompts
    differ, whether a system prompt differs), and whether the before's prompt differs."""
    reach, differs = {}, {}
    pa = {sid: after_prompts(f) for sid, f in after_runs.items()}
    pb = {sid: before_prompt(f) for sid, f in before_runs.items()}
    for c in checks:
        if not c.pairs():
            continue
        for a, b in c.scenarios:
            qa, qb = pa[a], pa[b]
            reach[(a, b)] = (frozenset(q for q in set(qa) | set(qb) if qa.get(q) != qb.get(q)),
                             any(qa[q][0] != qb[q][0] for q in set(qa) & set(qb)))
            differs[(a, b)] = pb[a] != pb[b]
    return reach, differs


def run_mock(binary, scenarios, ids, work, arm):
    """One batch-1 mock run per scenario, laid out by chain.runvens; {id: folder}."""
    out = {}
    for sid in ids:
        d = os.path.join(scenarios, sid)
        folder = os.path.join(work, arm, sid)
        rec = runvens.generate(binary, os.path.join(d, "config.yaml"), os.path.join(d, "report.json"), folder,
                               record={"arm": arm})
        if rec["generate"]["exit_status"] != 0:
            raise RuntimeError(f"{arm}, {sid}: vens exited {rec['generate']['exit_status']}, see {folder}/vens.log")
        out[sid] = folder
    return out


FACTORS = ("SL", "M", "O", "S", "ED", "EE", "A", "ID", "LC", "LI", "LAV", "LAC", "FD", "RD", "NC", "PV")


def _go_set(q, item, scen):
    """The factors of a group or a factor quantity whose level Go sets in the item's scenarios, with the source."""
    factors = contract.GROUPS.get(q, (q,) if q in FACTORS else ())
    found = []
    for sid in (item if isinstance(item, tuple) else (item,)):
        sc = scen[sid]
        for f in factors:
            src = contract.source(f, sc["dep"], sc["floors"], described=sc["described"])
            if src != "answer" and f"{f} ({src})" not in found:
                found.append(f"{f} ({src})")
    return f"; Go sets {', '.join(found)}" if found else ""


def report(scen, reach, differs, checks=CHECKS):
    """The lines printed and the problems."""
    lines = ["the prompts each contrast differs in (batch 1, the mock):"]
    for (a, b), (qs, system) in reach.items():
        lines.append(f"  {a} / {b}: after, system prompt differs {system}, questions "
                     f"{[q for q in contract.QUESTIONS if q in qs]}; before, its one call's prompt differs "
                     f"{differs[(a, b)]}")
    rows, problems = check(scen, reach, differs, checks)
    lines.append("each check, its kind in each arm it reads, what its scenarios can give, and in the after the "
                 "levels of its quantity that Go sets:")
    for c, arm, kind, item, res in rows:
        word = ("asked" if res[0] else "set by Go") if c.test == "any" else WORDS[res]
        lines.append(f"  {c.family}: {c.label}, {arm}, {kind}: {_name(item)}: {word}"
                     + (_go_set(c.quantity, item, scen) if arm == "after" else ""))
    lines.append("the diagnostics that read no contrast:")
    for d in NAMED:
        lines.append(f"  {d.name}: {d.reads}; {len(d.scenarios) or len(scen)} scenario(s), their levels' sources "
                     f"below")
    lines.append("each scenario's levels in the after by source:")
    for sid, sc in scen.items():
        by = {}
        for f in FACTORS:
            by.setdefault(contract.source(f, sc["dep"], sc["floors"], described=sc["described"]), []).append(f)
        lines.append(f"  {sid}: " + "; ".join(f"{k} {' '.join(v)}" for k, v in sorted(by.items())))
    for unfloored in (False, True):
        changes = corpus_wide(scen, reach, checks, unfloored)
        lines.append(f"after, pair outcomes any of the 45 corpus-wide combinations of detection, traceability and "
                     f"data_subjects changes, {'every axis unfloored' if unfloored else 'the vectors as written'}, "
                     f"on the Python rules: {len(changes)}" + (f" {changes[:5]}" if changes else ""))
    for sid, by in showcase_by_detection(scen).items():
        lines.append(f"after, {sid}'s attainable severities by detection: {by}")
    lines.append(f"problems: {len(problems)}")
    lines += [f"  {p}" for p in problems]
    return lines, problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--after", required=True, help="vens built from 310-step3")
    ap.add_argument("--before", required=True, help="vens built from main")
    ap.add_argument("--scenarios", default="scenarios")
    ap.add_argument("--work", required=True, help="an empty folder for the mock runs")
    a = ap.parse_args(argv)
    scen = load(a.scenarios)
    ids = needed()
    reach, differs = contrasts(run_mock(a.after, a.scenarios, ids, a.work, "after"),
                               run_mock(a.before, a.scenarios, ids, a.work, "before"))
    lines, problems = report(scen, reach, differs)
    print("\n".join(lines))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
