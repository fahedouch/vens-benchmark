"""The runs the analysis reads, from the reader's records (chain/read.py, one per attempt).

A cell is one corpus, campaign, arm, provider, model, unit, batch size and vens commit, the unit a context of the demo
scan (baseline.yml's downloads) or a scenario (a scenario campaign). Two campaigns are never pooled, nor two commits.
A replicate's run is its first complete attempt, by workflow run then attempt, that is not a stray run of an
abandoned dispatch, as 0B took a replicate's run. Its scores are read only where the reader found them usable; a
replicate whose run is complete but not usable has no scores, and says why. Every attempt, failed, stray or not read,
counts in its cell's attempts, failures, calls and cost; one whose arm or replicate is unknown is never a run.
"""
import collections
import re
from typing import NamedTuple

from chain import attempt as attemptmod

DEMO, SCENARIOS = "demo scan", "scenarios"
ARMS = ("before", "after")


class Cell(NamedTuple):
    corpus: str
    campaign: object
    arm: object
    provider: object
    model: object
    unit: object
    batch: object
    commit: object


def corpus(rec):
    return SCENARIOS if rec["what"].get("runner") == "scenarios" else DEMO


def unit(rec):
    w = rec["what"]
    return w.get("scenario") if corpus(rec) == SCENARIOS else w.get("context")


def commit(rec):
    """The vens commit an attempt ran: its record's, else the ref it was dispatched with when that ref is a full
    commit, which the workflow builds as it is (a failed job's download, made before the attempt record, keeps no
    commit of its own)."""
    w = rec["what"]
    ref = w.get("vens_ref")
    return w.get("vens_commit") or (ref if isinstance(ref, str) and re.fullmatch(r"[0-9a-f]{40}", ref) else None)


def key(rec, arm_of=None, campaign_of=None):
    """The record's cell; arm_of(rec) replaces its arm, campaign_of(rec) names its campaign (the record's own
    otherwise)."""
    w = rec["what"]
    return Cell(corpus(rec), campaign_of(rec) if campaign_of else w.get("campaign"),
                arm_of(rec) if arm_of else w.get("arm"), w.get("provider"), w.get("model"), unit(rec),
                w.get("batch_size"), commit(rec))


def model_of(cell):
    """provider/model, with its batch size where it is not 1."""
    return f"{cell.provider}/{cell.model}" + ("" if cell.batch in (1, None) else f" batch {cell.batch}")


def source(rec):
    """The attempt, named as its archive names it."""
    w = rec["what"]
    if corpus(rec) == SCENARIOS:
        return f"{w.get('campaign')} r{w.get('replicate')} {w.get('arm')}-a{w.get('run_attempt')}"
    return f"run {w.get('run_id')} a{w.get('run_attempt')} r{w.get('replicate')}"


def _order(rec):
    w = rec["what"]
    number = lambda v: v if isinstance(v, int) else 0
    return number(w.get("run_id")), number(w.get("run_attempt"))


def _select(c):
    by_rep = collections.defaultdict(list)
    for rec in c["attempts"]:
        rep = rec["what"].get("replicate")
        if rec["outcome"] == attemptmod.COMPLETE and rec["excluded"] is None and isinstance(rep, int):
            by_rep[rep].append(rec)
    for rep, recs in sorted(by_rep.items()):
        recs = sorted(recs, key=_order)
        first = recs[0]
        if len(recs) > 1:
            c["problems"].append(f"replicate {rep}: {len(recs)} complete attempts, the first one read "
                                 f"({source(first)})")
        if first["scores_usable"]:
            c["runs"][rep] = first
        else:
            c["unusable"][rep] = (first, "; ".join(first["incomplete"] + first["vex_problems"] + first["problems"])
                                  or "scores not usable")


def group(records, arm_of=None, campaign_of=None):
    """{Cell: {"attempts": [...], "runs": {replicate: record}, "unusable": {replicate: (record, why)},
    "problems": [...]}}; a cell whose arm is unknown keeps its attempts and has no run."""
    cells = collections.defaultdict(lambda: {"attempts": [], "runs": {}, "unusable": {}, "problems": []})
    for rec in records:
        cells[key(rec, arm_of, campaign_of)]["attempts"].append(rec)
    for k, c in cells.items():
        if k.arm in ARMS:
            _select(c)
        else:
            c["problems"].append(f"{len(c['attempts'])} attempt(s) whose arm is unknown: never a run")
    return dict(cells)


def conflicts(cells):
    """{(corpus, campaign, arm, provider, model, unit, batch): commits} where one arm of a campaign holds runs at
    more than one vens commit: such a cell is compared with nothing."""
    seen = collections.defaultdict(set)
    for k, c in cells.items():
        if c["runs"] or c["unusable"]:
            seen[k[:7]].add(k.commit)
    return {k: sorted(v, key=str) for k, v in seen.items() if len(v) > 1}


def complete_runs(c):
    """The replicates' complete runs, with their VEX or without one: what the targets read."""
    out = dict(c["runs"])
    out.update({rep: rec for rep, (rec, _) in c["unusable"].items()})
    return dict(sorted(out.items()))


def scores(rec, value="score"):
    """{CVE: value} over a run's ratings that carry a score; value is a rating's field or a function of it."""
    get = value if callable(value) else (lambda r: r[value])
    return {vid: get(r) for vid, r in (rec["ratings"] or {}).items() if r.get("score") is not None}


def common(runs):
    """The CVEs every run rates."""
    sets = [set(scores(r)) for r in runs]
    return sorted(set.intersection(*sets)) if sets else []


def matrix(runs, ids, value="score"):
    return [[scores(r, value)[v] for v in ids] for r in runs]


def replicates(reps):
    """'r1-r10' style."""
    reps = sorted(reps)
    if not reps:
        return "none"
    spans, start = [], reps[0]
    for a, b in zip(reps, reps[1:] + [None]):
        if b != a + 1:
            spans.append(f"r{start}" if start == a else f"r{start}-r{a}")
            start = b
    return ", ".join(spans)


def sources(runs):
    """{replicate: record} named compactly: the replicates of each run and attempt, or of each campaign and
    attempt."""
    groups = {}
    for rep, rec in sorted(runs.items()):
        w = rec["what"]
        head = (f"{w.get('campaign')} {w.get('arm')}-a{w.get('run_attempt')}" if corpus(rec) == SCENARIOS
                else f"run {w.get('run_id')} a{w.get('run_attempt')}")
        groups.setdefault(head, []).append(rep)
    return "; ".join(f"{head} {replicates(reps)}" for head, reps in groups.items())


def label(cell):
    return f"{cell.campaign} · {cell.arm} · {model_of(cell)} · {cell.unit}"
