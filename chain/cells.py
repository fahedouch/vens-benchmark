"""The runs the analysis reads, from the reader's records (chain/read.py, one per attempt).

A cell is one corpus, arm, provider, model, unit and batch size, the unit a context of the demo scan (baseline.yml's
downloads) or a scenario (a scenario campaign). A replicate's run is its first complete attempt, in attempt order, that is not a stray
run of an abandoned dispatch, as 0B took a replicate's run. Its scores are read only where the reader found them
usable; a replicate whose run is complete but not usable has no scores, and says why. Every attempt, failed, stray or
not read, counts in its cell's attempts, failures, calls and cost; one whose arm or replicate is unknown is never a run.
"""
import collections

from chain import attempt as attemptmod

DEMO, SCENARIOS = "demo scan", "scenarios"
ARMS = ("before", "after")


def corpus(rec):
    return SCENARIOS if rec["what"].get("runner") == "scenarios" else DEMO


def unit(rec):
    w = rec["what"]
    return w.get("scenario") if corpus(rec) == SCENARIOS else w.get("context")


def key(rec, arm_of=None):
    """(corpus, arm, provider, model, unit, batch size); arm_of(rec) replaces the record's arm, to group by something
    else."""
    w = rec["what"]
    return (corpus(rec), (arm_of(rec) if arm_of else w.get("arm")), w.get("provider"), w.get("model"), unit(rec),
            w.get("batch_size"))


def model_of(cell_key):
    """provider/model, with its batch size where it is not 1."""
    batch = cell_key[5]
    return f"{cell_key[2]}/{cell_key[3]}" + ("" if batch in (1, None) else f" batch {batch}")


def source(rec):
    """The attempt, named as its archive names it."""
    w = rec["what"]
    if corpus(rec) == SCENARIOS:
        return f"{w.get('campaign')} r{w.get('replicate')} {w.get('arm')}-a{w.get('run_attempt')}"
    return f"run {w.get('run_id')} a{w.get('run_attempt')} r{w.get('replicate')}"


def _attempt_no(rec):
    n = rec["what"].get("run_attempt")
    return n if isinstance(n, int) else 0


def group(records, arm_of=None):
    """{cell: {"attempts": [...], "runs": {replicate: record}, "unusable": {replicate: (record, why)},
    "problems": [...]}}."""
    cells = collections.defaultdict(lambda: {"attempts": [], "runs": {}, "unusable": {}, "problems": []})
    for rec in records:
        cells[key(rec, arm_of)]["attempts"].append(rec)
    for c in cells.values():
        by_rep = collections.defaultdict(list)
        for rec in c["attempts"]:
            rep = rec["what"].get("replicate")
            if rec["outcome"] == attemptmod.COMPLETE and rec["excluded"] is None and isinstance(rep, int):
                by_rep[rep].append(rec)
        for rep, recs in sorted(by_rep.items()):
            recs.sort(key=_attempt_no)
            first = recs[0]
            commits = {r["what"].get("vens_commit") for r in recs} - {None}
            if len(commits) > 1:
                c["problems"].append(f"replicate {rep}: complete attempts at {len(commits)} vens commits")
            if len(recs) > 1:
                c["problems"].append(f"replicate {rep}: {len(recs)} complete attempts, the first one read "
                                     f"({source(first)})")
            if first["scores_usable"]:
                c["runs"][rep] = first
            else:
                c["unusable"][rep] = (first, "; ".join(first["incomplete"] + first["vex_problems"]
                                                       + first["problems"]) or "scores not usable")
    return dict(cells)


def complete_runs(c):
    """The replicates' runs that published a VEX, usable or not: what the targets read."""
    out = dict(c["runs"])
    out.update({rep: rec for rep, (rec, _) in c["unusable"].items() if rec["ratings"] is not None})
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


def label(cell_key):
    return f"{cell_key[1]} · {model_of(cell_key)} · {cell_key[4]}"
