"""Synthetic records, shaped as chain/read.py gives them, for the analysis's tests."""
from chain import cdx, demo
from tests import support as s


def vector(**levels):
    """A 16-level vector, every level 5 but those given."""
    lv = {f: 5 for f in cdx.FACTORS}
    lv.update(levels)
    return "/".join(f"{f}:{lv[f]}" for f in cdx.FACTORS)


def group_vector(ta, vu, t, b):
    """vens main's vector: each group's four levels its aggregate."""
    return "/".join(f"{f}:{v}" for f, v in zip(cdx.FACTORS, [ta] * 4 + [vu] * 4 + [t] * 4 + [b] * 4))


def rating(vec, arm="after", score=None, severity=None):
    """A rating as chain/cdx.py reads it, its score and severity the arm's own rule unless given."""
    lv = cdx.levels(vec)
    r = {"vector": vec, "levels": lv, **cdx.subscores(lv)}
    own_score, own_severity = demo.own_rule(r, arm)
    r["score"] = float(own_score) if score is None else score
    r["severity"] = own_severity if severity is None else severity
    return r


def factors(vec, **given):
    """answers.json's factors for a vector: each level answered (answer 'a<level>', source answer) unless given as
    (answer, source); an answer of None is a question not asked."""
    out = {}
    for f, level in cdx.levels(vec).items():
        answer, source = given.get(f, (f"a{level}", "answer"))
        out[f] = {"answer": answer, "reading": None if answer is None else "answered", "level": level,
                  "source": source, "adjusted": None}
    return out


def record(arm, unit, replicate, ratings, *, scenario=False, provider="openai", model=s.MODEL, attempt=1,
           outcome="complete", usable=True, answers=None, batch=1, commit=None, excluded=None, summary=None,
           recovery=None, cost=None, failure=None, steps=None, run_id=1000, campaign="c1"):
    """One attempt. ratings: {CVE: rating}; answers: {CVE: factors} for the after."""
    what = {"runner": "scenarios" if scenario else "baseline.yml", "arm": arm, "provider": provider,
            "model": model, "replicate": replicate, "run_attempt": attempt, "run_id": None if scenario else run_id,
            "campaign": campaign if scenario else None, "batch_size": batch,
            "vens_commit": commit or (s.AFTER_SHA if arm == "after" else s.BEFORE_SHA),
            "scenario": unit if scenario else None, "context": None if scenario else unit,
            "corpus": f"scenarios/{unit}/report.json" if scenario else "runs/2026-09-23/scan/scan.json"}
    per_cve = None if answers is None else {
        vid: {"unrated": False, "adjustment": "not_asked", "counters": [], "factors": fs}
        for vid, fs in answers.items()}
    return {"folder": None, "what": what, "outcome": outcome, "excluded": excluded, "scores_usable": usable,
            "ratings": ratings if outcome == "complete" else None,
            "answers": None if per_cve is None else {"per_cve": per_cve, "counters": {}, "defects": {}},
            "incomplete": [], "vex_problems": [], "problems": [], "failure": failure, "summary": summary,
            "recovery": recovery or {}, "cost_estimate": cost or {}, "steps": steps, "retry_cap_reached": None}


def scored(scores, severities=None, impacts=None):
    """{CVE: rating} with the scores given straight, for the statistics that read the score alone; severities and
    impacts ((T, B) per CVE) where a figure reads them."""
    out = {}
    for i, x in enumerate(scores):
        t, b = impacts[i] if impacts else (0.0, 0.0)
        out[f"CVE-2099-{i:04d}"] = {"vector": f"v{x}", "levels": {}, "score": float(x), "L": float(x),
                                    "severity": severities[i] if severities else "low", "T": t, "B": b,
                                    "impact": max(t, b)}
    return out
