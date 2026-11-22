"""answers.json, which the after writes once per run under --debug-dir, failed runs included.

Per CVE, each factor's answer as the reply wrote it, its reading, its level and the level's source; a failed run also
lists, marked `unrated`, the CVEs of its failing batch already answered, with their answers and readings only. From
310-step3b 19b333a, each entry also holds its reachability answer and reading, `reachability`, outside the 16
factors: a CVE of a failing batch answered reachability alone has no factor list, which Go writes null. From 0421679
a flagged CVE not reachable keeps its adjustment, confidentiality alone: its Loss of confidentiality record carries the
adjusted answer at source reachability, and Privacy violation may take source adjustment.
"""
import collections

from chain import contract
from chain.cdx import FACTORS
from chain.errors import Refused, load_json


def _entry(path, e):
    """One entry, an unrated one holding reachability alone given an empty factor list; Refused when it is not an
    entry's shape."""
    reach = e.get("reachability") if isinstance(e, dict) else None
    if reach is not None and (not isinstance(reach, dict) or reach.get("factor") != contract.R):
        raise Refused(f"{path}: not answers.json, a reachability record that is not R's")
    if reach is not None and e.get("unrated") and e.get("factors") is None:
        e = {**e, "factors": []}
    factors = e.get("factors") if isinstance(e, dict) else None
    if not isinstance(factors, list) or not isinstance(e.get("vulnId"), str) or any(
            not isinstance(f, dict) or "factor" not in f for f in factors):
        raise Refused(f"{path}: not answers.json, an entry without vulnId or factors")
    return e


def load(path):
    """The document; Refused when it is cut short or not answers.json's shape."""
    doc = load_json(path)
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise Refused(f"{path}: not answers.json, no vulnerabilities list")
    for key in ("counters", "defects"):
        if not isinstance(doc.get(key), dict):
            raise Refused(f"{path}: not answers.json, no {key} object")
    return {**doc, "vulnerabilities": [_entry(path, e) for e in doc["vulnerabilities"]]}


def duplicates(doc):
    """The problems of a CVE listed more than once, rated or unrated: its entries cannot be told apart."""
    counts = collections.Counter(e["vulnId"] for e in doc["vulnerabilities"])
    return [f"{vid}: listed {n} times in answers.json" for vid, n in sorted(counts.items()) if n > 1]


def entries(doc):
    """{vulnId: entry} split into the rated and the unrated; a CVE listed twice is one of duplicates()'s."""
    rated = {e["vulnId"]: e for e in doc["vulnerabilities"] if not e.get("unrated")}
    unrated = {e["vulnId"]: e for e in doc["vulnerabilities"] if e.get("unrated")}
    return rated, unrated


def per_cve(entry):
    """One entry: whether it is unrated, how its adjustment read, its counters, per factor {answer, reading, level,
    source, adjusted}, absent keys as None, and its reachability {answer, reading}, None before 19b333a."""
    keys = ("answer", "reading", "level", "source", "adjusted")
    reach = entry.get("reachability")
    return {"unrated": bool(entry.get("unrated")), "adjustment": entry.get("adjustment"),
            "counters": entry.get("counters") or [],
            "factors": {f["factor"]: {k: f.get(k) for k in keys} for f in entry["factors"]},
            "reachability": None if reach is None else {k: reach.get(k) for k in ("answer", "reading")}}


def check(doc, vex_ratings):
    """answers.json against the VEX: each rated CVE's 16 levels, in the vector's order, equal its vector's; every
    CVE the VEX rates has a rated entry, and no rated entry is missing from the VEX. The problems found."""
    rated, _ = entries(doc)
    problems = []
    for vid, r in sorted(vex_ratings.items()):
        e = rated.get(vid)
        if e is None:
            problems.append(f"{vid}: rated in the VEX, no rated entry in answers.json")
            continue
        names = tuple(f.get("factor") for f in e["factors"])
        got = [f.get("level") for f in e["factors"]]
        if names != FACTORS or got != [r["levels"][f] for f in FACTORS]:
            problems.append(f"{vid}: answers.json's levels differ from the vector's")
    problems += [f"{vid}: a rated entry the VEX does not rate" for vid in sorted(set(rated) - set(vex_ratings))]
    return problems


def unrated_shape(doc):
    """The problems of the unrated entries: each lists only questions answered, reachability's included, with no
    level and no source."""
    _, unrated = entries(doc)
    problems = []
    for vid, e in sorted(unrated.items()):
        answered = e["factors"] + ([e["reachability"]] if e.get("reachability") is not None else [])
        if not answered:
            problems.append(f"{vid}: an unrated entry with no answer")
        if any("level" in f or "source" in f for f in answered):
            problems.append(f"{vid}: an unrated entry with a level or a source")
    return problems


def _lowest(f):
    """The levels reachability can give factor f, Loss of accountability's by its traceability column."""
    return set(contract.LAC_ACTOR["identified"].values()) if f == "LAC" else {contract.UNREACHED[f]}


def _unreached_problems(vid, factors):
    """A rated entry answered not_reachable: none of the six questions reachability decides answered, each at its
    lowest level from reachability, an impact whose axis the vector floors from floor."""
    asked = [f for f in contract.REACHED_ONLY if (factors.get(f) or {}).get("answer") is not None]
    problems = [f"{vid}: not reachable, yet {', '.join(asked)} answered"] if asked else []
    for f in contract.REACHED_ONLY:
        x = factors.get(f) or {}
        sources = (contract.REACH_SOURCE, "floor") if f in contract.AXIS else (contract.REACH_SOURCE,)
        if x.get("source") not in sources or x.get("level") not in _lowest(f):
            problems.append(f"{vid}: not reachable, yet {f} at {x.get('level')} from {x.get('source')}")
    return problems


def reachability(doc):
    """The problems of the rated entries against the reachability rule (310-step3b 19b333a): in a run whose entries
    hold reachability, every rated entry holds it; one answered not_reachable as _unreached_problems says; and no
    level takes its source from reachability unless its CVE was answered not_reachable. Before 19b333a no entry holds
    reachability and no level comes from it: none of these arises."""
    rated, _ = entries(doc)
    held = {vid for vid, e in rated.items() if e.get("reachability") is not None}
    problems = [f"{vid}: a rated entry without reachability, other entries holding it"
                for vid in sorted(set(rated) - held)] if held else []
    for vid, e in sorted(rated.items()):
        factors = {f["factor"]: f for f in e["factors"]}
        answer = (e.get("reachability") or {}).get("answer")
        if answer is not None and not contract.reachable(answer):
            problems += _unreached_problems(vid, factors)
            continue
        by_reach = [f for f in FACTORS if (factors.get(f) or {}).get("source") == contract.REACH_SOURCE]
        if by_reach:
            problems.append(f"{vid}: {', '.join(by_reach)} from reachability, yet its answer is {answer!r}")
    return problems
