"""answers.json, which the after writes once per run under --debug-dir, failed runs included.

Per CVE, each factor's answer as the reply wrote it, its reading, its level and the level's source; a failed run also
lists, marked `unrated`, the CVEs of its failing batch already answered, with their answers and readings only. From
310-step3b 19b333a, each entry also holds its reachability answer and reading, `reachability`, outside the 16
factors: a CVE of a failing batch answered reachability alone has no factor list, which Go writes null. From 0421679
(its request as at 5f797bf) a flagged CVE not reachable keeps its adjustment, confidentiality alone: its Loss of
confidentiality record carries the adjusted answer at source reachability, and Privacy violation may take source
adjustment.

From 310-c1c2 (C1 + C2) no entry holds reachability. Loss of confidentiality, integrity and availability carry source
cvss and the worst value, H, L or N, the CVE's usable CVSS v3 vectors give the axis, `cvss`, absent without a usable
vector, and no answer or reading; a Privacy violation they floor carries source floor and `cvss` N. With the relay
removed (plan Z0d, N) no entry holds `declared` and the VEX publishes no status: check() fails any VEX `analysis` and
validate() any `declared` block, whatever the contract, none relaying. marks() lists the contracts a document's
entries show; validate() checks them against the pinned contract, which they never choose, and c1c2() checks C1 +
C2's on every entry.
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
    source, adjusted, cvss}, absent keys as None, its reachability {answer, reading}, None but from 19b333a to
    5f797bf, and its declared block, None but where a commit relayed reachability (2de5d34), which fails the gate."""
    keys = ("answer", "reading", "level", "source", "adjusted", "cvss")
    reach = entry.get("reachability")
    return {"unrated": bool(entry.get("unrated")), "adjustment": entry.get("adjustment"),
            "counters": entry.get("counters") or [],
            "factors": {f["factor"]: {k: f.get(k) for k in keys} for f in entry["factors"]},
            "reachability": None if reach is None else {k: reach.get(k) for k in ("answer", "reading")},
            "declared": entry.get("declared")}


def check(doc, vex_ratings):
    """answers.json against the VEX: each rated CVE's 16 levels, in the vector's order, equal its vector's, and no VEX
    status, none of the contracts relaying one; every CVE the VEX rates has a rated entry, and no rated entry is
    missing from the VEX. The problems found."""
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
        if r.get("analysis") is not None:
            problems.append(f"{vid}: the VEX publishes a status, {r['analysis'].get('state')}")
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


def marks(doc):
    """The contracts a document's entries show: 5f797bf's (19b333a on) where one holds reachability, C1 + C2's where
    one has a level from source cvss, b7c0435's where a rated entry has a technical impact from another source and no
    reachability. A document of unrated entries alone shows none."""
    vulns, out = doc["vulnerabilities"], set()
    for e in vulns:
        sources = {f.get("source") for f in e["factors"] if f.get("factor") in contract.AXIS}
        if e.get("reachability") is not None:
            out.add(contract.REACH_RULES)
        if contract.CVSS_SOURCE in sources:
            out.add(contract.C1C2)
        if not e.get("unrated") and e.get("reachability") is None and sources - {contract.CVSS_SOURCE}:
            out.add(contract.B7C0435)
    return out


def rules_of(doc):
    """The one contract a document shows, b7c0435's when it shows none; None when it shows two."""
    found = marks(doc)
    return None if len(found) > 1 else found.pop() if found else contract.B7C0435


def _c2_levels(f, value):
    """The levels C2's table can give factor f from the worst value written, both columns for confidentiality, 9
    without one; none for a value off H, L and N."""
    if value is None:
        return {contract.VECTORLESS_LEVEL}
    if value not in contract.WORSE:
        return set()
    return set(contract.C2_LC[value]) if f == "LC" else {(contract.C2_LI if f == "LI" else contract.C2_LAV)[value]}


def _impact_problems(vid, factors, counters):
    """Loss of confidentiality, integrity and availability under C2: source cvss, no answer or reading, their level
    the table's for their worst value, 9 for all three without one, the CVE then counted cvss_v3_missing; Privacy
    violation from source floor exactly where confidentiality's worst value is N, at 3 with it."""
    x = {f: factors.get(f) or {} for f in contract.AXIS}
    problems = []
    for f, rec in x.items():
        if rec.get("source") != contract.CVSS_SOURCE or rec.get("answer") is not None or rec.get("reading"):
            problems.append(f"{vid}: {f} not from cvss alone")
            continue
        value = rec.get("cvss")
        if rec.get("level") not in _c2_levels(f, value):
            problems.append(f"{vid}: {f} at {rec.get('level')} from cvss {value!r}")
    vectorless = {x[f].get("cvss") is None for f in x}
    if len(vectorless) > 1:
        problems.append(f"{vid}: a usable vector for some technical impacts and not for others")
    elif vectorless.pop() != (contract.VECTOR_MISSING in counters):
        problems.append(f"{vid}: {contract.VECTOR_MISSING} counted against what the three impacts say")
    pv, floored = factors.get("PV") or {}, x["LC"].get("cvss") == "N"
    if (pv.get("source") == contract.FLOOR_SOURCE) != floored or (
            floored and (pv.get("level"), pv.get("cvss"), pv.get("answer")) != (contract.FLOOR["PV"], "N", None)) or (
            not floored and pv.get("cvss") is not None):
        problems.append(f"{vid}: Privacy violation's floor off confidentiality's worst value")
    return problems


def validate(doc, pinned):
    """The problems of a document against its arm's pinned contract (contract.CONTRACTS of its vens commit; None when
    the commit pins none): its entries showing two contracts, or one other than the pinned; under C1 + C2 pinned,
    c1c2()'s on every entry whatever it shows. Without a pinned contract, c1c2() where the document shows C1 + C2."""
    found = marks(doc)
    relayed = [f"{e['vulnId']}: a declared block, no contract relaying reachability" for e in doc["vulnerabilities"]
               if "declared" in e]
    if len(found) > 1:
        return relayed + [f"answers.json mixes contracts: {', '.join(sorted(found))}"]
    if pinned is not None and found - {pinned}:
        return relayed + [f"answers.json follows {found.pop()}, not the pinned {pinned}"]
    return relayed + (c1c2(doc) if contract.C1C2 in found | {pinned} else [])


def c1c2(doc):
    """The problems of a document's entries against C1 + C2: no reachability record, the three technical impacts and
    Privacy violation's floor as _impact_problems says on every rated entry, an unrated entry answering no technical
    impact. A declared block is validate()'s, under any contract."""
    rated, unrated = entries(doc)
    problems = [f"{vid}: a reachability record under C1 + C2" for vid, e in sorted({**rated, **unrated}.items())
                if e.get("reachability") is not None]
    for vid, e in sorted(rated.items()):
        factors = {f["factor"]: f for f in e["factors"]}
        problems += _impact_problems(vid, factors, e.get("counters") or [])
    for vid, e in sorted(unrated.items()):
        if any(f["factor"] in contract.AXIS for f in e["factors"]):
            problems.append(f"{vid}: an unrated entry answering a technical impact")
    return problems
