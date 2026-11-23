"""C1 + C2's implementation gate on every after run read (venslabs/vens#310 plans Z0 and Z0d; the chain review's B4, B8,
BD1 as Z0d keeps them): vens publishes no reachability status.

With the after's contract pinned to C1 + C2, every after cell, a scenario or a demo context of one model, is one
implementation item, binding on every expected replicate whatever read5's eligibility rule prints for the families. A
replicate passes when its complete run holds no VEX `analysis` and no `declared` block in answers.json, and its 16
levels, vector, severity and score are what C1 + C2's rules give its own answers on its frozen inputs, its config and
its scanner report (a demo scan's under --demo). The item fails on any replicate that does not, a run the reader
refused for its answers.json included; it is inconclusive where an expected replicate has no complete run or its inputs
cannot be read. Any CVE of an after run holding a status or a declared block is also counted per cell (BD1, widened to
every after run). failures() lists every fail and inconclusive: any of them stops a go.
"""
import os
from fractions import Fraction

import yaml

from chain import cdx, contract, verdicts
from chain import cells as cellmod

PASS, FAIL, INCONCLUSIVE = "pass", "fail", "inconclusive"


def rating(levels):
    """(vector, severity, score) the 16 levels give: OWASP's likelihood and impact, max(T, B), the matrix on the
    calculator's bands, the score their product, as vens rates."""
    total = lambda names: sum(levels[f] for f in names)
    likelihood = Fraction(total(cdx.FACTORS[:8]), 8)
    impact = max(Fraction(total(cdx.FACTORS[8:12]), 4), Fraction(total(cdx.FACTORS[12:]), 4))
    vector = "/".join(f"{f}:{levels[f]}" for f in cdx.FACTORS)
    return vector, verdicts.SEVERITY[verdicts.band(likelihood)][verdicts.band(impact)], float(likelihood * impact)


def cve_problems(vid, entry, published, dep, findings):
    """What differs, for one CVE of a run, from C1 + C2 on its own answers: entry, its answers.json entry as
    answers.per_cve reads it; published, its VEX rating; findings, the report's rows of the CVE."""
    if entry is None or entry["unrated"]:
        return [f"{vid}: no rated answers.json entry"]
    problems = [f"{vid}: the VEX publishes a status, {published['analysis'].get('state')}"] \
        if published.get("analysis") is not None else []
    problems += [f"{vid}: answers.json holds a declared block"] if entry.get("declared") is not None else []
    fs = entry["factors"]
    answers = {f: x["answer"] for f, x in fs.items() if x.get("answer") is not None}
    adjusted = {f: (fs.get(f) or {}).get("adjusted") for f in ("O", "PV")}
    got = contract.c1c2_levels(dep, contract.cve_impact(findings), contract.described(findings), answers, adjusted)
    levels = {f: lv for f, (lv, _) in got.items()}
    off = [f"{f} {published['levels'][f]} not {levels[f]}" for f in cdx.FACTORS if published["levels"][f] != levels[f]]
    vector, severity, score = rating(levels)
    off += [f"{name} {published.get(name)!r} not {want!r}" for name, want in (
        ("vector", vector), ("severity", severity), ("score", score)) if published.get(name) != want]
    return problems + ([f"{vid}: " + ", ".join(off)] if off else [])


def run_problems(rec, config, cves):
    """cve_problems() over every CVE the run's VEX rates; cves, the report's {vulnId: [finding]}."""
    per = (rec.get("answers") or {}).get("per_cve") or {}
    dep, out = contract.deployment(config), []
    for vid, published in sorted((rec["ratings"] or {}).items()):
        if vid not in cves:
            out.append(f"{vid}: rated, not in the report")
            continue
        out += cve_problems(vid, per.get(vid), published, dep, cves[vid])
    return out


def statuses(rec):
    """The CVEs of a run holding a VEX status or a declared block."""
    per = (rec.get("answers") or {}).get("per_cve") or {}
    return sorted(vid for vid, r in (rec["ratings"] or {}).items()
                  if r.get("analysis") is not None or (per.get(vid) or {}).get("declared") is not None)


def _demo_inputs(rec, demo_root):
    """(the run's config, its report's {vulnId: [finding]}) under the vens-demo tree, None where one is missing."""
    paths = [os.path.join(demo_root, rec["what"][k]) if demo_root and rec["what"].get(k) else None
             for k in ("config", "corpus")]
    if not all(p and os.path.isfile(p) for p in paths):
        return None
    with open(paths[0], encoding="utf-8") as fh:
        return yaml.safe_load(fh), contract.report_cves(paths[1])


def _inputs(k, rec, scen, demo_root):
    """((config, the report's CVEs), None) of a run, or (None, why they cannot be read)."""
    if k.corpus == cellmod.SCENARIOS:
        sc = (scen or {}).get(k.unit)
        if sc is None:
            return None, f"{k.unit} is not in the corpus copy"
        return (sc["config"], {sc["vuln_id"]: sc["findings"]}), None
    got = _demo_inputs(rec, demo_root)
    return (got, None) if got else (None, "the demo scan or its context not found: give --demo")


def expected(c):
    """The replicates a cell owes: every one attempted, run or found unusable."""
    attempted = {rec["what"].get("replicate") for rec in c["attempts"]}
    return sorted({x for x in attempted if isinstance(x, int)} | set(c["runs"]) | set(c["unusable"]))


def read(cells, scen, demo_root):
    """{cell: {verdict, replicates, runs, cves, problems, statuses, unread, missing}} for every after cell: each
    complete run recomputed, each one the reader found unusable for its answers.json failing, each expected replicate
    without a complete run missing; statuses, every CVE holding a status or a declared block, unusable runs'
    included."""
    out = {}
    for k, c in cells.items():
        if k.arm != "after":
            continue
        got = {"replicates": expected(c), "runs": len(c["runs"]), "cves": 0, "problems": [], "statuses": [],
               "unread": None, "missing": []}
        for rep, rec in sorted(c["runs"].items()):
            got["cves"] += len(rec["ratings"] or {})
            got["statuses"] += [f"r{rep} {vid}" for vid in statuses(rec)]
            inputs, why = _inputs(k, rec, scen, demo_root)
            if inputs is None:
                got["unread"] = why
                continue
            got["problems"] += [f"r{rep} {p}" for p in run_problems(rec, *inputs)]
        for rep, (rec, why) in sorted(c["unusable"].items()):
            got["statuses"] += [f"r{rep} {vid}" for vid in statuses(rec)] if rec["ratings"] else []
            found = (rec.get("answers") or {}).get("problems")
            got["problems"] += [f"r{rep} refused by the reader: {'; '.join(found)}"] if found else []
            got["missing"] += [] if found else [f"r{rep} not usable: {why}"]
        got["missing"] += [f"r{rep} without a complete run" for rep in got["replicates"]
                           if rep not in c["runs"] and rep not in c["unusable"]]
        bad = got["problems"] or got["statuses"]
        got["verdict"] = FAIL if bad else INCONCLUSIVE if got["unread"] or got["missing"] or not c["runs"] else PASS
        out[k] = got
    return out


def failures(read_cells):
    """Every after cell that does not pass, with why: any of them stops a go."""
    out = []
    for k, c in sorted((read_cells or {}).items(), key=lambda kc: cellmod.label(kc[0])):
        if c["verdict"] == PASS:
            continue
        why = c["problems"] + [f"{s} holds a VEX status or a declared block" for s in c["statuses"]] + c["missing"]
        why += [f"not recomputed, {c['unread']}"] if c["unread"] else []
        out.append(f"{cellmod.label(k)}: {c['verdict']}: " + "; ".join(why or ["no complete run"]))
    return out
