"""C1 + C2's implementation gate on every after run read (venslabs/vens#310 plan Z0; the chain review's B4, B8, BD1).

With the after's contract pinned to C1 + C2, every CVE of every complete after run is recomputed from its frozen
inputs, its config and its scanner report, and its own answers: the VEX status the config's reachability entries and
the executable witnesses given publish (the hits, the vetoes, the exact detail), the declared block's entries, and the
16 levels, which no reachability input reaches. Any difference is a failure, a not_affected nothing declares among
them. A demo scan's run is read with --demo, its config the context the run names; on the demo scan, any CVE holding a
VEX status or a declared block is a failure too, the three contexts declaring no reachability (BD1). failures() adds
the implementation checks of chain/verdicts.py, each binding on every expected replicate (families.every_replicate),
whatever read5's eligibility rule prints beside, and each required one missing; any of them stops a go.
"""
import os

import yaml

from chain import contract, families, verdicts
from chain import cells as cellmod


def cve_problems(vid, entry, rating, dep, findings, entries, witnesses):
    """What differs, for one CVE of a run, between what vens published and C1 + C2 recomputed: entry, its
    answers.json entry as answers.per_cve reads it; rating, its VEX rating; findings, the report's rows of the CVE;
    entries, the config's reachability entries (contract.declarations); witnesses, those run where the run was."""
    if entry is None or entry["unrated"]:
        return [f"{vid}: no rated answers.json entry"]
    packages, problems = contract.packages(findings), []
    want = contract.status(entries, vid, packages, witnesses)
    if verdicts.status_tuple(rating.get("analysis")) != verdicts.status_tuple(want):
        problems.append(f"{vid}: VEX status {(rating.get('analysis') or {}).get('state') or 'none'}, the config "
                        f"declares {(want or {}).get('state') or 'none'}" + (
                            ", its detail off the entries" if want and rating.get("analysis") else ""))
    hit = contract.declared(entries, vid, packages)
    block = entry.get("declared") or {}
    got = {k: block.get(k) or [] for k in hit}
    if got != hit:
        problems.append(f"{vid}: declared entries {got}, the config's hit {hit}")
    fs = entry["factors"]
    answers = {f: x["answer"] for f, x in fs.items() if x.get("answer") is not None}
    adjusted = {f: (fs.get(f) or {}).get("adjusted") for f in ("O", "PV")}
    levels = contract.c1c2_levels(dep, contract.cve_impact(findings), contract.described(findings), answers, adjusted)
    off = [f for f in contract.FACTORS if rating["levels"][f] != levels[f][0]]
    if off:
        problems.append(f"{vid}: " + ", ".join(f"{f} {rating['levels'][f]} not {levels[f][0]}" for f in off))
    return problems


def run_problems(rec, config, cves, witnesses):
    """cve_problems() over every CVE the run's VEX rates; cves, the report's {vulnId: [finding]}."""
    per = (rec.get("answers") or {}).get("per_cve") or {}
    entries, dep = contract.declarations(config), contract.deployment(config)
    out = []
    for vid, rating in sorted((rec["ratings"] or {}).items()):
        if vid not in cves:
            out.append(f"{vid}: rated, not in the report")
            continue
        out += cve_problems(vid, per.get(vid), rating, dep, cves[vid], entries, witnesses)
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


def read(cells, scen, demo_root, witnesses=()):
    """{cell: {runs, cves, problems, statuses, unread}} for every after cell with complete runs: each run
    recomputed; statuses, on the demo scan, the CVEs holding a status or a declared block, each run's; unread, why its
    runs could not be recomputed (a scenario not in the corpus copy, a demo scan without --demo)."""
    out = {}
    for k, c in cells.items():
        if k.arm != "after" or not c["runs"]:
            continue
        got = {"runs": len(c["runs"]), "cves": 0, "problems": [], "statuses": [], "unread": None}
        here = contract.witnessed(witnesses, k.unit)
        for rep, rec in sorted(c["runs"].items()):
            got["cves"] += len(rec["ratings"] or {})
            if k.corpus == cellmod.SCENARIOS:
                sc = (scen or {}).get(k.unit)
                inputs = None if sc is None else (sc["config"], {sc["vuln_id"]: sc["findings"]})
                why = f"{k.unit} is not in the corpus copy"
            else:
                got["statuses"] += [f"r{rep} {vid}" for vid in statuses(rec)]
                inputs, why = _demo_inputs(rec, demo_root), "the demo scan or its context not found: give --demo"
            if inputs is None:
                got["unread"] = why
                continue
            got["problems"] += [f"r{rep} {p}" for p in run_problems(rec, *inputs, here)]
        out[k] = got
    return out


def required(rows):
    """The implementation rows the pinned C1 + C2 checks owe each model read on the scenarios: (label, item, model)."""
    models = {r["model"] for r in rows if r.get("rules") == contract.C1C2}
    checks = [c for c in verdicts.CHECKS_C1C2 if c.kind("after") == verdicts.IMPLEMENTATION]
    return {(c.label, item, m) for m in models for c in checks for item in c.scenarios}


def implementation_rows(rows):
    """{(label, item, model): plan Z0's every-replicate verdict} of the after's implementation rows."""
    return {(r["check"].label, r["row"]["item"], r["model"]): families.every_replicate(r["row"]) for r in rows
            if r["arm"] == "after" and r["kind"] == verdicts.IMPLEMENTATION}


def name(item):
    return " / ".join(item) if isinstance(item, tuple) else item


def failures(rows, read_cells):
    """Everything that stops a go under C1 + C2: an implementation row failing or inconclusive, one required and
    missing, a run whose recomputation differs or could not be made, a demo CVE holding a status."""
    got = implementation_rows(rows)
    out = [f"{label} · {name(item)} · {model}: {verdict}"
           for (label, item, model), verdict in sorted(got.items(), key=str) if verdict != "pass"]
    out += [f"{label} · {name(item)} · {model}: missing" for label, item, model in sorted(required(rows) - set(got),
                                                                                          key=str)]
    for k, c in sorted((read_cells or {}).items(), key=lambda kc: cellmod.label(kc[0])):
        cell = cellmod.label(k)
        out += [f"{cell}: {p}" for p in c["problems"]]
        out += [f"{cell}: {s} holds a VEX status or a declared block on the demo scan" for s in c["statuses"]]
        out += [f"{cell}: not recomputed, {c['unread']}"] if c["unread"] else []
    return out
