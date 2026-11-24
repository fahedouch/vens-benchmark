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

Under C1 + C2' (rules c1c2p) the rules are C2''s, Loss of availability in the column its config's
availability_requirement gives. Under either, each CVE also counts cvss_v3_missing and availability_requirement_missing
as Go does (contract.c1c2_counters), the latter never under C1 + C2.

A run of the marker commit (contract.MARKER_COMMIT; the mirror review's M3 and M3+), keyed on the run's own commit,
carries on each CVE exactly one vens:impact-provenance property, missing-cvss-v3-fallback where its report gives no
usable v3 vector and where its entry counts cvss_v3_missing, cvss-v3 otherwise; a run of any other commit carries none.

Under c1c2b (contract.POLICY_COMMIT) the levels are C1 + C2''s and the rating is recomputed on the run's own published
vens:impact-basis: the business impact where it says business, the technical impact where it says technical. A run of
that commit carries on each CVE exactly one such property, its value the one the config gives (business iff it
declares data_subjects, contract.impact_basis): one missing, two, another value or one off the config refuses the run.
A run of any other commit carries none, and its rating is recomputed on max(T, B).
"""
import os
from fractions import Fraction

import yaml

from chain import cdx, contract, verdicts
from chain import cells as cellmod

PASS, FAIL, INCONCLUSIVE = "pass", "fail", "inconclusive"


def rating(levels, basis=None):
    """(vector, severity, score) the 16 levels give: OWASP's likelihood and impact, the matrix on the calculator's
    bands, the score their product, as vens rates; the impact max(T, B), or, basis business or technical (c1c2b), that
    impact alone."""
    total = lambda names: sum(levels[f] for f in names)
    likelihood = Fraction(total(cdx.FACTORS[:8]), 8)
    technical, business = Fraction(total(cdx.FACTORS[8:12]), 4), Fraction(total(cdx.FACTORS[12:]), 4)
    impact = {None: max(technical, business), contract.TECHNICAL: technical, contract.BUSINESS: business}[basis]
    vector = "/".join(f"{f}:{levels[f]}" for f in cdx.FACTORS)
    return vector, verdicts.SEVERITY[verdicts.band(likelihood)][verdicts.band(impact)], float(likelihood * impact)


def published_basis(published):
    """The one vens:impact-basis value a VEX rating carries, technical or business; None for none, two or another."""
    values = published.get("basis") or []
    return values[0] if len(values) == 1 and values[0] in (contract.TECHNICAL, contract.BUSINESS) else None


def _basis_problems(vid, published, dep, commit):
    """The vens:impact-basis values published for a CVE against the run's commit and its config."""
    values = published.get("basis") or []
    if not contract.basis_commit(commit):
        return [f"{vid}: {contract.BASIS} published, vens {str(commit)[:12]} writes no basis"] if values else []
    if len(values) != 1:
        return [f"{vid}: {len(values)} {contract.BASIS} properties, not one"]
    value, want = values[0], contract.impact_basis(dep)
    if value not in (contract.TECHNICAL, contract.BUSINESS):
        return [f"{vid}: {contract.BASIS} {value!r} is not {contract.TECHNICAL} or {contract.BUSINESS}"]
    return [f"{vid}: {contract.BASIS} {value!r}, its config gives {want!r}"] if value != want else []


def _counter_problems(vid, entry, dep, imp, rules):
    """The C2 counters an entry holds against what Go counts for its CVE."""
    want = contract.c1c2_counters(dep, imp, rules)
    got = entry.get("counters") or []
    return [f"{vid}: {name} counted {got.count(name)} times, not {want.count(name)}"
            for name in (contract.VECTOR_MISSING, contract.AVAILABILITY_MISSING) if got.count(name) != want.count(name)]


def _marker_problems(vid, entry, published, imp, commit):
    """The vens:impact-provenance values published for a CVE against the run's commit, its report and its entry."""
    values = published.get("provenance") or []
    if not contract.marker_commit(commit):
        return [f"{vid}: {contract.PROVENANCE} published, vens {str(commit)[:12]} writes no marker"] if values else []
    if len(values) != 1:
        return [f"{vid}: {len(values)} {contract.PROVENANCE} properties, not one"]
    value, want = values[0], contract.FALLBACK if imp.usable == 0 else contract.FROM_CVSS_V3
    counted = (entry.get("counters") or []).count(contract.VECTOR_MISSING)
    out = [f"{vid}: {contract.PROVENANCE} {value!r}, its report gives {want!r}"] if value != want else []
    if (value == contract.FALLBACK) != bool(counted):
        out.append(f"{vid}: {contract.PROVENANCE} {value!r} against {contract.VECTOR_MISSING} counted {counted} times")
    return out


def cve_problems(vid, entry, published, dep, findings, rules=contract.C1C2, commit=None):
    """What differs, for one CVE of a run, from the pinned rules (C1 + C2, C1 + C2' with rules C1C2P, or c1c2b) on its
    own answers: entry, its answers.json entry as answers.per_cve reads it; published, its VEX rating; findings, the
    report's rows of the CVE; commit, the run's vens commit, which decides the marker and the basis. Under c1c2b the
    rating is recomputed on the published basis, and a rating without one valid basis is not recomputed: its basis
    problem refuses the run."""
    if entry is None or entry["unrated"]:
        return [f"{vid}: no rated answers.json entry"]
    problems = [f"{vid}: the VEX publishes a status, {published['analysis'].get('state')}"] \
        if published.get("analysis") is not None else []
    problems += [f"{vid}: answers.json holds a declared block"] if entry.get("declared") is not None else []
    fs = entry["factors"]
    answers = {f: x["answer"] for f, x in fs.items() if x.get("answer") is not None}
    adjusted = {f: (fs.get(f) or {}).get("adjusted") for f in ("O", "PV")}
    imp = contract.cve_impact(findings)
    got = contract.c1c2_levels(dep, imp, contract.described(findings), answers, adjusted, rules)
    levels = {f: lv for f, (lv, _) in got.items()}
    off = [f"{f} {published['levels'][f]} not {levels[f]}" for f in cdx.FACTORS if published["levels"][f] != levels[f]]
    basis = published_basis(published) if rules == contract.C1C2B else None
    if rules != contract.C1C2B or basis is not None:
        vector, severity, score = rating(levels, basis)
        off += [f"{name} {published.get(name)!r} not {want!r}" for name, want in (
            ("vector", vector), ("severity", severity), ("score", score)) if published.get(name) != want]
    return problems + ([f"{vid}: " + ", ".join(off)] if off else []) + _counter_problems(vid, entry, dep, imp, rules) \
        + _marker_problems(vid, entry, published, imp, commit) + _basis_problems(vid, published, dep, commit)


def run_problems(rec, config, cves, rules=contract.C1C2):
    """cve_problems() over every CVE the run's VEX rates; cves, the report's {vulnId: [finding]}."""
    per = (rec.get("answers") or {}).get("per_cve") or {}
    dep, out = contract.deployment(config), []
    for vid, published in sorted((rec["ratings"] or {}).items()):
        if vid not in cves:
            out.append(f"{vid}: rated, not in the report")
            continue
        out += cve_problems(vid, per.get(vid), published, dep, cves[vid], rules, rec["what"].get("vens_commit"))
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


def read(cells, scen, demo_root, rules=contract.C1C2):
    """{cell: {verdict, replicates, runs, cves, problems, statuses, unread, missing}} for every after cell: each
    complete run recomputed under the pinned rules, each one the reader found unusable for its answers.json failing,
    each expected replicate without a complete run missing; statuses, every CVE holding a status or a declared block,
    unusable runs' included."""
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
            got["problems"] += [f"r{rep} {p}" for p in run_problems(rec, *inputs, rules)]
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
