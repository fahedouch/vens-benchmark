"""Half B's analysis: what vens published, read per attempt by the chain's readers, through every statistic
step 5 reads (venslabs/vens#310 step 4).

    python3 ctx_analyze.py [--dispatch-log LOG] [--commit before=SHA --commit after=SHA] [--arm ARM]
                           [--failures FILE] [--freeze-sha256 SHA] [--demo DIR] [--fallback CAMPAIGN]
                           [--usage CSV] [--draw-list FILE] [--jar JAR] [--out FILE] DIR...

DIR is what `python3 -m chain.read` reads: baseline.yml's downloads on the demo scan (a workflow run's folder or a
campaign's, failed jobs included), or a scenario campaign (ctx_runner.py). Every attempt is read by chain/read.py,
with the same options; nothing here parses a record again. --demo names a vens-demo tree, where each download's
archived scan is read for its report's CVEs; without it the targets read the VEX's rated CVEs and say so.
--fallback names a scenario campaign of the after on vens's mock with every answer cannot_tell
(VENS_MOCK_LLM_CANNOT_TELL), the after's conservative fallback. --usage names the providers' usage exports copied into
one CSV (chain/usage.py), the measured cost. --draw-list names the CVE ids earlier draws used, one per line or a TSV
with a cve column: Opportunity's answers on the CVEs outside it are reported apart. --jar names the OWASP
calculator's 1.0.1 JAR, its sha256 checked, for target (i); the JDK is $VB_JDK, $JAVA_HOME/bin or javac's folder.

The report is Markdown, on stdout or in --out: each figure names the cell and the replicates it read, the records
section names each replicate's attempt, and the measured cost never mixes with the estimates. Exit 0 once written,
1 when a reader refuses an input or an input is wrong, 2 on a usage error.
"""
import argparse
import os
import sys

from chain import campaign, cdx, demo, diagnostics, families, javacheck, kpi, ledger, legal, read, report, usage
from chain import cells as cellmod
from chain import dispatch, downloads, verdicts
from chain.errors import Refused
from chain.javarun import own_commit

CANNOT_TELL_ENV = "VENS_MOCK_LLM_CANNOT_TELL"
# The showcases' headings, the CVSS score each text gives and the verdict expected of it.
SHOWCASES = {"showcase_high_to_low": "CVSS 10.0 RCE -> expect LOW",
             "showcase_med_to_high": "CVSS 6.5 leak -> expect HIGH"}


class InputError(Exception):
    pass


def draw_list(path):
    """The CVE ids of a list: one per line, or a TSV whose header has a cve column."""
    with open(path, encoding="utf-8") as fh:
        lines = [ln.rstrip("\n") for ln in fh if ln.strip()]
    if lines and "\t" in lines[0]:
        header = lines[0].split("\t")
        if "cve" not in header:
            raise InputError(f"{path}: a TSV without a cve column")
        col = header.index("cve")
        return {ln.split("\t")[col] for ln in lines[1:]}
    return {ln.strip() for ln in lines}


class Reports:
    """Each record's scanner report, its CVE ids read once per file: a scenario's in its campaign's corpus copy, a
    download's archived scan in the vens-demo tree given."""

    def __init__(self, demo_root):
        self.demo_root, self.roots, self.cache = demo_root, {}, {}

    def note(self, path, records):
        for rec in records:
            if cellmod.corpus(rec) == cellmod.SCENARIOS:
                self.roots[id(rec)] = path

    def path(self, rec):
        rel = rec["what"].get("corpus")
        if rel is None:
            return None
        if cellmod.corpus(rec) == cellmod.SCENARIOS:
            return os.path.join(self.roots[id(rec)], rel) if id(rec) in self.roots else None
        return os.path.join(self.demo_root, rel) if self.demo_root else None

    def ids(self, rec):
        p = self.path(rec)
        if p is None:
            return None
        if p not in self.cache:
            if not os.path.isfile(p):
                raise InputError(f"{p}: the report of {cellmod.source(rec)} is not there")
            self.cache[p] = cdx.report_ids(p)
        return self.cache[p]


def java_targets(cells, reports, jar):
    """{id(record): {CVE: accepted}} for every run that published a VEX; None without a JAR."""
    if jar is None:
        return None
    jdk = javacheck.jdk_bin()
    if jdk is None:
        raise InputError("--jar given, but no JDK: set VB_JDK or JAVA_HOME")
    items, recs = {}, {}
    for k, c in cells.items():
        for rec in cellmod.complete_runs(c).values():
            ids = reports.ids(rec)
            name = str(len(items))
            items[name] = (k[1], legal.vex_path(rec), ids if ids is not None else set(rec["ratings"]))
            recs[name] = rec
    got = legal.accepted(items, jdk, jar)
    return {id(recs[n]): {vid: r["accepted"] for vid, r in got[n].items()} for n in got}


def fallback_records(path):
    """A fallback campaign's records; refused unless its campaign ran vens's mock with every answer cannot_tell."""
    doc = campaign._campaign(path)
    if CANNOT_TELL_ENV not in (doc.get("mock_env") or {}):
        raise InputError(f"{path}: not a fallback campaign, its mock_env has no {CANNOT_TELL_ENV}")
    return read.read_any(path)


def scenario_info(inputs):
    """verdicts.load() of the first scenario campaign's corpus copy, None without a campaign."""
    for path, records in inputs:
        if any(cellmod.corpus(r) == cellmod.SCENARIOS for r in records):
            return verdicts.load(os.path.join(path, campaign.SCENARIOS))
    return None


def compute(inputs, reports, jar=None, fallback=None, usage_rows=None, listed=None):
    """Every section's figures, from the records of inputs, [(path, records)]."""
    cells = cellmod.group([r for _, recs in inputs for r in recs])
    java = java_targets(cells, reports, jar)
    out = {"inputs": [(p, len(recs)) for p, recs in inputs], "cells": cells, "java": java is not None,
           "targets": demo.targets(cells, reports.ids, (lambda r: java.get(id(r))) if java is not None else None),
           "spreads": demo.spreads(cells), "cross": demo.cross_model(cells), "impacts": demo.impacts(cells),
           "floors": demo.floors(cells), "ledgers": ledger.ledgers(cells), "usage": usage_rows,
           "opportunity": demo.opportunity(cells, listed) if listed is not None else None, "scenarios": None,
           "kpi": {"stability": kpi.stability(cells), "model": kpi.model_sensitivity(cells),
                   "context": kpi.context_sensitivity(cells), "discrimination": kpi.discrimination(cells),
                   "failures": kpi.failures(cells), "cost": kpi.cost(cells)}}
    scen = scenario_info(inputs)
    if scen is not None:
        rows = families.evaluate(cells, scen)
        fb = diagnostics.fallback_cells(fallback) if fallback is not None else None
        out["scenarios"] = {"rows": rows, "moves": families.family_moves(rows), "fallback": fb is not None,
                            "headings": SHOWCASES,
                            "consistency": diagnostics.consistency(cells), "wrong_yaml": diagnostics.wrong_yaml(cells),
                            "null": diagnostics.null_table(cells, scen, fb)}
    return out


def _commit(text):
    arm, sep, sha = text.partition("=")
    if arm not in dispatch.ARMS or not sep or not sha:
        raise argparse.ArgumentTypeError("give ARM=SHA, ARM before or after")
    return arm, sha


def parse(argv):
    ap = argparse.ArgumentParser(prog="python3 ctx_analyze.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--dispatch-log")
    ap.add_argument("--commit", action="append", type=_commit, default=[])
    ap.add_argument("--arm", choices=dispatch.ARMS)
    ap.add_argument("--failures", action="append", default=[])
    ap.add_argument("--freeze-sha256")
    ap.add_argument("--demo", help="a vens-demo tree, for each download's archived scan")
    ap.add_argument("--fallback", help="a scenario campaign of the after's mock with every answer cannot_tell")
    ap.add_argument("--usage", help="the providers' usage exports as one CSV (chain/usage.py)")
    ap.add_argument("--draw-list", help="the CVE ids earlier draws used")
    ap.add_argument("--jar", help="the OWASP calculator's 1.0.1 JAR, for target (i)")
    ap.add_argument("--out")
    ap.add_argument("dirs", nargs="+")
    return ap.parse_args(argv)


def read_input(path, a, lines, failures):
    """One DIR's records: a scenario campaign with the commits and the freeze, downloads with the rest."""
    commits = dict(a.commit) or None
    if os.path.exists(os.path.join(path, campaign.CAMPAIGN)):
        return read.read_any(path, commits=commits, freeze=a.freeze_sha256)
    return read.read_any(path, lines, a.arm, failures, commits)


def run(a):
    """The report's text."""
    lines = dispatch.load(a.dispatch_log) if a.dispatch_log else None
    failures = [f for path in a.failures for f in downloads.load_failures(path)]
    inputs = [(path, read_input(path, a, lines, failures)) for path in a.dirs]
    reports = Reports(a.demo)
    for path, records in inputs:
        reports.note(path, records)
    data = compute(inputs, reports, jar=a.jar, fallback=fallback_records(a.fallback) if a.fallback else None,
                   usage_rows=usage.load(a.usage) if a.usage else None,
                   listed=draw_list(a.draw_list) if a.draw_list else None)
    return report.render(data, reader=own_commit())


def main(argv=None):
    a = parse(argv)
    try:
        text = run(a)
    except (Refused, dispatch.DispatchError, InputError, usage.UsageError, legal.LegalError, javacheck.JarError,
            OSError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
