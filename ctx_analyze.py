"""Half B's analysis: what vens published, read per attempt by the chain's readers, through every statistic
step 5 reads (venslabs/vens#310 step 4).

    python3 ctx_analyze.py [--dispatch-log LOG] [--commit before=SHA --commit after=SHA] [--arm ARM]
                           [--failures FILE] [--freeze-sha256 SHA] [--demo DIR] [--fallback CAMPAIGN]
                           [--usage CSV] [--draw-list FILE] [--jar JAR] [--out FILE] DIR...

DIR is what `python3 -m chain.read` reads: baseline.yml's downloads on the demo scan (a workflow run's folder or a
campaign's, failed jobs included), or a scenario campaign (ctx_runner.py). Every attempt is read by chain/read.py,
with the same options; nothing here parses a record again. --demo names a vens-demo tree, where each download's
archived scan is read for its report's CVEs; without it the two targets are unavailable, and say why.
--fallback names a scenario campaign of the after on vens's mock with every answer cannot_tell
(VENS_MOCK_LLM_CANNOT_TELL=cannot_tell), the after's conservative fallback: refused unless its flag names cannot_tell,
its model is mock/mock, its after is the after's commit, its corpus is the scenario campaigns' and every after answer
it holds is cannot_tell. Scenario campaigns read together share one corpus, or are refused. --usage names
the providers' usage exports copied into one CSV with a campaign column (chain/usage.py), the measured cost.
--draw-list names the CVE ids earlier draws used, one per line or a TSV with a cve column: Opportunity's answers on the
CVEs outside it are reported apart. --jar names the OWASP calculator's 1.0.1 JAR, its sha256 checked, for target (i);
the JDK is $VB_JDK, $JAVA_HOME/bin or javac's folder.

The report is Markdown, on stdout or in --out: each figure names the cell and the replicates it read, the records
section names each replicate's attempt, and the measured cost never mixes with the estimates. Exit 0 once written,
1 when a reader refuses an input or an input is wrong, 2 on a usage error.
"""
import argparse
import collections
import hashlib
import os
import sys

from chain import campaign, cdx, demo, diagnostics, families, javacheck, kpi, ledger, legal, read, report, usage
from chain import cells as cellmod
from chain import dispatch, downloads, verdicts
from chain.errors import Refused
from chain.javarun import own_commit

CANNOT_TELL_ENV = "VENS_MOCK_LLM_CANNOT_TELL"
CANNOT_TELL = "cannot_tell"
# The showcases' headings, the CVSS score each text gives and the verdict expected of it.
SHOWCASES = {"showcase_high_to_low": "CVSS 10.0 RCE -> expect LOW",
             "showcase_med_to_high": "CVSS 6.5 leak -> expect HIGH"}


class InputError(Exception):
    pass


def digest(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


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


def campaigns(inputs, lines):
    """campaign_of(record) and {input: [campaigns]}: a record's campaign is its campaign.json's, else its run's in the
    dispatch log, else its input's (cells.Unnamed), numbered in the order of the inputs where two campaigns would
    show one name."""
    logged = {run_id: line["campaign"] for run_id, attempts in (dispatch.index(lines) if lines else {}).items()
              for line in attempts.values()}
    named = {id(rec): rec["what"].get("campaign") or logged.get(rec["what"].get("run_id"))
             for _, records in inputs for rec in records}
    paths = {}
    for path, records in inputs:
        if not all(named[id(r)] for r in records):
            paths.setdefault(os.path.realpath(path), os.path.basename(os.path.normpath(path)))
    shown = collections.Counter(paths.values())
    shown.update({n for n in named.values() if n})
    numbers, unnamed = collections.Counter(), {}
    for real, name in paths.items():
        numbers[name] += 1
        unnamed[real] = cellmod.Unnamed(real, name, numbers[name] if shown[name] > 1 else None)
    of_record, per_input = {}, {}
    for path, records in inputs:
        for rec in records:
            of_record[id(rec)] = named[id(rec)] or unnamed[os.path.realpath(path)]
        per_input[path] = sorted({of_record[id(r)] for r in records}, key=str)
    return (lambda rec: of_record.get(id(rec))), per_input


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
    """{id(record): {CVE: accepted}} for every complete run whose report is known, a run without a VEX failing every
    CVE; None without a JAR."""
    if jar is None:
        return None
    jdk = javacheck.jdk_bin()
    if jdk is None:
        raise InputError("--jar given, but no JDK: set VB_JDK or JAVA_HOME")
    items, recs = {}, {}
    for k, c in cells.items():
        if k.arm not in cellmod.ARMS:
            continue
        for rec in cellmod.complete_runs(c).values():
            ids = reports.ids(rec)
            if ids is not None:
                name = str(len(items))
                items[name], recs[name] = (k.arm, legal.vex_path(rec), ids), rec
    got = legal.accepted(items, jdk, jar)
    return {id(recs[n]): {vid: r["accepted"] for vid, r in got[n].items()} for n in got}


def _unqualified(doc, after_commit, got_corpus, corpus):
    """Why a campaign, by its campaign.json and its corpus copy, is not the after's fallback; empty when it may be."""
    flag = (doc.get("mock_env") or {}).get(CANNOT_TELL_ENV, "")
    why = [] if CANNOT_TELL in [v.strip() for v in flag.split(",")] else [
        f"{CANNOT_TELL_ENV} is {flag!r}: every question is forced to cannot_tell only when the list names "
        f"{CANNOT_TELL}"]
    models = [(m["provider"], m["model"]) for m in doc["models"]]
    why += [] if models == [("mock", "mock")] else [f"its models are {models}, not mock/mock alone"]
    got = doc["arms"]["after"]["vens_sha"]
    why += [f"its after is {got}, not {after_commit}"] if got != after_commit else []
    return why + ([f"its corpus is {got_corpus}, not the scenario campaigns' {corpus}"] if got_corpus != corpus else [])


def _asked(entry):
    """An answers.json entry's answers as per_cve gives them, reachability's with the factors'."""
    return list(entry["factors"].values()) + ([entry["reachability"]] if entry.get("reachability") else [])


def _not_cannot_tell(records):
    """Why a fallback's after runs are not every answer cannot_tell, reachability's included; empty when they are."""
    after = [r for r in records if r["what"].get("arm") == "after" and r["outcome"] == "complete"]
    n = sum(r["answers"] is None for r in after)
    why = [f"{n} complete after run(s) without answers.json"] if n else []
    other = sum(f.get("answer") not in (None, CANNOT_TELL) for r in after for e in (r["answers"] or {}).get(
        "per_cve", {}).values() for f in _asked(e))
    return why + ([f"{other} answer(s) other than {CANNOT_TELL}"] if other else [])


def fallback(path, after_commit, freeze=None, corpus=None):
    """A fallback campaign's records and what names it in the report; refused unless it is the after's own binary on
    vens's mock with every answer cannot_tell, on the scenario campaigns' corpus (corpus, its sha256), read under the
    freeze they were read under."""
    if after_commit is None:
        raise InputError(f"{path}: no after commit to check the fallback against: give --commit after=SHA or a "
                         f"scenario campaign")
    if corpus is None:
        raise InputError(f"{path}: no scenario campaign read, whose corpus the fallback must share")
    doc = campaign._campaign(path)
    why = _unqualified(doc, after_commit, corpus_digest(path), corpus)
    if not why:
        records = read.read_any(path, commits={"after": after_commit, "before": doc["arms"]["before"]["vens_sha"]},
                                freeze=freeze)
        why = _not_cannot_tell(records)
    if why:
        raise InputError(f"{path}: not the after's fallback: {'; '.join(why)}")
    flag = doc["mock_env"][CANNOT_TELL_ENV]
    return records, {"path": path, "campaign": doc["campaign"], "commit": after_commit, "flag": flag}


def after_commit(a, inputs):
    """The after's commit: --commit after=SHA, else the one the scenario campaigns' after ran; None otherwise."""
    given = dict(a.commit).get("after")
    if given:
        return given
    seen = {r["what"].get("vens_commit") for _, recs in inputs for r in recs
            if cellmod.corpus(r) == cellmod.SCENARIOS and r["what"].get("arm") == "after"} - {None}
    if len(seen) > 1:
        raise InputError(f"the scenario campaigns' after ran at {len(seen)} commits; give --commit after=SHA")
    return next(iter(seen), None)


def corpus_digest(path):
    """The sha256 of a scenario campaign's corpus copy: its freeze-scenarios.json, whose files the reader checks the
    copy's scenarios against."""
    return digest(os.path.join(path, campaign.FREEZE))


def scenario_corpus(inputs):
    """(folder, sha256) of the scenario campaigns' corpus copy, the first campaign's; None without a campaign.
    Refused when two campaigns ran on different corpora."""
    found = [(path, corpus_digest(path)) for path, records in inputs
             if any(cellmod.corpus(r) == cellmod.SCENARIOS for r in records)]
    if len({sha for _, sha in found}) > 1:
        raise InputError("the scenario campaigns ran on different corpora, their freezes "
                         + "; ".join(f"{path} {sha}" for path, sha in found) + ": read one corpus's campaigns at once")
    return found[0] if found else None


def scenario_info(inputs):
    """verdicts.load() of the scenario campaigns' one corpus copy, None without a campaign."""
    found = scenario_corpus(inputs)
    return None if found is None else verdicts.load(os.path.join(found[0], campaign.SCENARIOS))


def batches(cells):
    """The batch sizes of the runs read, each replicate's complete run with its scores read or not, None last for a
    run that does not record its own."""
    got = {k.batch for k, c in cells.items() if c["runs"] or c["unusable"]}
    return sorted(got - {None}) + ([None] if None in got else [])


def compute(inputs, reports, jar=None, fallback=None, usage=None, draws=None, lines=None):
    """Every section's figures, from the records of inputs, [(path, records)]; fallback: (records, its name) of the
    after's fallback campaign; usage: the measured usage, {rows, name, sha256}; draws: {ids, name, sha256}."""
    campaign_of, per_input = campaigns(inputs, lines)
    records = [r for _, recs in inputs for r in recs]
    cells = cellmod.group(records, campaign_of=campaign_of)
    java = java_targets(cells, reports, jar)
    out = {"inputs": [(p, len(recs)) for p, recs in inputs], "campaigns": per_input, "cells": cells,
           "conflicts": cellmod.conflicts(cells), "java": java is not None, "usage": usage, "draws": draws,
           "batches": batches(cells),
           "targets": demo.targets(cells, reports.ids, (lambda r: java.get(id(r))) if java is not None else None),
           "spreads": demo.spreads(cells), "cross": demo.cross_model(cells), "impacts": demo.impacts(cells),
           "floors": demo.floors(cells), "ledgers": ledger.ledgers(cells), "scenarios": None,
           "opportunity": demo.opportunity(cells, draws["ids"], reports.ids) if draws is not None else None,
           "kpi": {"stability": kpi.stability(cells), "model": kpi.model_sensitivity(cells),
                   "context": kpi.context_sensitivity(cells), "discrimination": kpi.discrimination(cells),
                   "failures": kpi.failures(cells), "cost": kpi.cost(cells)}}
    scen = scenario_info(inputs)
    if scen is not None:
        rows = families.evaluate(cells, scen)
        fb = diagnostics.fallback_cells(fallback[0]) if fallback is not None else None
        out["scenarios"] = {"rows": rows, "moves": families.family_moves(rows),
                            "fallback": fallback[1] if fallback is not None else None, "headings": SHOWCASES,
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
    ap.add_argument("--fallback", help="a scenario campaign of the after's mock with every answer cannot_tell "
                                       "(VENS_MOCK_LLM_CANNOT_TELL=cannot_tell), at the after's commit")
    ap.add_argument("--usage", help="the providers' usage exports as one CSV, a campaign column naming each row's "
                                    "campaign (chain/usage.py)")
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
    named = lambda path: {"name": os.path.basename(path), "sha256": digest(path)}
    scen = scenario_corpus(inputs)
    data = compute(inputs, reports, jar=a.jar, lines=lines,
                   fallback=fallback(a.fallback, after_commit(a, inputs), a.freeze_sha256,
                                     scen and scen[1]) if a.fallback else None,
                   usage={"rows": usage.load(a.usage), **named(a.usage)} if a.usage else None,
                   draws={"ids": draw_list(a.draw_list), **named(a.draw_list)} if a.draw_list else None)
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
