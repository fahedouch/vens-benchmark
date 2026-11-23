"""The Java run over the after's own VEX, on vens's mock, made at the after's commit before that commit is measured:
the scenarios (schema 2 as committed; a config without the marker gets it in a scratch copy), the demo scan's three
contexts and the two quickstart reports. The reference calculator runs over every vector, its failure paths on
their own inputs, and answers.json's levels are checked against each vector; with --before, the before's VEX too,
each refused vector's other checks not applicable and its score and severity recomputed under main's own rule. Every
vens exit and every verdict is checked against the one it must be; any other makes the run exit 1.

    python3 -m chain.javarun --vens BIN --commit SHA --scenarios DIR --demo DIR --quickstart DIR --jar JAR \
        --out DIR [--before BIN --before-commit SHA] [--jdk DIR]

--demo holds runs/2026-09-23/scan/scan.json and contexts/*.yaml (vens-demo); --quickstart is vens's
examples/quickstart at --commit. --out must not exist. It receives the runs, debug folders included, and archive/,
what is kept: the VEX files, answers.json, java-check.txt, manifest.json (the commits, the binaries' and every
input's sha256, no local path) and SHA256SUMS.
"""
import argparse
import datetime
import glob
import json
import os
import shutil
import subprocess
import sys

from chain import answers as answersmod
from chain import cdx, contract, javacheck, runvens

DEMO_SCAN = os.path.join("runs", "2026-09-23", "scan", "scan.json")
CONTEXTS = ("internet-facing", "internal", "internal-api")


def _run(binary, arm, commit, config, report, folder, expect, label):
    rec = runvens.generate(binary, config, report, folder, record={"arm": arm, "vens_sha": commit})
    expect(f"vens generate, {arm}, {label}: exit", rec["generate"]["exit_status"], 0)
    return folder


def _scenarios(a, binary, arm, commit, out, expect, inputs):
    pairs = []
    for cfg in sorted(glob.glob(os.path.join(a.scenarios, "*", "config.yaml"))):
        name = os.path.basename(os.path.dirname(cfg))
        report = os.path.join(os.path.dirname(cfg), "report.json")
        marked = runvens.add_marker(cfg, os.path.join(out, "configs", "scenarios", name, "config.yaml"))
        inputs.update({f"scenarios/{name}/config.yaml": runvens.sha256(cfg),
                       f"scenarios/{name}/report.json": runvens.sha256(report),
                       f"configs/scenarios/{name}/config.yaml": runvens.sha256(marked)})
        folder = _run(binary, arm, commit, marked, report, os.path.join(out, "runs", arm, "scenarios", name),
                      expect, f"scenario {name}")
        pairs.append((folder, report))
    return pairs


def _demo(a, binary, arm, commit, out, expect, inputs):
    scan, pairs = os.path.join(a.demo, DEMO_SCAN), []
    inputs[f"vens-demo/{DEMO_SCAN}"] = runvens.sha256(scan)
    for c in CONTEXTS:
        src = os.path.join(a.demo, "contexts", c + ".yaml")
        marked = runvens.add_marker(src, os.path.join(out, "configs", "demo", c + ".yaml"))
        inputs.update({f"vens-demo/contexts/{c}.yaml": runvens.sha256(src),
                       f"configs/demo/{c}.yaml": runvens.sha256(marked)})
        pairs.append((c, _run(binary, arm, commit, marked, scan, os.path.join(out, "runs", arm, "demo", c),
                              expect, f"demo scan {c}"), scan))
    return pairs


def _quickstart(a, out, expect, inputs):
    pairs, config = [], os.path.join(a.quickstart, "config.yaml")
    inputs["vens/examples/quickstart/config.yaml"] = runvens.sha256(config)
    for name in ("trivy", "grype"):
        report = os.path.join(a.quickstart, "reports", f"python-slim.{name}.json")
        inputs[f"vens/examples/quickstart/reports/python-slim.{name}.json"] = runvens.sha256(report)
        folder = _run(a.vens, "after", a.commit, config, report,
                      os.path.join(out, "runs", "after", "quickstart", name), expect, f"quickstart {name}")
        pairs.append((name, folder, report))
    return pairs


def own_commit():
    """The vens-benchmark commit this check runs from, +dirty when its tree differs; unknown outside a checkout."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        head = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        dirty = subprocess.run(["git", "-C", root, "status", "--porcelain"], capture_output=True, text=True,
                               check=True)
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return head.stdout.strip() + ("+dirty" if dirty.stdout.strip() else "")


def answers_check(folders, out, commit=None):
    """answers.json against each after VEX and the contract commit pins: (runs with answers.json, CVEs checked,
    problems)."""
    present, checked, problems = 0, 0, []
    for folder in folders:
        found = glob.glob(os.path.join(folder, "calls", "run-*", "answers.json"))
        ratings, _ = cdx.ratings(os.path.join(folder, "vex.cdx.json"))
        if len(found) != 1:
            problems.append(f"{os.path.relpath(folder, out)}: {len(found)} answers.json")
            continue
        present += 1
        checked += len(ratings)
        doc = answersmod.load(found[0])
        problems += (answersmod.duplicates(doc) + answersmod.check(doc, ratings) + answersmod.reachability(doc)
                     + answersmod.validate(doc, contract.CONTRACTS.get(commit)))
    return present, checked, problems


def before_report(groups):
    """The before's ratings: (report lines, ratings off main's own rule). A rating the reader cannot read is listed,
    not failed on: the calculator refuses it, its other checks not applicable."""
    lines, off = [], []
    for label, kind, pairs in groups:
        if kind != "before":
            continue
        read = [cdx.ratings(vex) for vex, _ in pairs]
        found = [p for ratings, _ in read for p in cdx.main_rule(ratings)]
        unread = [p for _, problems in read for p in problems]
        off += found
        lines.append(f"  {label}: {sum(len(r) for r, _ in read)} ratings read, off main's score or severity "
                     f"{len(found)}; not read {len(unread)}")
        lines += [f"    not read: {p}" for p in unread]
    return lines, off


def archive(out, report_lines, manifest):
    """out/archive: every VEX and answers.json of the runs, java-check.txt, manifest.json and SHA256SUMS; no debug
    folder, no attempt record, no local path."""
    root = os.path.join(out, "archive")
    os.makedirs(root)
    for vex in sorted(glob.glob(os.path.join(out, "runs", "**", "vex.cdx.json"), recursive=True)):
        folder = os.path.dirname(vex)
        dest = os.path.join(root, os.path.relpath(folder, out))
        os.makedirs(dest)
        shutil.copy(vex, os.path.join(dest, "vex.cdx.json"))
        for answers in glob.glob(os.path.join(folder, "calls", "run-*", "answers.json")):
            shutil.copy(answers, os.path.join(dest, "answers.json"))
    with open(os.path.join(root, "java-check.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(report_lines) + "\n")
    with open(os.path.join(root, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
        fh.write("\n")
    files = sorted(os.path.relpath(os.path.join(d, f), root) for d, _, names in os.walk(root) for f in names)
    with open(os.path.join(root, "SHA256SUMS"), "w", encoding="utf-8") as fh:
        fh.writelines(f"{runvens.sha256(os.path.join(root, p))}  {p}\n" for p in files)
    return root


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m chain.javarun")
    for k in ("vens", "commit", "scenarios", "demo", "quickstart", "jar", "out"):
        ap.add_argument("--" + k, required=True)
    ap.add_argument("--before")
    ap.add_argument("--before-commit")
    ap.add_argument("--jdk")
    a = ap.parse_args(argv)
    if os.path.exists(a.out):
        ap.error(f"{a.out} exists")
    if bool(a.before) != bool(a.before_commit):
        ap.error("--before and --before-commit go together")
    jdk = a.jdk or javacheck.jdk_bin()
    if jdk is None:
        ap.error("no JDK: pass --jdk or set JAVA_HOME")
    javacheck.verify_jar(a.jar)
    os.makedirs(a.out)
    expect, inputs = javacheck.Expect(), {}

    scen = _scenarios(a, a.vens, "after", a.commit, a.out, expect, inputs)
    demo = _demo(a, a.vens, "after", a.commit, a.out, expect, inputs)
    quick = _quickstart(a, a.out, expect, inputs)
    vex = lambda folder: os.path.join(folder, "vex.cdx.json")
    groups = [(f"after, the {len(scen)} scenarios", "after", [(vex(f), r) for f, r in scen])]
    groups += [(f"after, demo scan, {c}", "after", [(vex(f), r)]) for c, f, r in demo]
    groups += [(f"after, quickstart {n}", "after", [(vex(f), r)]) for n, f, r in quick]
    before_row = None
    if a.before:
        bscen = _scenarios(a, a.before, "before", a.before_commit, a.out, expect, inputs)
        bdemo = _demo(a, a.before, "before", a.before_commit, a.out, expect, inputs)
        groups += [(f"before, the {len(bscen)} scenarios", "before", [(vex(f), r) for f, r in bscen])]
        groups += [(f"before, demo scan, {c}", "before", [(vex(f), r)]) for c, f, r in bdemo]
        (before_row,) = cdx.vex_rows(vex(bscen[0][0]))

    classes, stub = javacheck.compile_check(jdk, a.jar, os.path.join(a.out, "java-classes"))
    res = javacheck.check_vexes(jdk, a.jar, classes, groups, expect)
    before_lines, off = before_report(groups)
    expect("the before's ratings against main's own rule: problems", off, [])
    (after_row,) = cdx.vex_rows(vex(scen[0][0]))
    cases = javacheck.run_cases(jdk, a.jar, classes, stub, javacheck.failure_cases(after_row, before_row), expect)
    after_folders = [f for f, _ in scen] + [f for _, f, _ in demo] + [f for _, f, _ in quick]
    present, checked, problems = answers_check(after_folders, a.out, a.commit)
    expect("answers.json against the VEX: problems", problems, [])

    binaries = {"after": {"commit": a.commit, "binary_sha256": runvens.sha256(a.vens)}}
    if a.before:
        binaries["before"] = {"commit": a.before_commit, "binary_sha256": runvens.sha256(a.before)}
    run_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    arms = "; ".join(f"{arm} vens {b['commit']}, binary sha256 {b['binary_sha256']}" for arm, b in binaries.items())
    lines = [f"# Java check over the after's VEX on vens's mock; {arms}",
             f"# JAR {javacheck.JAR_NAME} sha256 {javacheck.sha256(a.jar)}; {javacheck.java_version(jdk)}; "
             f"run {run_at} by vens-benchmark {own_commit()}",
             f"Check4 over every VEX, each declared with its arm and its report's CVE ids: exit {res.rc}"]
    lines += ["  " + line for line in res.lines]
    if before_lines:
        lines.append("the before's ratings, their score and severity recomputed under main's own rule:")
        lines += before_lines
    lines.append("each failure path on its own input, the sub-score path through the stub calculator:")
    lines += [f"  {case.name}: exit {rc}; {verdict}" for case, rc, verdict in cases]
    lines.append(f"answers.json against the VEX: runs with answers.json {present} of {len(after_folders)}; CVEs "
                 f"checked {checked}; problems {len(problems)}")
    lines += expect.report()
    manifest = {"vens": binaries, "vens_benchmark": own_commit(), "run_at": run_at, "java": javacheck.java_version(jdk),
                "jar": {"name": javacheck.JAR_NAME, "sha256": javacheck.sha256(a.jar)}, "inputs": inputs,
                "unexpected": len(expect.unexpected())}
    archive(a.out, lines, manifest)
    print("\n".join(lines))
    return 1 if expect.unexpected() else 0


if __name__ == "__main__":
    sys.exit(main())
