"""The Java run step 3's exit is claimed on (venslabs/vens#310 step 4, Q9): the after's VEX on the scenarios (the
schema-2 marker added in a scratch copy until the corpus is regenerated), the demo scan's three contexts and the
two quickstart reports, written on vens's mock; the reference calculator over every vector, its failure paths on
their own inputs, and answers.json's levels against each vector. Every vens exit and every verdict is checked
against the one it must be; any other makes the run exit 1.

    python3 -m chain.javarun --vens BIN --commit SHA --scenarios DIR --demo DIR --quickstart DIR --jar JAR \
        --out DIR [--before BIN --before-commit SHA] [--jdk DIR]

--demo holds runs/2026-09-23/scan/scan.json and contexts/*.yaml (vens-demo); --quickstart is vens's
examples/quickstart at --commit. --out must not exist; it receives the runs, java-check.txt and SHA256SUMS.
"""
import argparse
import datetime
import glob
import os
import subprocess
import sys

from chain import answers as answersmod
from chain import cdx, javacheck, runvens

DEMO_SCAN = os.path.join("runs", "2026-09-23", "scan", "scan.json")
CONTEXTS = ("internet-facing", "internal", "internal-api")


def _run(a, binary, arm, commit, config, report, folder, expect, label):
    rec = runvens.generate(binary, config, report, folder, record={"arm": arm, "vens_sha": commit})
    expect(f"vens generate, {arm}, {label}: exit", rec["generate"]["exit_status"], 0)
    return folder


def _scenarios(a, binary, arm, commit, out, expect):
    pairs = []
    for cfg in sorted(glob.glob(os.path.join(a.scenarios, "*", "config.yaml"))):
        name = os.path.basename(os.path.dirname(cfg))
        report = os.path.join(os.path.dirname(cfg), "report.json")
        marked = runvens.add_marker(cfg, os.path.join(out, "configs", name, "config.yaml"))
        folder = _run(a, binary, arm, commit, marked, report, os.path.join(out, "runs", arm, "scenarios", name),
                      expect, f"scenario {name}")
        pairs.append((folder, report))
    return pairs


def _demo(a, binary, arm, commit, out, expect):
    scan, pairs = os.path.join(a.demo, DEMO_SCAN), []
    for c in CONTEXTS:
        marked = runvens.add_marker(os.path.join(a.demo, "contexts", c + ".yaml"),
                                    os.path.join(out, "configs", "demo", c + ".yaml"))
        pairs.append((c, _run(a, binary, arm, commit, marked, scan, os.path.join(out, "runs", arm, "demo", c),
                              expect, f"demo scan {c}"), scan))
    return pairs


def _quickstart(a, out, expect):
    pairs = []
    for name in ("trivy", "grype"):
        report = os.path.join(a.quickstart, "reports", f"python-slim.{name}.json")
        folder = _run(a, a.vens, "after", a.commit, os.path.join(a.quickstart, "config.yaml"), report,
                      os.path.join(out, "runs", "after", "quickstart", name), expect, f"quickstart {name}")
        pairs.append((name, folder, report))
    return pairs


def _own_commit():
    """The vens-benchmark commit this check runs from, +dirty when its tree differs; unknown outside a checkout."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        head = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        dirty = subprocess.run(["git", "-C", root, "status", "--porcelain"], capture_output=True, text=True,
                               check=True)
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return head.stdout.strip() + ("+dirty" if dirty.stdout.strip() else "")


def _answers(folders):
    """answers.json against each after VEX: (runs with answers.json, CVEs checked, problems)."""
    present, checked, problems = 0, 0, []
    for folder in folders:
        found = glob.glob(os.path.join(folder, "calls", "run-*", "answers.json"))
        ratings, _ = cdx.ratings(os.path.join(folder, "vex.cdx.json"))
        if len(found) != 1:
            problems.append(f"{folder}: {len(found)} answers.json")
            continue
        present += 1
        checked += len(ratings)
        problems += answersmod.check(answersmod.load(found[0]), ratings)
    return present, checked, problems


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
    jdk = a.jdk or javacheck.jdk_bin()
    if jdk is None:
        ap.error("no JDK: pass --jdk or set JAVA_HOME")
    javacheck.verify_jar(a.jar)
    os.makedirs(a.out)
    expect = javacheck.Expect()

    scen = _scenarios(a, a.vens, "after", a.commit, a.out, expect)
    demo = _demo(a, a.vens, "after", a.commit, a.out, expect)
    quick = _quickstart(a, a.out, expect)
    vex = lambda folder: os.path.join(folder, "vex.cdx.json")
    groups = [(f"after, the {len(scen)} scenarios", "after", [(vex(f), r) for f, r in scen])]
    groups += [(f"after, demo scan, {c}", "after", [(vex(f), r)]) for c, f, r in demo]
    groups += [(f"after, quickstart {n}", "after", [(vex(f), r)]) for n, f, r in quick]
    before_row = None
    if a.before:
        bscen = _scenarios(a, a.before, "before", a.before_commit, a.out, expect)
        bdemo = _demo(a, a.before, "before", a.before_commit, a.out, expect)
        groups += [(f"before, the {len(bscen)} scenarios", "before", [(vex(f), r) for f, r in bscen])]
        groups += [(f"before, demo scan, {c}", "before", [(vex(f), r)]) for c, f, r in bdemo]
        (before_row,) = cdx.vex_rows(vex(bscen[0][0]))

    classes, stub = javacheck.compile_check(jdk, a.jar, os.path.join(a.out, "java-classes"))
    res = javacheck.check_vexes(jdk, a.jar, classes, groups, expect)
    main_rule = []
    for label, kind, pairs in groups:
        if kind == "before":
            found = [p for vex_path, _ in pairs for p in cdx.main_rule(cdx.ratings(vex_path)[0])]
            expect(f"main's rule, {label}: problems", found, [])
            main_rule.append(f"  {label}: {sum(len(cdx.ratings(v)[0]) for v, _ in pairs)} ratings, "
                             f"off main's score or severity {len(found)}")
    (after_row,) = cdx.vex_rows(vex(scen[0][0]))
    cases = javacheck.run_cases(jdk, a.jar, classes, stub, javacheck.failure_cases(after_row, before_row), expect)
    after_folders = [f for f, _ in scen] + [f for _, f, _ in demo] + [f for _, f, _ in quick]
    present, checked, problems = _answers(after_folders)
    expect("answers.json against the VEX: problems", problems, [])

    lines = [f"# Java check over the after's VEX on vens's mock; vens {a.commit}, binary sha256 "
             f"{runvens.sha256(a.vens)}" + (f"; before vens {a.before_commit}, binary sha256 "
                                            f"{runvens.sha256(a.before)}" if a.before else ""),
             f"# JAR {javacheck.JAR_NAME} sha256 {javacheck.sha256(a.jar)}; {javacheck.java_version(jdk)}; "
             f"run {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%MZ')} by vens-benchmark "
             f"{_own_commit()}",
             f"Check4 over every VEX, each declared with its arm and its report's CVE ids: exit {res.rc}"]
    lines += ["  " + line for line in res.lines]
    if main_rule:
        lines.append("the before's ratings against main's own rule, recomputed here (the calculator refuses them):")
        lines += main_rule
    lines.append("each failure path on its own input, the sub-score path through the stub calculator:")
    lines += [f"  {case.name}: exit {rc}; {verdict}" for case, rc, verdict in cases]
    lines.append(f"answers.json against the VEX: runs with answers.json {present} of {len(after_folders)}; CVEs "
                 f"checked {checked}; problems {len(problems)}")
    lines += expect.report()
    with open(os.path.join(a.out, "java-check.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    sums = sorted(glob.glob(os.path.join(a.out, "runs", "**", "vex.cdx.json"), recursive=True)
                  + glob.glob(os.path.join(a.out, "runs", "**", "answers.json"), recursive=True)
                  + [os.path.join(a.out, "java-check.txt")])
    with open(os.path.join(a.out, "SHA256SUMS"), "w", encoding="utf-8") as fh:
        fh.writelines(f"{runvens.sha256(p)}  {os.path.relpath(p, a.out)}\n" for p in sums)
    print("\n".join(lines))
    return 1 if expect.unexpected() else 0


if __name__ == "__main__":
    sys.exit(main())
