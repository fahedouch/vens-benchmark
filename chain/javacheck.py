"""The Java check (venslabs/vens#310 step 4, section 2.4): the OWASP reference calculator's 1.0.1 JAR over every
OWASP rating of every VEX the chain collects, each VEX declared with its arm and the CVE ids its report gives, and the
driver, which records every exit and verdict against the one its input must give.

    python3 -m chain.javacheck fetch-jar DIR      download the JAR into DIR and check its sha256
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass

from chain import cdx

JAR_NAME = "owasp-risk-rating-calculator-1.0.1.jar"
JAR_URL = "https://repo1.maven.org/maven2/us/springett/owasp-risk-rating-calculator/1.0.1/" + JAR_NAME
JAR_SHA256 = "9b66d91d1ff61f99e320466ff451555696f139147260528591ff1718c5605d1c"
JAVA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "java")
OTHER = "CVE-2099-9999"  # an id no corpus holds, for the controls that swap one in
ABSENT, EXTRA = "a CVE of the report missing from the VEX", "a CVE the report does not hold"
_LINE = re.compile(r"(?P<label>.+): (?P<kind>after|before|refused); VEX files \d+; .*; (?P<verdict>PASS|FAIL: .+)")


class JarError(Exception):
    pass


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def verify_jar(path):
    got = sha256(path)
    if got != JAR_SHA256:
        raise JarError(f"{path}: sha256 {got}, not {JAR_SHA256}")
    return path


def fetch_jar(dest_dir):
    """The JAR in dest_dir, downloaded from Maven Central when absent; JarError unless its sha256 is the one the
    calculator's product was run with."""
    path = os.path.join(dest_dir, JAR_NAME)
    if not os.path.exists(path):
        os.makedirs(dest_dir, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=dest_dir, suffix=".part")
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(JAR_URL, timeout=60) as resp:
            shutil.copyfileobj(resp, out)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    return verify_jar(path)


def jdk_bin():
    """A JDK's bin folder: $VB_JDK, else $JAVA_HOME/bin, else javac's folder on PATH; None without one."""
    for candidate in (os.environ.get("VB_JDK"),
                      os.path.join(os.environ["JAVA_HOME"], "bin") if os.environ.get("JAVA_HOME") else None,
                      os.path.dirname(shutil.which("javac") or "")):
        if candidate and all(os.path.exists(os.path.join(candidate, t)) for t in ("java", "javac")):
            if subprocess.run([os.path.join(candidate, "java"), "-version"], capture_output=True).returncode == 0:
                return candidate
    return None


def java_version(jdk):
    r = subprocess.run([os.path.join(jdk, "java"), "-version"], capture_output=True, text=True)
    return (r.stderr or r.stdout).splitlines()[0]


def compile_check(jdk, jar, work):
    """(Check4's classes, the stub calculator's classes), compiled into work."""
    classes, stub = os.path.join(work, "classes"), os.path.join(work, "stub-classes")
    for out, src in ((classes, os.path.join(JAVA_DIR, "Check4.java")),
                     (stub, os.path.join(JAVA_DIR, "stub", "OwaspRiskRating.java"))):
        os.makedirs(out, exist_ok=True)
        subprocess.run([os.path.join(jdk, "javac"), "-cp", jar, "-d", out, src], check=True)
    return classes, stub


def declare(label, kind, vex_id, expected, rows):
    """Check4's input for one VEX: its declaration with the CVE ids its report gives, then one line per rating."""
    return ([f"#vex\t{label}\t{vex_id}\t{kind}\t{','.join(sorted(expected))}"]
            + [f"{label}\t{vex_id}\t{vid}\t{vec}\t{sev}\t{score}" for vid, vec, sev, score in rows])


@dataclass(frozen=True)
class Result:
    rc: int
    lines: tuple
    stderr: str

    def verdicts(self):
        return {m.group("label"): m.group("verdict") for m in map(_LINE.fullmatch, self.lines) if m}


def run(jdk, jar, classes, lines, stub=None):
    cp = os.pathsep.join(([stub] if stub else []) + [jar, classes])
    r = subprocess.run([os.path.join(jdk, "java"), "-cp", cp, "Check4"], input="\n".join(lines) + "\n",
                       capture_output=True, text=True)
    return Result(r.returncode, tuple(r.stdout.splitlines()), r.stderr)


class Expect:
    """Every exit status and verdict met, with the one it must be."""

    def __init__(self):
        self.checks = []

    def __call__(self, what, got, want):
        self.checks = self.checks + [(what, got, want)]
        return got == want

    def unexpected(self):
        return [c for c in self.checks if c[1] != c[2]]

    def report(self):
        bad = self.unexpected()
        lines = [f"statuses: {len(self.checks)} exit statuses and verdicts checked against what each must be; "
                 f"unexpected {len(bad)}"]
        return lines + [f"  {what}: {got!r}, where {want!r} was expected" for what, got, want in bad]


@dataclass(frozen=True)
class Case:
    name: str
    kind: str
    expected: frozenset
    rows: tuple
    stub: bool
    rc: int
    reasons: tuple

    def verdict(self):
        return "FAIL: " + ", ".join(self.reasons) if self.reasons else "PASS"


def failure_cases(after_row, before_row=None):
    """Each failure path of the check on its own input, built from one after rating and one before rating, with
    the exit and the reasons it must give; the two ratings as published pass."""
    vid, vec, sev, score = after_row
    ok = tuple(after_row)
    cases = [
        Case("the after rating as published", "after", frozenset({vid}), (ok,), False, 0, ()),
        Case("an after vector off its enumeration, NC at 9", "after", frozenset({vid}),
             ((vid, re.sub(r"NC:\d", "NC:9", vec), sev, score),), False, 1, ("an after vector refused",)),
        Case("an after severity changed", "after", frozenset({vid}),
             ((vid, vec, "low" if sev != "low" else "high", score),), False, 1, ("a severity off the matrix",)),
        Case("an after score changed by 1", "after", frozenset({vid}), ((vid, vec, sev, repr(float(score) + 1)),),
             False, 1, ("a score off L x max(T, B)",)),
        Case("an after rating through the stub calculator", "after", frozenset({vid}), (ok,), True, 1,
             ("sub-scores off the level sums",)),
        Case("a control given the after's legal vector", "refused", frozenset({vid}), (ok,), False, 1,
             ("a control vector accepted",)),
    ]
    cases += _id_cases("after", ok)
    if before_row is not None:
        cases += [Case("the before rating as published, refused", "before", frozenset({before_row[0]}),
                       (tuple(before_row),), False, 0, ())]
        cases += _id_cases("before", tuple(before_row))
    return cases


def _id_cases(kind, row):
    vid = row[0]
    return [
        Case(f"{kind}, a CVE the VEX lists without an OWASP rating", kind, frozenset({vid}), ((vid, "", "", ""),),
             False, 1, ("a CVE without an OWASP rating",)),
        Case(f"{kind}, a CVE rated twice", kind, frozenset({vid}), (row, row), False, 1, ("a CVE rated twice",)),
        Case(f"{kind}, one CVE of the report missing", kind, frozenset({vid, OTHER}), (row,), False, 1, (ABSENT,)),
        Case(f"{kind}, the report's CVE replaced by another one", kind, frozenset({vid}), ((OTHER,) + row[1:],),
             False, 1, (ABSENT, EXTRA)),
    ]


def run_cases(jdk, jar, classes, stub, cases, expect, want_rc=None):
    """Runs each case and records its exit and verdict against the case's; want_rc, if given, replaces every case's
    expected exit, which is how the driver is shown to fail on an exit it does not expect."""
    out = []
    for case in cases:
        res = run(jdk, jar, classes, declare("case", case.kind, "case", case.expected, case.rows),
                  stub=stub if case.stub else None)
        expect(f"{case.name}: exit", res.rc, case.rc if want_rc is None else want_rc)
        verdict = res.verdicts().get("case", "no output")
        expect(f"{case.name}: verdict", verdict, case.verdict())
        out.append((case, res.rc, verdict))
    return out


def control_rows():
    """One vector the calculator must refuse: every factor at 9, NC off its enumeration."""
    return [("X", "/".join(f"{f}:9" for f in cdx.FACTORS), "critical", "81.0")]


def check_vexes(jdk, jar, classes, groups, expect):
    """Check4 over every VEX of groups, [(label, kind, [(vex, report), ...])], and the refused control; the exit
    and every label's verdict recorded against PASS. Returns the Result."""
    lines = []
    for label, kind, pairs in groups:
        for vex, report in pairs:
            lines += declare(label, kind, vex, cdx.report_ids(report), cdx.vex_rows(vex))
    lines += declare("control, one off-enumeration vector (NC 9)", "refused", "control", {"X"}, control_rows())
    res = run(jdk, jar, classes, lines)
    expect("Check4 over every VEX and the control: exit", res.rc, 0)
    for label, verdict in sorted(res.verdicts().items()):
        expect(f"Check4, {label}: verdict", verdict, "PASS")
    return res


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] != "fetch-jar":
        print(__doc__, file=sys.stderr)
        return 2
    try:
        print(fetch_jar(argv[1]))
    except JarError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
