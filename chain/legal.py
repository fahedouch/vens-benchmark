"""Target (i) per CVE: whether the Java check accepts a run's rating of each CVE of its report.

Each CVE goes to Check4 (java/Check4.java) as a VEX of its own, declared with that one CVE and the run's arm, so that
Check4's tally for its label is the CVE's: accepted when it is rated once (the CVE not missing, its rating with a
vector, not twice) and its vector parses and scores, fromVector() returning and calculateScore() not throwing. A CVE of
the report the VEX does not list, or lists without a rating, is not accepted. For the after, the label's other counts
say whether the sub-scores, the severity and the score match what the levels give.
"""
import re
import tempfile

from chain import attempt as attemptmod
from chain import cdx, javacheck

_TALLY = re.compile(
    r"(?P<label>c\d+): (?:after|before); VEX files 1; CVEs \d+; of the report missing from the VEX (?P<absent>\d+); "
    r"not in the report \d+; without an OWASP rating (?P<missing>\d+); rated twice (?P<twice>\d+); vectors "
    r"(?P<vectors>\d+); refused by fromVector\(\) or calculateScore\(\) (?P<refused>\d+); sub-scores off the level "
    r"sums /8, /4, /4 (?P<sub>\d+) \(not applicable \d+\); severity differing from OWASP's matrix on the "
    r"calculator's bands with max\(T, B\) (?P<sev>\d+) \(not applicable \d+\); score differing from likelihood x "
    r"max\(T, B\) (?P<score>\d+) \(not applicable \d+\); .*")
COUNTS = ("absent", "missing", "twice", "vectors", "refused", "sub", "sev", "score")


class LegalError(Exception):
    pass


def vex_path(rec):
    return attemptmod._files(rec["folder"])["vex"] if rec.get("folder") else None


def _rows_by_cve(vex):
    out = {}
    for row in cdx.vex_rows(vex):
        out.setdefault(row[0], []).append(row)
    return out


def _lines(items):
    """Check4's input and {label: (item, CVE)}: one declaration per report CVE of each item."""
    lines, where = [], {}
    for name, (kind, vex, report_ids) in items.items():
        rows = _rows_by_cve(vex)
        for vid in sorted(report_ids):
            label = f"c{len(where)}"
            where[label] = (name, vid)
            lines += javacheck.declare(label, kind, label, {vid}, rows.get(vid, []))
    return lines, where


def accepted(items, jdk, jar):
    """items: {name: (arm, VEX path, report CVE ids)}. Returns {name: {CVE: {accepted, sub_off, severity_off,
    score_off}}}, Check4 compiled against the JAR, whose sha256 is checked first."""
    javacheck.verify_jar(jar)
    lines, where = _lines(items)
    out = {name: {} for name in items}
    if not where:
        return out
    with tempfile.TemporaryDirectory() as work:
        classes, _ = javacheck.compile_check(jdk, jar, work)
        res = javacheck.run(jdk, jar, classes, lines)
    seen = set()
    for line in res.lines:
        m = _TALLY.fullmatch(line)
        if not m:
            continue
        name, vid = where[m.group("label")]
        n = {k: int(m.group(k)) for k in COUNTS}
        ok = n["absent"] == n["missing"] == n["twice"] == n["refused"] == 0 and n["vectors"] == 1
        out[name][vid] = {"accepted": ok, "sub_off": n["sub"] > 0, "severity_off": n["sev"] > 0,
                          "score_off": n["score"] > 0}
        seen.add(m.group("label"))
    if seen != set(where):
        raise LegalError(f"Check4 printed {len(seen)} of {len(where)} labels: {res.stderr[-500:]}")
    return out
