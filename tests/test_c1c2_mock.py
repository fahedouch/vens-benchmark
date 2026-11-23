"""C1 + C2' and C1 + C2 without a reachability relay against vens's own mock LLM, no model and no API key: the C2'
commit, S2's after (VB_VENS_C1C2P, contract.C2P_COMMIT), and N beside it (VB_VENS_C1C2, contract.N_COMMIT).

- the demo scan: the chain's C2 counts equal what vens's Go tests freeze for it at the C2' commit (VB_VENS_C1C2P_SRC).
  In its three contexts (availability_requirement critical, low, medium) and in internal's with the field high and
  unset, per CVE the levels, sources, CVSS values, Privacy violation's floors, cvss_v3_missing and
  availability_requirement_missing the C2' commit writes (VB_VENS_C1C2P, VB_DEMO), every run recomputed by
  chain/conform.py under c1c2p. N's runs on the same inputs equal them but on Loss of availability where C2''s table
  differs from C2's and on the counter; they pass under c1c2, and fail under c1c2p where the record or the config
  tells the two apart, as the C2' commit's fail under c1c2;
- every scenario on the C2' commit: each call's question, every level, source and counter, a system prompt byte for
  byte N's and b7c0435's (VB_VENS_C1C2, VB_VENS_AFTER), every level N's (step 5's corpus reads the primary column); no
  VEX status and no declared block, every run as conform recomputes it under c1c2p; a flagged copy, described and not,
  through the adjustment;
- a scenario campaign through ctx_runner.py on the eight showcase and reachability scenarios, both arms
  (VB_VENS_BEFORE), the after at the C2' commit, read by ctx_analyze.py under c1c2p, pinned by --rules or by the
  commit: the implementation gate binding on every after cell, the checks the notes alone may move as diagnostics,
  showcase_med_to_high carried under read5's eligibility rule; read under c1c2, every after answers.json refused. N's
  campaign on the same scenarios passes under c1c2 and fails the gate under c1c2p, on the counter.
"""
import collections
import contextlib
import glob
import gzip
import hashlib
import io
import json
import os
import re
import tempfile
import unittest

import yaml

import ctx_analyze
import ctx_runner
from chain import attempt, calls, cdx, conform, contract, families, read, runvens, verdicts
from chain import cells as cellmod
from tests import support as s

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS = os.path.join(ROOT, "scenarios")
IDS = sorted(d for d in os.listdir(SCENARIOS) if os.path.isdir(os.path.join(SCENARIOS, d)))
SHOWCASES_AND_REACH = ("reach_no", "reach2_no", "reach3_no", "showcase_high_to_low", "reach_yes", "reach2_yes",
                       "reach3_yes", "showcase_med_to_high")
DEMO_SCAN = os.path.join("runs", "2026-09-23", "scan", "scan.json")
# The bytes vens pins for its copy of the demo scan (pkg/scanner/reports_test.go), and what C2 reads of them there.
DEMO_SHA = "afc7d20702f270e4dbd43579c67ea295064f42183a3369baf9d4734a91153514"
DEMO_COUNTS = {"cves": 74, "vectorless": 10, "rejected": 0, "disagree": 8, "disagree_axes": 12, "v4": 9,
               "pv_floor": 28}
GO_COUNTS = re.compile(r'"vens-demo scan", "testdata/vens-demo-2026-09-23\.trivy\.json\.gz",\s*"(?P<sha>[0-9a-f]{64})"'
                       r'.*?Impact: impactCounts\{Vectorless: (?P<vectorless>\d+), Rejected: (?P<rejected>\d+), '
                       r'Disagree: (?P<disagree>\d+), DisagreeAxes: (?P<disagree_axes>\d+), V4: (?P<v4>\d+)\}', re.S)
GO_KEYS = ("vectorless", "rejected", "disagree", "disagree_axes", "v4")
# The scenarios: one vector each but on the ten copies, none refused, none disagreeing; Z2's replay printed the same.
SCENARIO_COUNTS = {"cves": 46, "vectorless": 10, "rejected": 0, "disagree": 0, "disagree_axes": 0, "v4": 0,
                   "pv_floor": 11}
AR, VM = contract.AVAILABILITY_MISSING, contract.VECTOR_MISSING
# Each demo state: its context, availability_requirement (the context's own where it is the file's), Loss of
# availability's moves from N to the C2' commit, {(worst A, N's level, C2''s): CVEs}, and the CVEs counted
# availability_requirement_missing. Z8 printed the moves: internal and internal-api alone, 38 of 74 each.
SECONDARY = {("H", 7, 5): 30, ("L", 5, 1): 8}
STATES = {"internet-facing": ("internet-facing", "critical", {}, 0),
          "internal": ("internal", "low", SECONDARY, 0),
          "internal-api": ("internal-api", "medium", SECONDARY, 0),
          "internal-high": ("internal", "high", {}, 0),
          "internal-unset": ("internal", None, {}, 64)}
REQUIREMENT = re.compile(r'^[ \t]*availability_requirement:.*\n', re.M)


def answers_doc(folder):
    with open(os.path.join(verdicts.run_dir(folder), "answers.json"), encoding="utf-8") as fh:
        return json.load(fh)


def answers_entries(folder):
    return {e["vulnId"]: e for e in answers_doc(folder)["vulnerabilities"]}


def given(e):
    """An answers.json entry's answers and adjustment as chain.contract.c1c2_levels takes them."""
    fs = {x["factor"]: x for x in e["factors"]}
    return ({f: x["answer"] for f, x in fs.items() if "answer" in x},
            {f: fs[f].get("adjusted") for f in ("O", "PV") if f in fs})


def written(e):
    return {x["factor"]: (x["level"], x["source"]) for x in e["factors"]}


def c2_counters(e):
    """The C2 counters an entry holds, in its order."""
    return [c for c in e.get("counters", []) if c in (VM, AR)]


def demo_tree(demo, root):
    """A vens-demo tree under root for the five states: the scan linked, each state's context written, its
    availability_requirement set, replaced or removed, every other byte the context's own."""
    os.makedirs(os.path.join(root, os.path.dirname(DEMO_SCAN)))
    os.symlink(os.path.join(demo, DEMO_SCAN), os.path.join(root, DEMO_SCAN))
    for state, (ctx, requirement, _, _) in STATES.items():
        with open(os.path.join(demo, "contexts", f"{ctx}.yaml"), encoding="utf-8") as fh:
            text = fh.read()
        (line,) = REQUIREMENT.findall(text)
        if requirement is None:
            text = text.replace(line, "")
        elif f'"{requirement}"' not in line:
            text = text.replace(line, line.split(":")[0] + f': "{requirement}"\n')
        s.write(os.path.join(root, "contexts", f"{state}.yaml"), text)
    return root


class TestTheDemoScan(unittest.TestCase):
    """The chain's C2 counts and per-CVE reading of the demo scan against the C2' commit's, N's beside."""

    @classmethod
    def setUpClass(cls):
        demo = s.env("VB_DEMO")
        if demo is None:
            raise unittest.SkipTest("set VB_DEMO to a vens-demo tree at 7ab1570 to read the demo scan")
        cls.demo, cls.scan = demo, os.path.join(demo, DEMO_SCAN)
        cls.cves = contract.report_cves(cls.scan)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tree = demo_tree(demo, os.path.join(cls.tmp.name, "demo"))
        cls.runs = {}
        for tag, var in (("c2p", "VB_VENS_C1C2P"), ("n", "VB_VENS_C1C2")):
            binary = s.env(var)
            for state in STATES if binary else ():
                config = runvens.add_marker(os.path.join(cls.tree, "contexts", f"{state}.yaml"),
                                            os.path.join(cls.tmp.name, tag, state, "config.yaml"))
                folder = os.path.join(cls.tmp.name, tag, state, "run")
                rec = runvens.generate(binary, config, cls.scan, folder, record={"arm": "after"}, batch=10)
                with open(config, encoding="utf-8") as fh:
                    dep = contract.deployment(yaml.safe_load(fh))
                cls.runs[(tag, state)] = (folder, rec["generate"]["exit_status"], dep)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def need_runs(self, *tags):
        names = {"c2p": "VB_VENS_C1C2P", "n": "VB_VENS_C1C2"}
        s.need(self, *(names[t] for t in tags))

    def test_the_counts(self):
        self.assertEqual(runvens.sha256(self.scan), DEMO_SHA)
        self.assertEqual(contract.impact_counts(self.cves), DEMO_COUNTS)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            contract.main(["--demo", self.scan, "--scenarios", SCENARIOS])
        self.assertEqual(out.getvalue().splitlines(), [contract.counts_line("demo scan", DEMO_COUNTS),
                                                       contract.counts_line("scenarios", SCENARIO_COUNTS)])

    def test_the_counts_vens_go_tests_freeze(self):
        (src,) = s.need(self, "VB_VENS_C1C2P_SRC")
        with open(os.path.join(src, "pkg", "scanner", "reports_test.go"), encoding="utf-8") as fh:
            m = GO_COUNTS.search(fh.read())
        self.assertIsNotNone(m)
        with gzip.open(os.path.join(src, "pkg", "scanner", "testdata", "vens-demo-2026-09-23.trivy.json.gz")) as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), m["sha"])
        self.assertEqual(m["sha"], DEMO_SHA)
        got = contract.impact_counts(self.cves)
        self.assertEqual({k: int(m[k]) for k in GO_KEYS}, {k: got[k] for k in GO_KEYS})

    def test_the_states(self):
        self.need_runs("c2p")
        self.assertEqual({state: dep["availability_requirement"] for (tag, state), (_, _, dep) in self.runs.items()
                          if tag == "c2p"}, {state: x[1] for state, x in STATES.items()})

    def test_per_cve_against_what_the_c2p_commit_writes(self):
        self.need_runs("c2p")
        for state, (_, requirement, _, counted) in STATES.items():
            folder, code, dep = self.runs[("c2p", state)]
            self.assertEqual(code, 0, state)
            entries = answers_entries(folder)
            self.assertEqual(sorted(entries), sorted(self.cves), state)
            floors, vectorless, missing = set(), set(), set()
            for vid, e in entries.items():
                imp, fs = contract.cve_impact(self.cves[vid]), {x["factor"]: x for x in e["factors"]}
                described = any((f.get("Description") or "").strip() for f in self.cves[vid])
                for f in contract.AXIS:
                    self.assertEqual((fs[f]["level"], fs[f]["source"], fs[f].get("cvss")),
                                     (contract.impact_level(f, dep, imp, contract.C1C2P), "cvss",
                                      imp.values.get(contract.AXIS[f])), (state, vid, f))
                floors |= {vid} if fs["PV"]["source"] == "floor" else set()
                vectorless |= {vid} if VM in e.get("counters", []) else set()
                missing |= {vid} if AR in e.get("counters", []) else set()
                self.assertEqual(c2_counters(e), contract.c1c2_counters(dep, imp, contract.C1C2P), (state, vid))
                answered, adjusted = given(e)
                self.assertEqual(sorted(answered), sorted(contract.c1c2_questions(dep, imp, described)), (state, vid))
                self.assertEqual(written(e), contract.c1c2_levels(dep, imp, described, answered, adjusted,
                                                                  contract.C1C2P), (state, vid))
            usable = {v for v, fs in self.cves.items() if contract.cve_impact(fs).usable}
            self.assertEqual(floors, {v for v, fs in self.cves.items()
                                      if contract.privacy_floored(contract.cve_impact(fs))}, state)
            self.assertEqual(vectorless, set(self.cves) - usable, state)
            self.assertEqual(missing, usable if requirement is None else set(), state)
            self.assertEqual((len(floors), len(vectorless), len(missing)), (28, 10, counted), state)
            totals = answers_doc(folder)["counters"]
            self.assertEqual((totals.get(VM), totals.get(AR)), (10, counted or None), state)
            for rules in (None, contract.C1C2P):
                got = attempt.read_attempt(folder, rules=rules)
                self.assertEqual((got["scores_usable"], got["problems"], got["answers"]["problems"]), (True, [], []),
                                 (state, rules))
            self.check_recomputed(got, state, contract.C1C2P, contract.C2P_COMMIT)

    def test_n_beside_the_c2p_commit(self):
        self.need_runs("c2p", "n")
        for state, (_, requirement, moves, _) in STATES.items():
            (c2p, _, dep), (n, code, _) = self.runs[("c2p", state)], self.runs[("n", state)]
            self.assertEqual(code, 0, state)
            ours, theirs = answers_entries(c2p), answers_entries(n)
            got = collections.Counter()
            for vid, e in ours.items():
                was, now = written(theirs[vid]), written(e)
                self.assertEqual({f for f in now if now[f] != was[f]} - {"LAV"}, set(), (state, vid))
                if now["LAV"] != was["LAV"]:
                    got[(contract.cve_impact(self.cves[vid]).values["A"], was["LAV"][0], now["LAV"][0])] += 1
                self.assertEqual([c for c in e.get("counters", []) if c != AR], theirs[vid].get("counters", []),
                                 (state, vid))
            self.assertEqual(dict(got), moves, state)
            # N's runs follow C1 + C2; each commit's runs fail under the other's contract where the two differ
            rec_n = attempt.read_attempt(n, rules=contract.C1C2)
            self.assertEqual((rec_n["scores_usable"], rec_n["answers"]["problems"]), (True, []), state)
            self.check_recomputed(rec_n, state, contract.C1C2, contract.N_COMMIT)
            differ = bool(moves) or requirement is None
            self.check_recomputed(rec_n, state, contract.C1C2P, contract.N_COMMIT, passes=not differ)
            rec = attempt.read_attempt(c2p, rules=contract.C1C2)
            self.assertEqual(rec["answers"]["problems"],
                             ["answers.json follows c1c2p, not the pinned c1c2"] if differ else [], state)

    def check_recomputed(self, rec, state, rules, commit, passes=True):
        """chain/conform.py on the run laid out as baseline.yml's: every CVE as recomputed, no status, a pass; one
        status added, or one score off, a failure."""
        what = {**rec["what"], "runner": "baseline.yml", "context": state, "corpus": DEMO_SCAN, "replicate": 1,
                "config": os.path.join("contexts", f"{state}.yaml"), "vens_commit": commit}
        demo_rec = {**rec, "what": what}
        got = conform.read(cellmod.group([demo_rec]), None, self.tree, rules)
        (c,) = got.values()
        self.assertEqual((c["verdict"], c["cves"], c["statuses"]), ("pass" if passes else "fail", 74, []),
                         (state, rules))
        if not passes:
            return
        vid = sorted(rec["ratings"])[0]
        status = {"state": "not_affected", "justification": "code_not_reachable", "detail": "x"}
        for change, want in ((dict(analysis=status), f"r1 {vid}: the VEX publishes a status, not_affected; r1 {vid} "
                                                     f"holds a VEX status or a declared block"),
                             (dict(score=0.5), f"r1 {vid}: score 0.5 not {rec['ratings'][vid]['score']!r}")):
            tampered = {**demo_rec, "ratings": {**rec["ratings"], vid: {**rec["ratings"][vid], **change}}}
            (line,) = conform.failures(conform.read(cellmod.group([tampered]), None, self.tree, rules))
            self.assertEqual(line.split(": fail: ", 1)[1], want, state)


class TestTheScenariosOnTheMock(unittest.TestCase):
    """Every scenario on the C2' commit's mock, as answered and with every answer cannot_tell, N and b7c0435 beside it,
    and two flagged copies."""

    FLAGGED = "crit_critical"
    DISPUTE = " Fixed in 2.0. The maintainer disputes this report."
    # The undescribed copy is flagged severity_contested: its row LOW from another source, NVD's CRITICAL.
    UNDESCRIBED = {"Description": "", "Severity": "LOW", "SeveritySource": "debian"}

    @classmethod
    def setUpClass(cls):
        cls.binary = s.env("VB_VENS_C1C2P")
        if cls.binary is None:
            raise unittest.SkipTest("set VB_VENS_C1C2P to a vens binary built from 310-c1c2 at the C2' commit")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.scen = verdicts.load(SCENARIOS, contract.C1C2P)
        cls.runs = {}
        for tag, binary, extra in (("after", cls.binary, None),
                                   ("cannot_tell", cls.binary, {"VENS_MOCK_LLM_CANNOT_TELL": "cannot_tell"}),
                                   ("n", s.env("VB_VENS_C1C2"), None),
                                   ("b7c0435", s.env("VB_VENS_AFTER"), None)):
            for sid in IDS if binary else ():
                d = os.path.join(SCENARIOS, sid)
                cls.generate(tag, sid, os.path.join(d, "config.yaml"), os.path.join(d, "report.json"), extra,
                             binary)
        cls.flagged = {}
        with open(os.path.join(SCENARIOS, cls.FLAGGED, "report.json"), encoding="utf-8") as fh:
            report = json.load(fh)
        original = report["Results"][0]["Vulnerabilities"][0]
        for tag, f in (("described", {**original, "Description": original["Description"] + cls.DISPUTE}),
                       ("undescribed", {**original, **cls.UNDESCRIBED})):
            doc = {**report, "Results": [{**report["Results"][0], "Vulnerabilities": [f]}]}
            path = s.write(os.path.join(cls.tmp.name, f"flagged-{tag}.json"), doc)
            cls.flagged[tag] = f
            cls.generate(f"flagged-{tag}", cls.FLAGGED, os.path.join(SCENARIOS, cls.FLAGGED, "config.yaml"), path,
                         binary=cls.binary)

    @classmethod
    def generate(cls, tag, sid, config, report, extra=None, binary=None):
        folder = os.path.join(cls.tmp.name, tag, sid)
        rec = runvens.generate(binary, config, report, folder, record={"arm": "after"}, env_extra=extra)
        cls.runs[(tag, sid)] = (folder, rec["generate"]["exit_status"])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def entry(self, tag, sid):
        (e,) = answers_entries(self.runs[(tag, sid)][0]).values()
        return e

    def vex(self, tag, sid):
        ratings, problems = cdx.ratings(os.path.join(self.runs[(tag, sid)][0], "vex.cdx.json"))
        self.assertEqual(problems, [])
        (r,) = ratings.values()
        return r

    def beside(self, tag):
        if (tag, IDS[0]) not in self.runs:
            self.skipTest(f"set {'VB_VENS_C1C2' if tag == 'n' else 'VB_VENS_AFTER'} to run {tag} beside")

    def test_every_run_completes_and_reads(self):
        for (tag, sid), (folder, code) in self.runs.items():
            self.assertEqual(code, 0, (tag, sid))
            if tag == "b7c0435":
                continue
            rules = contract.C1C2 if tag == "n" else contract.C1C2P
            rec = attempt.read_attempt(folder, rules=rules)
            self.assertEqual((rec["outcome"], rec["scores_usable"], rec["problems"], rec["answers"]["problems"]),
                             ("complete", True, [], []), (tag, sid))

    def test_each_call_asks_the_questions_the_rules_give(self):
        for tag in ("after", "cannot_tell"):
            for sid in IDS:
                sc = self.scen[sid]
                asked = [contract.question_of(c.text("human"))
                         for c in calls.load(verdicts.run_dir(self.runs[(tag, sid)][0]))]
                self.assertEqual(asked, contract.c1c2_questions(sc["dep"], sc["impact"], sc["described"]), (tag, sid))
                self.assertLessEqual(len(asked), 9)

    def test_the_levels_sources_and_counters_vens_wrote(self):
        counted = collections.Counter()
        for tag in ("after", "cannot_tell"):
            for sid in IDS:
                sc, e = self.scen[sid], self.entry(tag, sid)
                answered, adjusted = given(e)
                if tag == "cannot_tell":
                    self.assertEqual(set(answered.values()) - {contract.CANNOT_TELL}, set(), sid)
                self.assertEqual(written(e), contract.c1c2_levels(sc["dep"], sc["impact"], sc["described"], answered,
                                                                  adjusted, contract.C1C2P), (tag, sid))
                fs = {x["factor"]: x for x in e["factors"]}
                self.assertEqual({f: fs[f].get("cvss") for f in contract.AXIS},
                                 {f: sc["impact"].values.get(contract.AXIS[f]) for f in contract.AXIS}, sid)
                self.assertEqual(c2_counters(e), contract.c1c2_counters(sc["dep"], sc["impact"], contract.C1C2P), sid)
                totals = answers_doc(self.runs[(tag, sid)][0])["counters"]
                self.assertEqual(totals.get(AR, 0), c2_counters(e).count(AR), sid)
                counted[tag] += AR in c2_counters(e)
        self.assertEqual(counted, {"after": 31, "cannot_tell": 31})

    def test_n_writes_the_same_levels(self):
        self.beside("n")
        for sid in IDS:
            ours, theirs = self.entry("after", sid), self.entry("n", sid)
            self.assertEqual(written(ours), written(theirs), sid)
            self.assertEqual([c for c in ours.get("counters", []) if c != AR], theirs.get("counters", []), sid)

    def test_the_system_prompt_is_ns_and_b7c0435s(self):
        for tag in ("n", "b7c0435"):
            self.beside(tag)
            for sid in IDS:
                then = {c.system for c in calls.load(verdicts.run_dir(self.runs[(tag, sid)][0]))}
                now = {c.system for c in calls.load(verdicts.run_dir(self.runs[("after", sid)][0]))}
                self.assertEqual((len(then), now), (1, then), (tag, sid))

    def test_no_status_and_every_run_as_recomputed(self):
        for tag in ("after", "cannot_tell"):
            recs = []
            for sid in IDS:
                self.assertIsNone(self.vex(tag, sid)["analysis"], (tag, sid))
                self.assertNotIn("declared", self.entry(tag, sid), (tag, sid))
                rec = attempt.read_attempt(self.runs[(tag, sid)][0], rules=contract.C1C2P)
                recs.append({**rec, "what": {**rec["what"], "scenario": sid, "replicate": 1}})
            got = conform.read(cellmod.group(recs), self.scen, None, contract.C1C2P)
            self.assertEqual({c["verdict"] for c in got.values()}, {"pass"}, tag)
            self.assertEqual(len(got), len(IDS))

    def test_a_flagged_copy_through_the_adjustment(self):
        sc = self.scen[self.FLAGGED]
        for tag in ("described", "undescribed"):
            folder, _ = self.runs[(f"flagged-{tag}", self.FLAGGED)]
            e, f = self.entry(f"flagged-{tag}", self.FLAGGED), self.flagged[tag]
            described, imp = bool(f["Description"].strip()), contract.cve_impact([f])
            lines = calls.load(verdicts.run_dir(folder))[-1].text("human").split("\n")
            block = lines[lines.index("QUESTIONS") + 1:]
            fields = [ln.partition(":")[0] for ln in block[:block.index("")]]
            self.assertEqual(fields, contract.adjustment_fields(sc["dep"], imp, described), tag)
            self.assertEqual(fields, ["opportunity", "confidentiality"] if described else ["confidentiality"])
            self.assertEqual(e["adjustment"], "answered", tag)
            answered, adjusted = given(e)
            self.assertEqual(written(e), contract.c1c2_levels(sc["dep"], imp, described, answered, adjusted,
                                                              contract.C1C2P), tag)
            rec = attempt.read_attempt(folder, rules=contract.C1C2P)
            self.assertEqual((rec["scores_usable"], rec["answers"]["problems"], rec["calls"]["kinds"][-1]),
                             (True, [], "adjustment"), tag)


def campaign(root, name, after, commit):
    """ctx_runner.py on the eight showcase and reachability scenarios, the before at main 43ab10b, two replicates."""
    camp = os.path.join(root, name)
    argv = ["--campaign", name, "--out", camp, "--before", s.env("VB_VENS_BEFORE"), "--before-commit", s.BEFORE_SHA,
            "--after", after, "--after-commit", commit, "--model", "mock/mock", "--replicates", "2",
            "--retry-cap", "2", "--timeout", "120", "--parallel", "4"]
    argv += [x for sid in SHOWCASES_AND_REACH for x in ("--scenario", sid)]
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        code = ctx_runner.main(argv, environ={"PATH": os.environ.get("PATH", ""), "HOME": root})
    if code != 0:
        raise AssertionError(f"the runner exited {code}")
    return camp


def analyze(camp, *argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ctx_analyze.main([*argv, camp])
    return code, out.getvalue(), err.getvalue()


class TestTheCampaignOnTheMock(unittest.TestCase):
    """The eight showcase and reachability scenarios through ctx_runner.py, the before at main and the after at the
    C2' commit, two replicates, read by the chain under c1c2p; N's campaign beside it."""

    @classmethod
    def setUpClass(cls):
        cls.after, cls.n = s.env("VB_VENS_C1C2P"), s.env("VB_VENS_C1C2")
        if cls.after is None or s.env("VB_VENS_BEFORE") is None:
            raise unittest.SkipTest("set VB_VENS_C1C2P and VB_VENS_BEFORE to run a C1 + C2' campaign on the mock")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.camp = campaign(cls.tmp.name, "c1c2p", cls.after, contract.C2P_COMMIT)
        cls.n_camp = campaign(cls.tmp.name, "c1c2", cls.n, contract.N_COMMIT) if cls.n else None
        cls.code, cls.text, cls.err = analyze(cls.camp, "--rules", "c1c2p")
        cls.records = list(read.read_any(cls.camp, rules=contract.C1C2P))
        cls.rows = families.evaluate(cellmod.group(cls.records), verdicts.load(os.path.join(cls.camp, "scenarios")),
                                     rules=contract.C1C2P)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_pinned_contract(self):
        # the C2' commit pins c1c2p: the same report as --rules c1c2p
        code, text, err = analyze(self.camp, "--commit", f"after={contract.C2P_COMMIT}")
        self.assertEqual((code, err, text), (0, "", self.text))
        code, _, err = analyze(self.camp, "--rules", "c1c2p", "--commit", f"after={contract.N_COMMIT}")
        self.assertEqual(code, 1)
        self.assertIn("--rules c1c2p, but --commit after= pins c1c2", err)
        # c1c2 pinned on the C2' commit's runs: the reader refuses each answers.json, the gate stops a go
        for rules in (contract.C1C2, contract.B7C0435):
            after = [r for r in read.read_any(self.camp, rules=rules) if r["what"]["arm"] == "after"]
            self.assertEqual({(r["scores_usable"], tuple(r["answers"]["problems"])) for r in after},
                             {(False, (f"answers.json follows c1c2p, not the pinned {rules}",))})
        code, _, err = analyze(self.camp, "--rules", "c1c2")
        self.assertEqual(code, 1)
        self.assertIn("C1 + C2's implementation gate: 8 failure(s), no go:", err)
        self.assertEqual(err.count("refused by the reader: answers.json follows c1c2p, not the pinned c1c2"), 16)

    def test_the_report(self):
        self.assertEqual((self.code, self.err), (0, ""))
        self.assertIn("## C1 + C2' recomputed on every after run", self.text)
        self.assertIn("The after's contract pinned: c1c2p, no reachability relay.", self.text)
        self.assertIn("C1 + C2''s implementation gate: pass.", self.text)
        self.assertIn("Under C1 + C2' (rules c1c2p, no reachability relay), each after scenario", self.text)
        self.assertIn("Implementation checks (plan Z0, every replicate; binding): 8 pass, 0 fail, 0 inconclusive",
                      self.text)
        self.assertEqual(self.text.count(": pass; 2 run(s) of 2 replicate(s), 2 CVE(s), 0 off their recomputation, "
                                         "0 CVE(s) holding a status or a declared block."), 8)
        first = self.text.split("\n## ")[1]
        self.assertTrue(first.startswith("What C2 reads of the reports"), first[:80])
        self.assertIn(f"- {contract.counts_line('scenarios', SCENARIO_COUNTS)}.", first)
        self.assertIn("| showcase_med_to_high high or critical | after | carried | c1c2p · mock/mock |", self.text)
        self.assertIn("| showcase_high_to_low low, the notes alone | after | diagnostic | c1c2p · mock/mock |",
                      self.text)
        self.assertIn("- showcase_med_to_high high or critical · showcase_med_to_high · c1c2p · mock/mock: the "
                      "before passes", self.text)
        self.assertEqual(self.text.count("Withdrawn, not met (plan Z0d): #333's expected low"), 2)

    def test_the_rows(self):
        self.assertEqual({r["rules"] for r in self.rows}, {contract.C1C2P})
        self.assertTrue(all(r["certified"] for r in self.rows))
        kinds = {(r["check"].label, r["arm"]): r["kind"] for r in self.rows
                 if r["check"].family in ("showcases", "reachability")}
        self.assertEqual({k for k, kind in kinds.items() if kind != verdicts.DIAGNOSTIC},
                         {("showcase_med_to_high high or critical", "before"),
                          ("showcase_med_to_high high or critical", "after")})
        self.assertTrue(all(label.endswith(verdicts.NOTES) for (label, _), kind in kinds.items()
                            if kind == verdicts.DIAGNOSTIC))

    def test_the_after_runs_follow_c1c2p(self):
        after = [r for r in self.records if r["what"]["arm"] == "after"]
        self.assertEqual(len(after), 16)
        for rec in after:
            self.assertEqual((rec["scores_usable"], rec["answers"]["problems"], families.run_rules(rec)),
                             (True, [], contract.C1C2P), rec["folder"])
            self.assertEqual(conform.statuses(rec), [], rec["folder"])
            self.assertEqual({vid: c2_counters(e) for vid, e in rec["answers"]["per_cve"].items()},
                             {vid: [AR] for vid in rec["ratings"]}, rec["folder"])
            self.assertEqual(rec["answers"]["counters"].get(AR), 1, rec["folder"])
        self.assertTrue(glob.glob(os.path.join(self.camp, "**", "after-a1"), recursive=True))

    def test_ns_campaign_under_each_contract(self):
        if self.n_camp is None:
            self.skipTest("set VB_VENS_C1C2 to run N's campaign beside")
        code, text, err = analyze(self.n_camp, "--commit", f"after={contract.N_COMMIT}")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("C1 + C2's implementation gate: pass.", text)
        self.assertIn("Implementation checks (plan Z0, every replicate; binding): 8 pass, 0 fail, 0 inconclusive", text)
        # read under c1c2p, N's records are ones C1 + C2' could give, but not on these configs: the counter is missing
        code, _, err = analyze(self.n_camp, "--rules", "c1c2p")
        self.assertEqual(code, 1)
        self.assertIn("C1 + C2''s implementation gate: 8 failure(s), no go:", err)
        self.assertEqual(err.count(f"{AR} counted 0 times, not 1"), 16)


if __name__ == "__main__":
    unittest.main()
