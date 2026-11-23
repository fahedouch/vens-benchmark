"""C1 + C2 against vens 310-c1c2 2de5d34 itself, on its mock LLM, no model and no API key:

- the demo scan: the chain's C2 counts equal what vens's Go tests freeze for it (VB_VENS_C1C2_SRC), and per CVE the
  levels, sources, CVSS values, Privacy violation's floors and cvss_v3_missing vens writes in each demo context
  (VB_VENS_C1C2, VB_DEMO);
- every scenario: each call's question, every level and source, and a system prompt byte for byte b7c0435's on step 5's
  corpus (VB_VENS_AFTER); the four no-fixtures publishing their declared status with the rating the same answers give
  on their config without the entry; a flagged copy, described and not, through the adjustment;
- a scenario campaign through ctx_runner.py on the eight showcase and reachability scenarios, both arms
  (VB_VENS_BEFORE), read by ctx_analyze.py: the families' status checks, plan Z0's every replicate and read5's
  eligibility rule.
"""
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
from chain import attempt, calls, cdx, contract, families, read, runvens, verdicts
from chain import cells as cellmod
from tests import support as s

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS = os.path.join(ROOT, "scenarios")
IDS = sorted(d for d in os.listdir(SCENARIOS) if os.path.isdir(os.path.join(SCENARIOS, d)))
NO_FIXTURES = ("reach_no", "reach2_no", "reach3_no", "showcase_high_to_low")
YES_FIXTURES = ("reach_yes", "reach2_yes", "reach3_yes", "showcase_med_to_high")
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


def answers_entries(folder):
    with open(os.path.join(verdicts.run_dir(folder), "answers.json"), encoding="utf-8") as fh:
        return {e["vulnId"]: e for e in json.load(fh)["vulnerabilities"]}


def given(e):
    """An answers.json entry's answers and adjustment as chain.contract.c1c2_levels takes them."""
    fs = {x["factor"]: x for x in e["factors"]}
    return ({f: x["answer"] for f, x in fs.items() if "answer" in x},
            {f: fs[f].get("adjusted") for f in ("O", "PV") if f in fs})


def written(e):
    return {x["factor"]: (x["level"], x["source"]) for x in e["factors"]}


class TestTheDemoScan(unittest.TestCase):
    """The chain's C2 counts and per-CVE reading of the demo scan against vens 2de5d34's."""

    @classmethod
    def setUpClass(cls):
        demo = s.env("VB_DEMO")
        if demo is None:
            raise unittest.SkipTest("set VB_DEMO to a vens-demo tree at 7ab1570 to read the demo scan")
        cls.demo, cls.scan = demo, os.path.join(demo, DEMO_SCAN)
        cls.cves = contract.report_cves(cls.scan)

    def test_the_counts(self):
        self.assertEqual(runvens.sha256(self.scan), DEMO_SHA)
        self.assertEqual(contract.impact_counts(self.cves), DEMO_COUNTS)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            contract.main(["--demo", self.scan, "--scenarios", SCENARIOS])
        self.assertEqual(out.getvalue().splitlines(), [contract.counts_line("demo scan", DEMO_COUNTS),
                                                       contract.counts_line("scenarios", SCENARIO_COUNTS)])

    def test_the_counts_vens_go_tests_freeze(self):
        (src,) = s.need(self, "VB_VENS_C1C2_SRC")
        with open(os.path.join(src, "pkg", "scanner", "reports_test.go"), encoding="utf-8") as fh:
            m = GO_COUNTS.search(fh.read())
        self.assertIsNotNone(m)
        with gzip.open(os.path.join(src, "pkg", "scanner", "testdata", "vens-demo-2026-09-23.trivy.json.gz")) as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), m["sha"])
        self.assertEqual(m["sha"], DEMO_SHA)
        got = contract.impact_counts(self.cves)
        self.assertEqual({k: int(m[k]) for k in GO_KEYS}, {k: got[k] for k in GO_KEYS})

    def test_per_cve_against_what_vens_writes(self):
        (binary,) = s.need(self, "VB_VENS_C1C2")
        with tempfile.TemporaryDirectory() as tmp:
            for ctx in ("internet-facing", "internal", "internal-api"):
                config = runvens.add_marker(os.path.join(self.demo, "contexts", f"{ctx}.yaml"),
                                            os.path.join(tmp, ctx, "config.yaml"))
                folder = os.path.join(tmp, ctx, "run")
                rec = runvens.generate(binary, config, self.scan, folder, record={"arm": "after"}, batch=10)
                self.assertEqual(rec["generate"]["exit_status"], 0, ctx)
                with open(config, encoding="utf-8") as fh:
                    dep = contract.deployment(yaml.safe_load(fh))
                entries = answers_entries(folder)
                self.assertEqual(sorted(entries), sorted(self.cves), ctx)
                floors, vectorless = set(), set()
                for vid, e in entries.items():
                    imp, fs = contract.cve_impact(self.cves[vid]), {x["factor"]: x for x in e["factors"]}
                    described = any((f.get("Description") or "").strip() for f in self.cves[vid])
                    for f in contract.AXIS:
                        self.assertEqual((fs[f]["level"], fs[f]["source"], fs[f].get("cvss")),
                                         (contract.impact_level(f, dep, imp), "cvss", imp.values.get(contract.AXIS[f])),
                                         (ctx, vid, f))
                    floors |= {vid} if fs["PV"]["source"] == "floor" else set()
                    vectorless |= {vid} if "cvss_v3_missing" in e.get("counters", []) else set()
                    answered, adjusted = given(e)
                    self.assertEqual(sorted(answered), sorted(contract.c1c2_questions(dep, imp, described)),
                                     (ctx, vid))
                    self.assertEqual(written(e), contract.c1c2_levels(dep, imp, described, answered, adjusted),
                                     (ctx, vid))
                self.assertEqual(floors, {v for v, fs in self.cves.items()
                                          if contract.privacy_floored(contract.cve_impact(fs))}, ctx)
                self.assertEqual(vectorless, {v for v, fs in self.cves.items()
                                              if contract.cve_impact(fs).usable == 0}, ctx)
                self.assertEqual((len(floors), len(vectorless)), (28, 10), ctx)
                got = attempt.read_attempt(folder)
                self.assertEqual((got["scores_usable"], got["problems"], got["answers"]["problems"]), (True, [], []))


class TestTheScenariosOnTheMock(unittest.TestCase):
    """Every scenario on vens 2de5d34's mock, as answered and with every answer cannot_tell, b7c0435 beside it on step
    5's corpus, the no-fixtures again without their entry, and two flagged copies."""

    FLAGGED = "crit_critical"
    DISPUTE = " Fixed in 2.0. The maintainer disputes this report."
    # The undescribed copy is flagged severity_contested: its row LOW from another source, NVD's CRITICAL.
    UNDESCRIBED = {"Description": "", "Severity": "LOW", "SeveritySource": "debian"}

    @classmethod
    def setUpClass(cls):
        cls.binary, cls.b7c0435 = s.env("VB_VENS_C1C2"), s.env("VB_VENS_AFTER")
        if cls.binary is None:
            raise unittest.SkipTest("set VB_VENS_C1C2 to a vens binary built from 310-c1c2 2de5d34")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.scen = verdicts.load(SCENARIOS, contract.C1C2)
        cls.runs = {}
        step5 = s.step5_scenarios()
        for tag, root, sids, extra in (("after", SCENARIOS, IDS, None),
                                       ("cannot_tell", SCENARIOS, IDS, {"VENS_MOCK_LLM_CANNOT_TELL": "cannot_tell"}),
                                       ("without_entry", step5, NO_FIXTURES, None)):
            for sid in sids:
                d = os.path.join(root, sid)
                cls.generate(tag, sid, os.path.join(d, "config.yaml"), os.path.join(d, "report.json"), extra)
        if cls.b7c0435 is not None:
            for sid in IDS:
                d = os.path.join(step5, sid)
                cls.generate("b7c0435", sid, os.path.join(d, "config.yaml"), os.path.join(d, "report.json"),
                             binary=cls.b7c0435)
        cls.flagged = {}
        with open(os.path.join(SCENARIOS, cls.FLAGGED, "report.json"), encoding="utf-8") as fh:
            report = json.load(fh)
        original = report["Results"][0]["Vulnerabilities"][0]
        for tag, f in (("described", {**original, "Description": original["Description"] + cls.DISPUTE}),
                       ("undescribed", {**original, **cls.UNDESCRIBED})):
            doc = {**report, "Results": [{**report["Results"][0], "Vulnerabilities": [f]}]}
            path = s.write(os.path.join(cls.tmp.name, f"flagged-{tag}.json"), doc)
            cls.flagged[tag] = f
            cls.generate(f"flagged-{tag}", cls.FLAGGED, os.path.join(SCENARIOS, cls.FLAGGED, "config.yaml"), path)

    @classmethod
    def generate(cls, tag, sid, config, report, extra=None, binary=None):
        folder = os.path.join(cls.tmp.name, tag, sid)
        rec = runvens.generate(binary or cls.binary, config, report, folder, record={"arm": "after"},
                               env_extra=extra)
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

    def test_every_run_completes_and_reads(self):
        for (tag, sid), (folder, code) in self.runs.items():
            self.assertEqual(code, 0, (tag, sid))
            if tag == "b7c0435":
                continue
            rec = attempt.read_attempt(folder)
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

    def test_the_levels_and_sources_vens_wrote(self):
        for tag in ("after", "cannot_tell"):
            for sid in IDS:
                sc, e = self.scen[sid], self.entry(tag, sid)
                answered, adjusted = given(e)
                if tag == "cannot_tell":
                    self.assertEqual(set(answered.values()) - {contract.CANNOT_TELL}, set(), sid)
                self.assertEqual(written(e), contract.c1c2_levels(sc["dep"], sc["impact"], sc["described"], answered,
                                                                  adjusted), (tag, sid))
                fs = {x["factor"]: x for x in e["factors"]}
                self.assertEqual({f: fs[f].get("cvss") for f in contract.AXIS},
                                 {f: sc["impact"].values.get(contract.AXIS[f]) for f in contract.AXIS}, sid)
                self.assertEqual("cvss_v3_missing" in e.get("counters", []), sc["impact"].usable == 0, sid)

    def test_the_system_prompt_is_b7c0435s(self):
        if self.b7c0435 is None:
            self.skipTest("set VB_VENS_AFTER to a vens binary built from b7c0435 to compare the system prompts")
        for sid in IDS:
            then = {c.system for c in calls.load(verdicts.run_dir(self.runs[("b7c0435", sid)][0]))}
            now = {c.system for c in calls.load(verdicts.run_dir(self.runs[("after", sid)][0]))}
            self.assertEqual((len(then), now), (1, then), sid)

    def test_the_no_fixtures_publish_their_declared_status(self):
        for sid in NO_FIXTURES:
            with open(os.path.join(SCENARIOS, sid, "config.yaml"), encoding="utf-8") as fh:
                (entry,) = contract.declarations(yaml.safe_load(fh))
            r, e = self.vex("after", sid), self.entry("after", sid)
            self.assertEqual(verdicts.status_tuple(r["analysis"]), self.scen[sid]["status"], sid)
            self.assertEqual((r["analysis"]["state"], r["analysis"]["justification"]),
                             ("not_affected", "code_not_reachable"), sid)
            self.assertIn(f"reachability[0] ({contract.selector(entry)}). Provenance: {entry['provenance']}",
                          r["analysis"]["detail"])
            self.assertEqual(e["declared"], {"unreachable": [0], "analysis": r["analysis"]}, sid)
        for sid in set(IDS) - set(NO_FIXTURES):
            self.assertIsNone(self.vex("after", sid)["analysis"], sid)
            self.assertNotIn("declared", self.entry("after", sid), sid)

    def test_the_rating_is_the_one_without_the_entry(self):
        for sid in NO_FIXTURES:
            now, then = self.vex("after", sid), self.vex("without_entry", sid)
            self.assertEqual((now["vector"], now["score"], now["severity"]),
                             (then["vector"], then["score"], then["severity"]), sid)
            self.assertIsNone(then["analysis"], sid)
            self.assertEqual(given(self.entry("after", sid)), given(self.entry("without_entry", sid)), sid)

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
            self.assertEqual(written(e), contract.c1c2_levels(sc["dep"], imp, described, answered, adjusted), tag)
            rec = attempt.read_attempt(folder)
            self.assertEqual((rec["scores_usable"], rec["answers"]["problems"], rec["calls"]["kinds"][-1]),
                             (True, [], "adjustment"), tag)


class TestTheCampaignOnTheMock(unittest.TestCase):
    """The eight showcase and reachability scenarios through ctx_runner.py, the before at main and the after at
    2de5d34, two replicates, read by the chain."""

    @classmethod
    def setUpClass(cls):
        cls.after, cls.before = s.env("VB_VENS_C1C2"), s.env("VB_VENS_BEFORE")
        if cls.after is None or cls.before is None:
            raise unittest.SkipTest("set VB_VENS_C1C2 and VB_VENS_BEFORE to run a C1 + C2 campaign on the mock")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.camp = os.path.join(cls.tmp.name, "c1c2")
        argv = ["--campaign", "c1c2", "--out", cls.camp, "--before", cls.before, "--before-commit", s.BEFORE_SHA,
                "--after", cls.after, "--after-commit", s.C1C2_SHA, "--model", "mock/mock", "--replicates", "2",
                "--retry-cap", "2", "--timeout", "120", "--parallel", "4"]
        argv += [x for sid in NO_FIXTURES + YES_FIXTURES for x in ("--scenario", sid)]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = ctx_runner.main(argv, environ={"PATH": os.environ.get("PATH", ""), "HOME": cls.tmp.name})
        if code != 0:
            raise AssertionError(f"the runner exited {code}")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            cls.code = ctx_analyze.main([cls.camp])
        cls.text, cls.err = out.getvalue(), err.getvalue()
        cls.records = list(read.read_any(cls.camp))
        cls.rows = families.evaluate(cellmod.group(cls.records), verdicts.load(os.path.join(cls.camp, "scenarios")))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def row(self, label, arm, item):
        (x,) = [r for r in self.rows if (r["check"].label, r["arm"], r["row"]["item"]) == (label, arm, item)]
        return x

    def test_the_report(self):
        self.assertEqual((self.code, self.err), (0, ""))
        first = self.text.split("\n## ")[1]
        self.assertTrue(first.startswith("What C2 reads of the reports"), first[:80])
        self.assertIn(f"- {contract.counts_line('scenarios', SCENARIO_COUNTS)}.", first)
        for label in (verdicts.REACH_STATUS, verdicts.SHOWCASE_STATUS[0].label, verdicts.SHOWCASE_STATUS[1].label,
                      "showcase_med_to_high publishes no not_affected"):
            self.assertIn(f"| {label} | after | implementation | c1c2 · mock/mock |", self.text)
        self.assertIn("every replicate: pass (pass 2 of 2)", self.text)
        self.assertNotIn("every replicate: fail", self.text)
        self.assertIn(f"- {verdicts.REACH_STATUS} · reach_no / reach_yes · c1c2 · mock/mock: the before passes "
                      f"0.00, the after fails 0.00: not gated.", self.text)

    def test_the_rows(self):
        self.assertEqual({r["rules"] for r in self.rows}, {contract.C1C2})
        self.assertTrue(all(r["certified"] for r in self.rows))
        for item in verdicts.REACH:
            self.assertEqual(families.every_replicate(self.row(verdicts.REACH_STATUS, "after", item)["row"]), "pass")
            self.assertEqual([p["ok"] for p in self.row(verdicts.REACH_STATUS, "before", item)["row"]["per"]],
                             [False, False])
        for label in (verdicts.SHOWCASE_STATUS[0].label, verdicts.SHOWCASE_STATUS[1].label):
            self.assertEqual(families.every_replicate(self.row(label, "after", "showcase_high_to_low")["row"]), "pass")
        med = self.row("showcase_med_to_high publishes no not_affected", "after", "showcase_med_to_high")
        self.assertEqual(families.every_replicate(med["row"]), "pass")
        gates = families.gates(self.rows)
        self.assertEqual({k[2]: v[2] for k, v in gates.items() if k[1] == verdicts.REACH_STATUS},
                         {item: "not gated" for item in verdicts.REACH})

    def test_the_after_runs_follow_c1c2(self):
        after = [r for r in self.records if r["what"]["arm"] == "after"]
        self.assertEqual(len(after), 16)
        for rec in after:
            self.assertEqual((rec["scores_usable"], rec["answers"]["problems"], families.run_rules(rec)),
                             (True, [], contract.C1C2), rec["folder"])
        self.assertTrue(glob.glob(os.path.join(self.camp, "**", "after-a1"), recursive=True))


if __name__ == "__main__":
    unittest.main()
