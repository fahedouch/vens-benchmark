"""The reader on vens's own mock LLM at both commits: complete attempts, the failed attempts VENS_MOCK_LLM_SKIP and
VENS_MOCK_LLM_FAIL leave, the demo scan's skipped CVE at batch 1 and 10, the attempt record laid out from mock runs,
and the Java run end to end. No model is called and vens gets no API key."""
import contextlib
import glob
import io
import json
import os
import shutil
import tempfile
import unittest

from chain import attempt, javarun, runvens
from tests import support as s

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS = os.path.join(ROOT, "scenarios")
FIRST = sorted(d for d in os.listdir(SCENARIOS) if os.path.isdir(os.path.join(SCENARIOS, d)))[0]
SKIPPED = "model returned no answer to Motive (M) for {cve} after asking again; stopping the run"
SKIPPED_BEFORE = "model returned no score for {cve} after asking again; stopping the run"
FORCED = "LLM evaluation failed: mockllm: forced failure (VENS_MOCK_LLM_FAIL is set)"


class MockRuns(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.after, cls.before = s.env("VB_VENS_AFTER"), s.env("VB_VENS_BEFORE")
        if cls.after is None or cls.before is None:
            raise unittest.SkipTest("set VB_VENS_AFTER and VB_VENS_BEFORE to vens binaries built from fa7fc9a and "
                                    "43ab10b to run the mock tests")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = cls.tmp.name
        cls.report = os.path.join(SCENARIOS, FIRST, "report.json")
        cls.config = runvens.add_marker(os.path.join(SCENARIOS, FIRST, "config.yaml"),
                                        os.path.join(cls.dir, "config.yaml"))
        with open(cls.report) as fh:
            cls.cve = json.load(fh)["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"]
        cls.runs = {}
        for arm in ("after", "before"):
            for tag, extra in (("complete", {}), ("skip", {"VENS_MOCK_LLM_SKIP": cls.cve}),
                               ("fail", {"VENS_MOCK_LLM_FAIL": "1"})):
                cls.runs[(arm, tag)] = cls.mock_run(arm, tag, cls.config, cls.report, extra)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def mock_run(cls, arm, tag, config, report, extra, batch=1):
        folder = os.path.join(cls.dir, f"{arm}-{tag}")
        binary = cls.after if arm == "after" else cls.before
        runvens.generate(binary, config, report, folder, record={"arm": arm}, batch=batch, env_extra=extra)
        return folder


class TestMockAttempts(MockRuns):
    def test_complete_attempts(self):
        for arm, calls in (("after", 11), ("before", 1)):
            rec = attempt.read_attempt(self.runs[(arm, "complete")])
            self.assertEqual((rec["outcome"], rec["scores_usable"], rec["problems"]), ("complete", True, []), arm)
            self.assertEqual(rec["models_attested"], [["mock", "mock"]] * calls)
            self.assertEqual((rec["recovery"]["planned"], rec["recovery"]["recovery_calls"]), (calls, 0))
            self.assertEqual(set(rec["calls"]["kinds"]), {"planned"})
        rec = attempt.read_attempt(self.runs[("after", "complete")])
        self.assertEqual((rec["answers"]["rated"], rec["answers"]["problems"]), (1, []))
        entry = rec["answers"]["per_cve"][self.cve]
        self.assertEqual(sorted(entry["counters"]), sorted(rec["summary"]["counters"]))
        self.assertEqual({f["source"] for f in entry["factors"].values()} - {"answer", "constant", "config", "floor",
                                                                             "adjustment"}, set())

    def test_skip_leaves_a_failed_attempt(self):
        for arm, cause in (("after", SKIPPED), ("before", SKIPPED_BEFORE)):
            rec = attempt.read_attempt(self.runs[(arm, "skip")])
            self.assertEqual(rec["failure"], {"kind": "scoring", "step": "generate", "cause_source": "vens log",
                                              "cause": "failed to generate risk scores: " + cause.format(cve=self.cve)})
            summ = rec["summary"]
            self.assertEqual((summ["failed"], summ["llm_calls"], summ["asked_again"], summ["splits"]), (True, 2, 1, 0))
            self.assertEqual((rec["calls"]["archived"], rec["calls"]["with_reply"]), (2, 2))
            self.assertEqual((rec["recovery"]["planned"], rec["recovery"]["again_omission"],
                              rec["recovery"]["recovery_calls"]), (1, 1, 1))
            self.assertIsNone(rec["ratings"])
            self.assertEqual(rec["incomplete"], [])
        after = attempt.read_attempt(self.runs[("after", "skip")])
        self.assertEqual((after["answers"]["rated"], after["answers"]["unrated"], after["answers"]["defects"]),
                         (0, 0, {}))
        self.assertIsNone(attempt.read_attempt(self.runs[("before", "skip")])["answers"])

    def test_fail_leaves_a_failed_attempt(self):
        for arm in ("after", "before"):
            rec = attempt.read_attempt(self.runs[(arm, "fail")])
            self.assertEqual(rec["failure"]["cause"], "failed to generate risk scores: " + FORCED)
            self.assertEqual((rec["summary"]["llm_calls"], rec["calls"]["archived"], rec["calls"]["with_reply"]),
                             (1, 1, 0))
            self.assertEqual(rec["recovery"]["recovery_calls"], 0)


class TestTheRecordFromMockRuns(MockRuns):
    """The attempt record as baseline.yml writes it, laid out from the mock's own runs."""

    def artefact(self, source, name, record, provenance=True):
        folder = os.path.join(self.dir, "downloads", "2001", f"baseline-mock-internal-r1-a{name}")
        shutil.copytree(os.path.join(source, "calls"), os.path.join(folder, "calls"))
        for src, dst in (("vex.cdx.json", "vex-internal.cdx.json"),
                         ("vex.attestation.cdx.json", "vex-internal.attestation.cdx.json"),
                         ("vens.log", "vens-internal.log")):
            if os.path.exists(os.path.join(source, src)):
                shutil.copy(os.path.join(source, src), os.path.join(folder, dst))
        with open(os.path.join(source, "attempt.json")) as fh:
            gen = json.load(fh)["generate"]
        base = {"provider": "mock", "model": "mock", "llm_batch_size": 1, "vens_ref": s.AFTER_SHA,
                "vens_sha": s.AFTER_SHA, "run_id": 2001, "run_attempt": int(name)}
        if provenance:
            s.write(os.path.join(folder, "provenance.json"), {**base, "context": "contexts/internal.yaml",
                                                              "replicate": 1})
        if record is not None:
            s.write(os.path.join(folder, "attempt.json"),
                    {"record": 1, "runner": "baseline.yml", "arm": "after", **base, "job": "internal · run 1",
                     "context": "internal", "replicate": 1, "generate": gen, **record})
        return folder

    def test_a_complete_attempt(self):
        record = {k: v for k, v in s.COMPLETE_RECORD.items() if k != "generate"}
        rec = attempt.read_attempt(self.artefact(self.runs[("after", "complete")], "1", record))
        self.assertEqual((rec["outcome"], rec["scores_usable"], rec["problems"]), ("complete", True, []))

    def test_an_enrichment_that_fails(self):
        record = {"enrich": {"exit_status": 1}, "archive_check": "skipped", "provenance": False}
        rec = attempt.read_attempt(self.artefact(self.runs[("after", "complete")], "2", record, provenance=False))
        self.assertEqual((rec["failure"]["kind"], rec["failure"]["step"]), ("later_step", "enrich"))
        self.assertEqual((rec["calls"]["archived"], rec["scores_usable"]), (11, False))

    def test_an_archive_check_that_fails(self):
        record = {"enrich": {"exit_status": 0}, "archive_check": "failure", "provenance": False}
        rec = attempt.read_attempt(self.artefact(self.runs[("after", "complete")], "3", record, provenance=False))
        self.assertEqual((rec["failure"]["kind"], rec["failure"]["step"]), ("later_step", "archive_check"))

    def test_a_scoring_that_fails(self):
        record = {"enrich": None, "archive_check": "skipped", "provenance": False}
        rec = attempt.read_attempt(self.artefact(self.runs[("after", "skip")], "4", record, provenance=False))
        self.assertEqual((rec["failure"]["kind"], rec["failure"]["cause"]),
                         ("scoring", "failed to generate risk scores: " + SKIPPED.format(cve=self.cve)))

    def test_a_download_made_before_the_record(self):
        rec = attempt.read_attempt(self.artefact(self.runs[("after", "complete")], "5", None), arm="after")
        self.assertEqual((rec["record"], rec["outcome"]), (None, "complete"))
        self.assertIn("generate.started_at", rec["unknown"])
        self.assertIn("generate.exit_status", rec["implied"])

    def test_a_run_without_answers_json_is_an_incomplete_record(self):
        record = {k: v for k, v in s.COMPLETE_RECORD.items() if k != "generate"}
        folder = self.artefact(self.runs[("after", "complete")], "6", record)
        (answers,) = glob.glob(os.path.join(folder, "calls", "run-*", "answers.json"))
        os.remove(answers)
        rec = attempt.read_attempt(folder)
        self.assertEqual(rec["incomplete"], ["a complete run's VEX without its answers.json"])


class TestTheDemoScan(MockRuns):
    """The demo scan, internet-facing, its third CVE in scanner order skipped (a CVE a row describes)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.demo = s.env("VB_DEMO")
        if cls.demo is None:
            raise unittest.SkipTest("set VB_DEMO to a vens-demo tree at 7ab1570 to run the demo-scan tests")
        cls.scan = os.path.join(cls.demo, javarun.DEMO_SCAN)
        cls.ctx = runvens.add_marker(os.path.join(cls.demo, "contexts", "internet-facing.yaml"),
                                     os.path.join(cls.dir, "internet-facing.yaml"))
        with open(cls.scan) as fh:
            rows = [v for r in json.load(fh).get("Results") or [] for v in r.get("Vulnerabilities") or []]
        order = list(dict.fromkeys(v["VulnerabilityID"] for v in rows))
        described = {v["VulnerabilityID"] for v in rows if (v.get("Description") or "").strip()}
        cls.skipped = next(order[i] for i in range(2, len(order)) if order[i] in described)
        for batch in (1, 10):
            cls.mock_run("after", f"demo-b{batch}", cls.ctx, cls.scan, {"VENS_MOCK_LLM_SKIP": cls.skipped}, batch=batch)

    def test_batch_1(self):
        rec = attempt.read_attempt(os.path.join(self.dir, "after-demo-b1"))
        self.assertEqual((rec["summary"]["llm_calls"], rec["recovery"]["planned"], rec["recovery"]["recovery_calls"]),
                         (18, 17, 1))
        self.assertEqual((rec["answers"]["rated"], rec["answers"]["unrated"]), (2, 0))
        self.assertNotIn(self.skipped, rec["answers"]["per_cve"])

    def test_batch_10(self):
        rec = attempt.read_attempt(os.path.join(self.dir, "after-demo-b10"))
        self.assertEqual((rec["summary"]["llm_calls"], rec["summary"]["asked_again"]), (2, 1))
        self.assertEqual((rec["answers"]["rated"], rec["answers"]["unrated"], rec["answers"]["problems"]), (0, 8, []))
        per_cve = rec["answers"]["per_cve"]
        self.assertTrue(all(e["unrated"] for e in per_cve.values()))
        self.assertEqual({tuple(e["factors"]) for e in per_cve.values()}, {("M",)})
        self.assertTrue(all(e["factors"]["M"]["level"] is None and e["factors"]["M"]["source"] is None
                            for e in per_cve.values()))
        self.assertNotIn(self.skipped, per_cve)


class TestTheJavaRun(MockRuns):
    def test_the_java_run_end_to_end(self):
        demo, quick, jar = s.env("VB_DEMO"), s.env("VB_QUICKSTART"), s.env("VB_JAR")
        if None in (demo, quick, jar):
            self.skipTest("set VB_DEMO, VB_QUICKSTART and VB_JAR to run the Java run end to end")
        out = os.path.join(self.dir, "java-run")
        with contextlib.redirect_stdout(io.StringIO()):
            code = javarun.main(["--vens", self.after, "--commit", s.AFTER_SHA, "--scenarios", SCENARIOS, "--demo",
                                 demo, "--quickstart", quick, "--jar", jar, "--out", out, "--before", self.before,
                                 "--before-commit", s.BEFORE_SHA])
        archive = os.path.join(out, "archive")
        with open(os.path.join(archive, "java-check.txt")) as fh:
            text = fh.read()
        self.assertEqual(code, 0, text[-2000:])
        self.assertIn("Check4: every label passes", text)
        self.assertIn("unexpected 0", text)
        self.assertIn("problems 0", text)
        self.assertIn("not read 0", text)
        files = sorted(os.path.relpath(os.path.join(d, f), archive) for d, _, names in os.walk(archive) for f in names)
        self.assertEqual({os.path.basename(f) for f in files},
                         {"vex.cdx.json", "answers.json", "java-check.txt", "manifest.json", "SHA256SUMS"})
        self.assertEqual(sum(f.endswith("vex.cdx.json") for f in files), 35 + 3 + 2 + 35 + 3)
        self.assertEqual(sum(f.endswith("answers.json") for f in files), 35 + 3 + 2)
        self.assertFalse(any("calls" in f.split(os.sep) for f in files))
        with open(os.path.join(archive, "SHA256SUMS")) as fh:
            sums = dict(reversed(line.rstrip("\n").split("  ", 1)) for line in fh)
        self.assertEqual(sorted(sums), [f for f in files if f != "SHA256SUMS"])
        self.assertTrue(all(runvens.sha256(os.path.join(archive, p)) == h for p, h in sums.items()))
        for name in ("manifest.json", "java-check.txt"):
            with open(os.path.join(archive, name)) as fh:
                content = fh.read()
            self.assertNotIn(self.dir, content)
            self.assertNotIn(os.path.expanduser("~"), content)
        with open(os.path.join(archive, "manifest.json")) as fh:
            manifest = json.load(fh)
        self.assertEqual(manifest["vens"]["after"]["commit"], s.AFTER_SHA)
        self.assertEqual(manifest["vens"]["before"]["binary_sha256"], runvens.sha256(self.before))
        self.assertIn("vens-demo/runs/2026-09-23/scan/scan.json", manifest["inputs"])
        self.assertEqual(manifest["unexpected"], 0)


if __name__ == "__main__":
    unittest.main()
