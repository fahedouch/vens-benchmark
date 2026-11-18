"""The analysis end to end: one command from the readers' input through every statistic.

- Always: synthetic baseline.yml downloads of both arms and a usage export, through ctx_analyze.py.
- VB_0B_MEASUREMENTS: on 0B's phase-2 downloads, the within-model MPD, Delta and the W and H figures
  read0b-phase2.out prints, read through the chain's reader; on phase 1's downloads, failed jobs and a replicate
  that never completed among them, the whole report.
- VB_R2: R2's two real-model runs (one replicate per arm, gpt-5.4-mini-2026-03-17), the after-ref and the before-ref
  downloads with their dispatch log; VB_DEMO adds the scan, VB_JAR and a JDK the Java check, VB_0A_DRAWS the
  CVE ids earlier draws used.
- VB_VENS_AFTER and VB_VENS_BEFORE: a scenario campaign on vens's mock through ctx_runner.py, and the after's
  fallback campaign, every answer cannot_tell.
The archives are read through mirrors, never written."""
import contextlib
import io
import os
import re
import tempfile
import unittest

import ctx_analyze
import ctx_runner
from chain import cells as cellmod
from chain import demo, downloads, javacheck, usage
from tests import support as s
from tests.test_0b import mirror

ARMS_0B = {"9ac9ef4": "control", "c1245cd": "a", "ab40f3f": "b"}
MODELS_0B = {"openai": "openai/gpt-5.4-mini-2026-03-17", "anthropic": "anthropic/claude-sonnet-4-6"}
CONTEXTS = ("internet-facing", "internal", "internal-api")
ARM_A = re.compile(r"  (?P<ctx>[\w-]+): control gap p [\d.]+ \((?:gap|no gap)\), Δ control (?P<dc>[\d.]+); "
                   r"Δ arm (?P<da>[\d.]+), .*; guards (?P<guards>.*); spread condition: .*")
GUARD = re.compile(r"(openai|anthropic) (W|H) ([\d.]+) (pass|fail)")
MPD = re.compile(r"    (openai|anthropic): S [-+\d.]+, D [\d.]+ \(p [\d.]+\), MPD arm ([\d.]+) / control ([\d.]+), .*")
ARM_B = re.compile(r"  (openai|anthropic) ([\w-]+): median A_BI .*; W ratio ([\d.]+), H ratio ([\d.]+)")


def analyze(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ctx_analyze.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def optional(*names):
    """The options the environment allows: the scan, the JAR with a JDK, the draw list."""
    argv = []
    if s.env("VB_DEMO"):
        argv += ["--demo", s.env("VB_DEMO")]
    if s.env("VB_JAR") and javacheck.jdk_bin():
        argv += ["--jar", s.env("VB_JAR")]
    if s.env("VB_0A_DRAWS") and "draws" in names:
        argv += ["--draw-list", s.env("VB_0A_DRAWS")]
    return argv


class TestTheCommand(unittest.TestCase):
    def test_synthetic_downloads_and_a_usage_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "downloads")
            s.baseline_folder(root, 4001, "internal", 1, 1, record=s.COMPLETE_RECORD,
                              log=[s.summary_line(llm_calls=2, asked_again=0, splits=0, failed=False)])
            s.baseline_folder(root, 4002, "internal", 1, 1, record=s.COMPLETE_RECORD, arm="before",
                              commit=s.BEFORE_SHA)
            use = s.write(os.path.join(tmp, "usage.csv"), ",".join(usage.FIELDS) + "\n"
                          + "2026-11-20,openai,key-after,after,gpt-5.4-mini-2026-03-17,2,1000,0,100,0.0012\n")
            code, text, err = analyze("--usage", use, root)
        self.assertEqual((code, err), (0, ""))
        for heading in ("## Records", "## Targets", "## The demo scan", "## The scenarios",
                        "## Attempts, failures and recovery calls", "### Measured: the providers' usage exports",
                        "### Estimated, per attempt (not measured)", "## KPI measures",
                        "## What these records cannot show"):
            self.assertIn(heading, text)
        self.assertIn(f"| demo scan | after · openai/{s.MODEL} · internal | 1 | 1 | 1 (r1) | 0 | 0 | 0 | 0 |", text)
        # the after's rating recomputes; the before's VEX holds the after's vector, off main's rule
        self.assertIn(f"| after · openai/{s.MODEL} · internal | r1 | the VEX's rated CVEs (no report given) | "
                      "1/1 (1.000) | 1/1 (1.000) |", text)
        self.assertIn(f"| before · openai/{s.MODEL} · internal | r1 | the VEX's rated CVEs (no report given) | "
                      "0/1 (0.000) | 0/1 (0.000) |", text)
        measured = text.split("### Measured")[1].split("### Estimated")[0]
        self.assertIn("| openai | gpt-5.4-mini-2026-03-17 | 2 | 1000 | 0 | 100 | 0.00 | 2026-11-20 |", measured)
        self.assertNotIn("estimate", measured)

    def test_a_refused_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, text, err = analyze(os.path.join(tmp, "missing"))
        self.assertEqual((code, text), (1, ""))
        self.assertTrue(err.startswith("refused: "))


class Phase(unittest.TestCase):
    """0B's downloads, mirrored once per class."""
    PHASE = None

    @classmethod
    def setUpClass(cls):
        cls.meas = s.env("VB_0B_MEASUREMENTS")
        if cls.meas is None:
            raise unittest.SkipTest("set VB_0B_MEASUREMENTS to the folder holding 0b-phase1 and 0b-phase2")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = mirror(os.path.join(cls.meas, cls.PHASE), os.path.join(cls.tmp.name, cls.PHASE))
        cls.failures = os.path.join(cls.meas, cls.PHASE, "failures.txt")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()


class TestAgainst0BPhase2(Phase):
    PHASE = "0b-phase2"

    def expected(self):
        arm_a, mpd, arm_b, ctx = {}, {}, {}, None
        with open(os.path.join(self.meas, self.PHASE, "read0b-phase2.out"), encoding="utf-8") as fh:
            for line in fh.read().splitlines():
                if m := ARM_A.fullmatch(line):
                    ctx = m.group("ctx")
                    arm_a[ctx] = (m.group("dc"), m.group("da"), GUARD.findall(m.group("guards")))
                elif (m := MPD.fullmatch(line)) and ctx:
                    mpd[(m.group(1), ctx)] = (m.group(2), m.group(3))
                elif m := ARM_B.fullmatch(line):
                    arm_b[(m.group(1), m.group(2))] = (m.group(3), m.group(4))
        self.assertEqual((len(arm_a), len(mpd), len(arm_b)), (3, 6, 6))
        return arm_a, mpd, arm_b

    def cells(self, after):
        """The phase's control as the before and one of its arms as the after, by each run's vens commit."""
        recs = downloads.read_downloads(self.dir, arm="before", failures=downloads.load_failures(self.failures))
        sha = {r["what"]["run_id"]: r["what"]["vens_commit"][:7] for r in recs if r["what"]["vens_commit"]}
        arm = lambda r: {"control": "before", after: "after"}.get(ARMS_0B[sha[r["what"]["run_id"]]])
        return cellmod.group([r for r in recs if arm(r)], arm_of=arm)

    def test_mpd_delta_w_and_h_as_read0b_prints_them(self):
        arm_a, mpd, arm_b = self.expected()
        cells = self.cells("a")
        cross, spreads = demo.cross_model(cells), demo.spreads(cells)
        pair = tuple(sorted(MODELS_0B.values()))
        for ctx, (dc, da, guards) in arm_a.items():
            self.assertEqual(f"{cross[(ctx, 'before') + pair]['delta']:.2f}", dc, ctx)
            self.assertEqual(f"{cross[(ctx, 'after') + pair]['delta']:.2f}", da, ctx)
            for provider, stat, bound, verdict in guards:
                ratio_bound = spreads[(MODELS_0B[provider], ctx)]["after / before"][stat]
                self.assertEqual((f"{ratio_bound[1]:.3f}", ratio_bound[2]), (bound, verdict), (ctx, provider, stat))
        for (provider, ctx), (in_arm, in_control) in mpd.items():
            i = pair.index(MODELS_0B[provider])
            got = (f"{cross[(ctx, 'after') + pair]['mpd'][i]:.2f}", f"{cross[(ctx, 'before') + pair]['mpd'][i]:.2f}")
            self.assertEqual(got, (in_arm, in_control), (provider, ctx))
        spreads_b = demo.spreads(self.cells("b"))
        for (provider, ctx), (w, h) in arm_b.items():
            got = spreads_b[(MODELS_0B[provider], ctx)]["after / before"]
            self.assertEqual((round(got["W"][0], 3), round(got["H"][0], 3)), (float(w), float(h)), (provider, ctx))


class TestEndToEndOn0BPhase1(Phase):
    PHASE = "0b-phase1"

    def test_every_statistic_with_the_failed_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.md")
            code, _, err = analyze("--arm", "before", "--failures", self.failures, "--out", out, *optional(), self.dir)
            with open(out, encoding="utf-8") as fh:
                text = fh.read()
        self.assertEqual((code, err), (0, ""))
        claude10 = "before · anthropic/claude-sonnet-4-6 batch 10 · internal"
        # replicate 3 failed four times, the retry cap; six more attempts failed before a complete one
        self.assertIn(f"| demo scan | {claude10} | 19 | 9 | 9 (r1-r2, r4-r10) | 0 | 10 | 0 | 0 |", text)
        self.assertIn(f"- {claude10}: run 43761034679 a1 r1-r2, r4-r5, r8; run 43761034679 a3 r6, r9; "
                      "run 43761034679 a2 r7, r10", text)
        self.assertRegex(text, rf"\| {re.escape(claude10)} \| 0 \| none \| 10 \| r3 \|")
        self.assertIn("| internal | before, batch 1 | anthropic/claude-sonnet-4-6 | openai/gpt-5.4-mini-2026-03-17 |",
                      text)
        self.assertEqual(len(re.findall(r"^\| before · .* \| r\d+ \| 74 \|", text, re.M)), 119)  # #340, per run
        self.assertIn("| anthropic/claude-sonnet-4-6 batch 10 | internal | before | r1-r2, r4-r10 | 74 |", text)
        if "--demo" in optional():
            self.assertIn("| the report's CVEs | each run 74/74 (1.000) | each run 74/74 (1.000) |", text)
        if "--jar" in optional():
            self.assertIn("| the report's CVEs | each run 0/74 (0.000) |", text)


class TestEndToEndOnR2(unittest.TestCase):
    """R2's after-ref and before-ref downloads: one replicate of each arm on a real model, read as step 5 reads its
    campaign."""

    @classmethod
    def setUpClass(cls):
        cls.r2 = s.env("VB_R2")
        if cls.r2 is None:
            raise unittest.SkipTest("set VB_R2 to R2's archive (its run folders, calls.tar.gz and dispatch-log.jsonl)")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = mirror(cls.r2, os.path.join(cls.tmp.name, "r2"))
        out = os.path.join(cls.tmp.name, "report.md")
        cls.code, _, cls.err = analyze("--dispatch-log", os.path.join(cls.r2, "dispatch-log.jsonl"),
                                       "--commit", f"before={s.BEFORE_SHA}", "--commit", f"after={s.AFTER_SHA}",
                                       "--out", out, *optional("draws"), cls.dir)
        with open(out, encoding="utf-8") as fh:
            cls.text = fh.read()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def cell(self, arm, ctx):
        return f"{arm} · openai/{s.MODEL} · {ctx}"

    def test_read_whole(self):
        self.assertEqual((self.code, self.err), (0, ""))
        for arm in ("after", "before"):
            for ctx in CONTEXTS:
                self.assertIn(f"| demo scan | {self.cell(arm, ctx)} | 1 | 1 | 1 (r1) | 0 | 0 | 0 | 0 |", self.text)
        self.assertIn("No failed attempt.", self.text)

    def test_the_targets(self):
        over = "the report's CVEs" if "--demo" in optional() else "the VEX's rated CVEs (no report given)"
        for arm in ("after", "before"):
            for ctx in CONTEXTS:
                self.assertIn(f"| {self.cell(arm, ctx)} | r1 | {over} | 74/74 (1.000) | 74/74 (1.000) |", self.text)
        if "--jar" in optional():
            for ctx in CONTEXTS:
                self.assertIn(f"| {self.cell('after', ctx)} | r1 | {over} | 74/74 (1.000) |\n", self.text)
                self.assertIn(f"| {self.cell('before', ctx)} | r1 | {over} | 0/74 (0.000) |\n", self.text)

    def test_the_spreads_on_one_replicate(self):
        model = f"openai/{s.MODEL}"
        for ctx, w, h in (("internal", "2.932", "1.114"), ("internal-api", "1.201", "1.216"),
                          ("internet-facing", "0.718", "1.033")):
            self.assertIn(f"| {model} · {ctx} | after / before |  |  | ratio {w}, lower bound n/a | ratio {h}, "
                          f"lower bound n/a |", self.text)
        self.assertIn("Needs two models with runs in one context and arm: none here.", self.text)

    def test_340_and_the_calls(self):
        self.assertIn(f"| {self.cell('after', 'internet-facing')} | r1 | 74 | 17 | 21 | 18 | 0.324 | 0.527 | 0.149 | "
                      f"0.000 | 0.054 |", self.text)
        for ctx, calls in (("internal", 649), ("internal-api", 649), ("internet-facing", 768)):
            self.assertIn(f"| {self.cell('after', ctx)} | 1 | 1 | 0 | 0 | {calls} | {calls} | 7 | 0 | 0 | 0 | 0 | 0 | "
                          f"0 | 0 | 0 |", self.text)
            self.assertIn(f"| {self.cell('before', ctx)} | 1 | 1 | 0 | 0 | 74 | 74 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | "
                          f"0 |", self.text)

    def test_opportunity_outside_the_draws(self):
        if s.env("VB_0A_DRAWS") is None:
            self.skipTest("set VB_0A_DRAWS to the CVE ids earlier draws used")
        self.assertIn(f"| openai/{s.MODEL} | internal | r1 | in the list | 37 |", self.text)
        # the five CVEs no row describes get no Opportunity question
        self.assertIn(f"| openai/{s.MODEL} | internal | r1 | outside it | 32 |", self.text)


class TestEndToEndOnTheMock(unittest.TestCase):
    """A scenario campaign through ctx_runner.py on vens's mock, both arms, and the after's fallback."""

    @classmethod
    def setUpClass(cls):
        cls.after, cls.before = s.env("VB_VENS_AFTER"), s.env("VB_VENS_BEFORE")
        if cls.after is None or cls.before is None:
            raise unittest.SkipTest("set VB_VENS_AFTER and VB_VENS_BEFORE to run a mock campaign")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.camp, cls.fb = os.path.join(cls.tmp.name, "c1"), os.path.join(cls.tmp.name, "fallback")
        env = {"PATH": os.environ.get("PATH", ""), "HOME": cls.tmp.name}
        for out, replicates, extra in ((cls.camp, 2, {}), (cls.fb, 1, {"VENS_MOCK_LLM_CANNOT_TELL": "1"})):
            argv = ["--campaign", os.path.basename(out), "--out", out, "--before", cls.before, "--before-commit",
                    s.BEFORE_SHA, "--after", cls.after, "--after-commit", s.AFTER_SHA, "--model", "mock/mock",
                    "--replicates", str(replicates), "--retry-cap", "2", "--timeout", "120", "--parallel", "4"]
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = ctx_runner.main(argv, environ={**env, **extra})
            if code != 0:
                raise AssertionError(f"{out}: the runner exited {code}")
        cls.code, cls.text, cls.err = analyze("--fallback", cls.fb, cls.camp)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_family(self):
        self.assertEqual((self.code, self.err), (0, ""))
        for family in ("1 Exposure", "2 Controls", "3 Data sensitivity", "4 Business criticality", "5 Compliance",
                       "6 DoS discriminator", "7 Accountability discriminator",
                       "8 Relevant against irrelevant control", "9 DoS, telegraphed or not",
                       "10 Accountability, telegraphed or not", "11 Irrelevant WAF on the local bug", "showcases",
                       "reachability"):
            self.assertIn(f"#### {family}\n", self.text)
        # exposure's step in the after is Size's, set by Go from the declared exposure
        self.assertIn("| the score not falling | after | carried | mock/mock | expo_internal / expo_private | ", self.text)
        self.assertIn("e.g. r1: S 4->6 (config/config)", self.text)
        self.assertIn("showcase_high_to_low: CVSS 10.0 RCE -> expect LOW; showcase_med_to_high: CVSS 6.5 leak -> "
                      "expect HIGH.", self.text)

    def test_the_targets_and_the_null_table(self):
        self.assertIn("| after | mock/mock | 46 | 92 | 92/92 (1.000) | none | 92/92 (1.000) |", self.text)
        self.assertIn("| before | mock/mock | 46 | 92 | 92/92 (1.000) | none | 92/92 (1.000) |", self.text)
        rows = [ln for ln in self.text.splitlines() if ln.startswith("| ") and "mock/mock after:" in ln]
        self.assertEqual(len(rows), 46)
        self.assertTrue(all(not ln.endswith("| n/a |") for ln in rows))
        self.assertIn("from the campaign given.", self.text)

    def test_a_campaign_that_is_no_fallback_is_refused(self):
        code, _, err = analyze("--fallback", self.camp, self.camp)
        self.assertEqual(code, 1)
        self.assertIn("not a fallback campaign", err)


if __name__ == "__main__":
    unittest.main()
