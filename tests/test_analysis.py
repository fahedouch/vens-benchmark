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
import json
import os
import re
import shutil
import tempfile
import unittest

import ctx_analyze
import ctx_runner
from chain import cells as cellmod
from chain import campaign, demo, downloads, javacheck, report_scen, usage, verdicts
from tests import records as r
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
OTHER_AFTER = "e" * 40  # a commit the after's fallback below claims, not the after's


def analyze(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ctx_analyze.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def refrozen(src, dst):
    """A copy of campaign src as if its corpus had been frozen again: freeze-scenarios.json one byte longer, every
    record naming its new sha256, SHA256SUMS rewritten. The new sha256."""
    shutil.copytree(src, dst)
    for d, _, names in os.walk(dst):
        os.chmod(d, 0o755)
        for n in names:
            os.chmod(os.path.join(d, n), 0o644)
    with open(os.path.join(dst, campaign.FREEZE), "a", encoding="utf-8") as fh:
        fh.write("\n")
    sha = ctx_analyze.digest(os.path.join(dst, campaign.FREEZE))
    for path in [os.path.join(dst, campaign.CAMPAIGN)] + [os.path.join(d, "attempt.json")
                                                         for d in campaign.attempt_folders(dst)]:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        (doc["corpus"] if "corpus" in doc else doc)["freeze_sha256"] = sha
        s.write(path, doc)
    campaign.write_sums(dst)
    return sha


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
    def downloads(self, tmp):
        root = os.path.join(tmp, "downloads")
        s.baseline_folder(root, 4001, "internal", 1, 1, record=s.COMPLETE_RECORD,
                          log=[s.summary_line(llm_calls=2, asked_again=0, splits=0, failed=False)])
        s.baseline_folder(root, 4002, "internal", 1, 1, record=s.COMPLETE_RECORD, arm="before", commit=s.BEFORE_SHA)
        return root

    def test_synthetic_downloads_and_a_usage_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.downloads(tmp)
            use = s.write(os.path.join(tmp, "usage.csv"), ",".join(usage.FIELDS) + "\n"
                          + "downloads,2026-11-20,openai,key-after,after,gpt-5.4-mini-2026-03-17,2,1000,0,100,0.0012\n"
                          + "downloads,2026-11-21,openai,key-after,before,gpt-5.4-mini-2026-03-17,1,10,0,1,0.0001\n")
            code, text, err = analyze("--usage", use, root)
        self.assertEqual((code, err), (0, ""))
        for heading in ("## Records", "## Targets", "## The demo scan", "## The scenarios",
                        "## Attempts, failures and recovery calls", "### Measured: the providers' usage exports",
                        "### Estimated, per attempt (not measured)", "## KPI measures",
                        "## What these records cannot show"):
            self.assertIn(heading, text)
        self.assertIn(f"| demo scan | downloads · after · openai/{s.MODEL} · internal | b7c043583544 | 1 | 1 | 1 (r1) | "
                      "0 | 0 | 0 | 0 |", text)
        self.assertIn("Unavailable: the Java check did not run, no JAR given (--jar).", text)
        self.assertIn(f"| downloads · after · openai/{s.MODEL} · internal | r1 | unavailable: the scanner's report is not "
                      "given", text)
        measured = text.split("### Measured")[1].split("### Estimated")[0]
        self.assertIn("The export `usage.csv`, sha256 ", measured)
        self.assertIn("| downloads | openai | gpt-5.4-mini-2026-03-17 | 3 | 1010 | 0 | 101 | 0.00 | 2026-11-20, "
                      "2026-11-21 |", measured)
        # one key carries both arms: no per-arm total
        self.assertIn("No per-arm total for downloads at openai: key key-after carries after, before.", measured)
        self.assertNotIn("estimate", measured)
        self.assertIn("- Batch size: every run read is at batch 1", text)

    def test_the_targets_over_the_report_its_unrated_cves_failing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.downloads(tmp)
            demo_tree = os.path.join(tmp, "vens-demo")
            s.write(os.path.join(demo_tree, "runs", "2026-09-23", "scan", "scan.json"),
                    {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2099-0001"},
                                                      {"VulnerabilityID": "CVE-2099-0002"}]}]})
            code, text, err = analyze("--demo", demo_tree, root)
        self.assertEqual((code, err), (0, ""))
        # the after's one rating recomputes and CVE-2099-0002 is not rated: 1 of 2; the before's VEX holds the
        # after's vector, off main's rule: 0 of 2
        self.assertIn(f"| downloads · after · openai/{s.MODEL} · internal | r1 | 1/2 (0.500) | 1/2 (0.500) |", text)
        self.assertIn(f"| downloads · before · openai/{s.MODEL} · internal | r1 | 0/2 (0.000) | 0/2 (0.000) |", text)

    def test_two_inputs_of_one_name_are_two_campaigns(self):
        with tempfile.TemporaryDirectory() as tmp:
            roots = [os.path.join(tmp, c, "downloads") for c in ("c1", "c2")]
            for root in roots:
                s.baseline_folder(root, 4001, "internal", 1, 1, record=s.COMPLETE_RECORD)
            code, text, err = analyze(*roots)
        self.assertEqual((code, err), (0, ""))
        row = f"| demo scan | downloads · after · openai/{s.MODEL} · internal | b7c043583544 | 1 | 1 | 1 (r1) | 0 | 0 |"
        self.assertEqual(text.count(row + " 0 | 0 |"), 2)
        self.assertNotIn("complete attempts, the first one read", text)

    def test_scenario_campaigns_on_two_corpora_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            inputs = []
            for name, freeze in (("c1", "{}"), ("c2", "{} ")):
                s.write(os.path.join(tmp, name, campaign.FREEZE), freeze)
                inputs.append((os.path.join(tmp, name), [r.record("after", "wrong_yaml", 1, {}, scenario=True,
                                                                  campaign=name)]))
            self.assertEqual(ctx_analyze.scenario_corpus(inputs[:1] * 2)[0], inputs[0][0])
            with self.assertRaisesRegex(ctx_analyze.InputError, "the scenario campaigns ran on different corpora"):
                ctx_analyze.scenario_info(inputs)

    def test_the_batch_scope_reads_the_runs_alone(self):
        rated = {vid: r.rating(s.VECTOR) for vid in ("CVE-A", "CVE-B")}
        # a complete run whose scores are not usable is still read, by the targets; a failed attempt is not a run
        recs = [r.record("after", "internal", 1, rated), r.record("after", "internal", 1, rated, batch=5, usable=False),
                r.record("after", "internal", 1, None, batch=10, outcome="failed")]
        data = ctx_analyze.compute([("downloads", recs)], ctx_analyze.Reports(None))
        self.assertEqual(data["batches"], [1, 5])
        self.assertIn("- Batch size: the runs read are at batch sizes 1, 5; each size is its own cell, never pooled, "
                      "and no statistic here compares two sizes.", report_scen.scope(data))

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
            self.assertEqual(f"{cross[(None, ctx, 'before') + pair]['delta']:.2f}", dc, ctx)
            self.assertEqual(f"{cross[(None, ctx, 'after') + pair]['delta']:.2f}", da, ctx)
            for provider, stat, bound, verdict in guards:
                ratio_bound = spreads[(None, MODELS_0B[provider], ctx)]["after / before"][stat]
                self.assertEqual((f"{ratio_bound[1]:.3f}", ratio_bound[2]), (bound, verdict), (ctx, provider, stat))
        for (provider, ctx), (in_arm, in_control) in mpd.items():
            i = pair.index(MODELS_0B[provider])
            got = (f"{cross[(None, ctx, 'after') + pair]['mpd'][i]:.2f}",
                   f"{cross[(None, ctx, 'before') + pair]['mpd'][i]:.2f}")
            self.assertEqual(got, (in_arm, in_control), (provider, ctx))
        spreads_b = demo.spreads(self.cells("b"))
        for (provider, ctx), (w, h) in arm_b.items():
            got = spreads_b[(None, MODELS_0B[provider], ctx)]["after / before"]
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
        claude10 = "0b-phase1 · before · anthropic/claude-sonnet-4-6 batch 10 · internal"
        # replicate 3 failed four times, the retry cap; six more attempts failed before a complete one; the failed
        # downloads keep no commit of their own and run at the one the run was dispatched with
        self.assertIn(f"| demo scan | {claude10} | 9ac9ef4d7d2f | 19 | 9 | 9 (r1-r2, r4-r10) | 0 | 10 | 0 | 0 |", text)
        self.assertIn(f"- {claude10}: run 43761034679 a1 r1-r2, r4-r5, r8; run 43761034679 a3 r6, r9; "
                      "run 43761034679 a2 r7, r10", text)
        self.assertRegex(text, rf"\| {re.escape(claude10)} \| 0 \| none \| 10 \| r3 \|")
        self.assertIn("| 0b-phase1 | internal | before, batch 1 | anthropic/claude-sonnet-4-6 | "
                      "openai/gpt-5.4-mini-2026-03-17 |", text)
        self.assertEqual(len(re.findall(r"^\| 0b-phase1 · before · .* \| r\d+ \| 74 \|", text, re.M)), 119)  # #340
        self.assertIn("| 0b-phase1 | anthropic/claude-sonnet-4-6 batch 10 | internal | before | r1-r2, r4-r10 | 74 |",
                      text)
        self.assertIn("- Batch size: the runs read are at batch sizes 1, 10;", text)
        if "--demo" in optional():
            self.assertIn("| r1-r10 | each run 74/74 (1.000) | each run 74/74 (1.000) |", text)
        if "--jar" in optional():
            self.assertIn("| r1-r10 | each run 0/74 (0.000) |", text)


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
        return f"r2 · {arm} · openai/{s.MODEL} · {ctx}"

    def test_read_whole(self):
        self.assertEqual((self.code, self.err), (0, ""))
        for arm in ("after", "before"):
            for ctx in CONTEXTS:
                commit = (s.AFTER_SHA if arm == "after" else s.BEFORE_SHA)[:12]
                self.assertIn(f"| demo scan | {self.cell(arm, ctx)} | {commit} | 1 | 1 | 1 (r1) | 0 | 0 | 0 | 0 |",
                              self.text)
        self.assertIn("No failed attempt.", self.text)

    def test_the_targets(self):
        if "--demo" not in optional():
            self.assertIn("unavailable: the scanner's report is not given", self.text)
            return
        for arm in ("after", "before"):
            for ctx in CONTEXTS:
                self.assertIn(f"| {self.cell(arm, ctx)} | r1 | 74/74 (1.000) | 74/74 (1.000) |", self.text)
        if "--jar" in optional():
            for ctx in CONTEXTS:
                self.assertIn(f"| {self.cell('after', ctx)} | r1 | 74/74 (1.000) |\n", self.text)
                self.assertIn(f"| {self.cell('before', ctx)} | r1 | 0/74 (0.000) |\n", self.text)

    def test_the_spreads_on_one_replicate(self):
        model = f"openai/{s.MODEL}"
        for ctx, w, h in (("internal", "2.932", "1.114"), ("internal-api", "1.201", "1.216"),
                          ("internet-facing", "0.718", "1.033")):
            self.assertIn(f"| r2 · {model} · {ctx} | after / before |  |  | ratio {w}, lower bound n/a | ratio {h}, "
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
        self.assertIn(f"| r2 | openai/{s.MODEL} | internal | r1 | in the list | 37 | 37 | 0 |", self.text)
        # all 37 outside: 32 answered, and the five CVEs no row describes, which get no Opportunity question
        self.assertIn(f"| r2 | openai/{s.MODEL} | internal | r1 | outside it | 37 | 32 | 5 |", self.text)
        self.assertRegex(self.text, r"The draw list `[^`]+`, sha256 [0-9a-f]{64}, \d+ CVE ids, of which 37 are among "
                                    r"the 74 CVEs these runs read\.")


class TestEndToEndOnTheMock(unittest.TestCase):
    """A scenario campaign through ctx_runner.py on vens's mock, both arms, and the after's fallback."""

    @classmethod
    def setUpClass(cls):
        cls.after, cls.before = s.env("VB_VENS_AFTER"), s.env("VB_VENS_BEFORE")
        if cls.after is None or cls.before is None:
            raise unittest.SkipTest("set VB_VENS_AFTER and VB_VENS_BEFORE to run a mock campaign")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.camp, cls.fb = os.path.join(cls.tmp.name, "c1"), os.path.join(cls.tmp.name, "fallback")
        cls.off = os.path.join(cls.tmp.name, "off")
        for out, replicates, extra in ((cls.camp, 2, {}), (cls.fb, 1, {"VENS_MOCK_LLM_CANNOT_TELL": "cannot_tell"}),
                                       (cls.off, 1, {"VENS_MOCK_LLM_CANNOT_TELL": "0"})):
            cls.campaign(out, replicates, extra, ["--scenario", "wrong_yaml"] if out == cls.off else [])
        # the after's own binary on the mock, every answer cannot_tell, but run as another after commit
        cls.elsewhere = os.path.join(cls.tmp.name, "fallback-elsewhere")
        cls.campaign(cls.elsewhere, 1, {"VENS_MOCK_LLM_CANNOT_TELL": "cannot_tell"}, ["--scenario", "wrong_yaml"],
                     after_commit=OTHER_AFTER)
        cls.code, cls.text, cls.err = analyze("--fallback", cls.fb, cls.camp)

    @classmethod
    def campaign(cls, out, replicates, extra, only, after_commit=s.AFTER_SHA):
        argv = ["--campaign", os.path.basename(out), "--out", out, "--before", cls.before, "--before-commit",
                s.BEFORE_SHA, "--after", cls.after, "--after-commit", after_commit, "--model", "mock/mock",
                "--replicates", str(replicates), "--retry-cap", "2", "--timeout", "120", "--parallel", "4", *only]
        env = {"PATH": os.environ.get("PATH", ""), "HOME": cls.tmp.name, **extra}
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = ctx_runner.main(argv, environ=env)
        if code != 0:
            raise AssertionError(f"{out}: the runner exited {code}")

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
        self.assertIn("| the score not falling | after | carried | c1 · mock/mock | expo_internal / expo_private | ",
                      self.text)
        self.assertIn("e.g. r1: S 4->6 (config/config)", self.text)
        self.assertIn("| r1-r2: SL ED A constant, M O EE LC LI LAV LAC FD RD PV answer, S ID NC config | Go's x2;",
                      self.text)
        self.assertIn("showcase_high_to_low: CVSS 10.0 RCE -> expect LOW; showcase_med_to_high: CVSS 6.5 leak -> "
                      "expect HIGH.", self.text)

    def test_the_targets_and_the_null_table(self):
        self.assertIn("| after | c1 · mock/mock | 46 | 92 | 92/92 (1.000) | none | 92/92 (1.000) |", self.text)
        self.assertIn("| before | c1 · mock/mock | 46 | 92 | 92/92 (1.000) | none | 92/92 (1.000) |", self.text)
        rows = [ln for ln in self.text.splitlines() if ln.startswith("| ") and "c1 · mock/mock after:" in ln]
        self.assertEqual(len(rows), 46)
        self.assertTrue(all(not ln.endswith("| n/a |") for ln in rows))
        self.assertIn(f"from campaign fallback (`{self.fb}`), vens {s.AFTER_SHA}, vens's mock with "
                      "VENS_MOCK_LLM_CANNOT_TELL=cannot_tell.", self.text)

    def test_a_campaign_that_is_no_fallback_is_refused(self):
        for campaign, why in ((self.camp, "VENS_MOCK_LLM_CANNOT_TELL is ''"),
                              (self.off, "VENS_MOCK_LLM_CANNOT_TELL is '0'")):
            code, _, err = analyze("--fallback", campaign, self.camp)
            self.assertEqual(code, 1, campaign)
            self.assertIn("not the after's fallback: " + why, err)
        # a --commit the scenario campaign did not run at refuses the campaign itself, before any fallback
        code, _, err = analyze("--fallback", self.fb, "--commit", "after=" + "f" * 40, self.camp)
        self.assertEqual(code, 1)
        self.assertIn(f"gives vens {s.AFTER_SHA}, not the after's {'f' * 40}", err)
        code, _, err = analyze("--fallback", self.elsewhere, self.camp)
        self.assertEqual(code, 1)
        self.assertIn(f"not the after's fallback: its after is {OTHER_AFTER}, not {s.AFTER_SHA}", err)

    def test_a_fallback_on_another_corpus_is_refused(self):
        # the scenario campaign on a corpus frozen again, read under its freeze; the fallback ran on the old one
        regenerated = os.path.join(self.tmp.name, "regenerated")
        sha = refrozen(self.off, regenerated)
        code, _, err = analyze("--freeze-sha256", sha, regenerated)
        self.assertEqual((code, err), (0, ""))
        code, _, err = analyze("--freeze-sha256", sha, "--fallback", self.fb, regenerated)
        self.assertEqual(code, 1)
        self.assertIn(f"not the after's fallback: its corpus is {campaign.FROZEN}, not the scenario campaigns' {sha}",
                      err)

    def test_the_single_checks_give_each_level_and_its_source(self):
        rows = [ln for ln in self.text.splitlines() if ln.startswith("| ")]
        (dos,) = [ln for ln in rows if ln.startswith("| T below the null model's | after | diagnostic | c1 · mock/mock "
                                                    "| disc_dos |")]
        # in the after the vector floors C and I on the DoS discriminator; availability and accountability answered
        self.assertTrue(dos.endswith("| r1-r2: LC=2 LI=1 floor, LAV=5 LAC=7 answer |  |"), dos)
        lac = {ln.split(" | ")[4]: ln for ln in rows
               if ln.startswith("| LAC's answer defeats_attribution, traceability per_individual | after | new |")}
        self.assertEqual(sorted(lac), sorted(verdicts.ACCOUNTABILITY))
        for sid, level in (("disc_audit", 1), ("disc_audit3", 9)):
            self.assertTrue(lac[sid].endswith(f"| r1-r2: LAC={level} answer |  |"), lac[sid])


if __name__ == "__main__":
    unittest.main()
