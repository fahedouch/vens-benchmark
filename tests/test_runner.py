"""The scenario runner (ctx_runner.py) and the reading of its campaigns. Its order, parallelism, retries, timeout,
stop, keys, model ids and freeze on a fake vens that calls nothing; on vens's own mock at both commits, a failed
attempt then a complete one, the omission stop up to the retry cap, and a timeout, read back by the reader. No model
is called and no real key is used."""
import contextlib
import io
import json
import os
import shutil
import signal
import sys
import tempfile
import threading
import time
import unittest

import ctx_runner
from chain import campaign, read, runvens
from chain.errors import Refused
from tests import support as s
from tests.test_mock_runs import FORCED, SKIPPED, SKIPPED_BEFORE

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARMS = ("before", "after")
KEYS = {"OPENAI_API_KEY_BEFORE": "sk-fake-before-0001", "OPENAI_API_KEY_AFTER": "sk-fake-after-0002"}
DATED = "openai/gpt-5.4-mini-2026-03-17"
# Variables Python sets in its own environment at startup, not given by the runner.
PYTHON_ADDS = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}

# The fake vens: ARM and STATE are set above this body. Each call takes the next mode of its arm's list in
# STATE/plan.json, else its default: ok, fail, sleep (killed at the timeout), echo (the key in its log), leak (the
# key in a debug file too), barrier (waits until plan.json's width calls run at once).
FAKE_VENS = r'''
import fcntl, json, os, sys, time
args = sys.argv[1:]
arg = lambda flag: args[args.index(flag) + 1]
scenario, out, calls = arg("--config-file").split("/")[1], args[-1], arg("--debug-dir")
with open(os.path.join(STATE, "lock"), "a") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    count = os.path.join(STATE, "count-" + ARM)
    n = int(open(count).read()) if os.path.exists(count) else 0
    open(count, "w").write(str(n + 1))
plan = json.load(open(os.path.join(STATE, "plan.json")))
modes = plan.get(ARM, [])
mode = modes[n] if n < len(modes) else plan.get("default", "ok")
key = os.environ.get("OPENAI_API_KEY", "")

def event(kind, **kw):
    with open(os.path.join(STATE, "events.jsonl"), "a") as fh:
        fh.write(json.dumps({"arm": ARM, "scenario": scenario, "folder": os.path.dirname(out), "event": kind,
                             "t": time.time(), "pid": os.getpid(), **kw}) + "\n")

def log(level, msg, **kw):
    fields = "".join(f" {k}={json.dumps(v)}" for k, v in kw.items())
    sys.stderr.write(f"time=2026-11-20T10:00:00.000Z level={level} msg={json.dumps(msg)}{fields}\n")
    sys.stderr.flush()

event("start", mode=mode, env=sorted(os.environ), model=os.environ.get("OPENAI_MODEL"), key=key, cwd=os.getcwd())
if mode == "barrier":
    # tickets in arrival order: a wave of width calls is released once its last ticket is taken, all of the wave
    # then running at once; alive counts the calls running when this one arrived
    def locked(change):
        with open(os.path.join(STATE, "lock"), "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            return change()

    def bump(name, by):
        path = os.path.join(STATE, name)
        value = (int(open(path).read()) if os.path.exists(path) else 0) + by
        open(path, "w").write(str(value))
        return value

    ticket, alive = locked(lambda: (bump("tickets", 1) - 1, bump("alive", 1)))
    wave_end, end = (ticket // plan["width"] + 1) * plan["width"], time.time() + 5
    while locked(lambda: bump("tickets", 0)) < wave_end and time.time() < end:
        time.sleep(0.02)
    event("barrier", seen=alive, released=locked(lambda: bump("tickets", 0)) >= wave_end)
    locked(lambda: bump("alive", -1))
if mode == "sleep":
    time.sleep(60)
if mode == "fail":
    log("ERROR", "Error", error="failed to generate risk scores: fake failure")
    event("end")
    sys.exit(1)
os.makedirs(os.path.join(calls, "run-1"), exist_ok=True)
for part, text in (("system.prompt", "s"), ("human.prompt", "h"), ("response", key if mode == "leak" else "{}")):
    with open(os.path.join(calls, "run-1", "batch-00001." + part), "w") as fh:
        fh.write(text)
with open(out, "w") as fh:
    fh.write('{"bomFormat": "CycloneDX", "vulnerabilities": []}')
if mode in ("echo", "leak"):
    log("WARN", "a key in the log", key=key)
log("INFO", "Scoring run finished", rows=1, cves=1, llm_calls=1, asked_again=0, splits=0, failed=False)
event("end")
'''

# Around vens's real mock: each call takes the next mode, fail (VENS_MOCK_LLM_FAIL set) or sleep (killed at the
# timeout), then the binary itself.
WRAPPER = '''#!{python}
import os, sys, time
COUNT, BINARY, MODES = {count!r}, {binary!r}, {modes!r}
n = int(open(COUNT).read()) if os.path.exists(COUNT) else 0
open(COUNT, "w").write(str(n + 1))
mode = MODES[n] if n < len(MODES) else "ok"
env = dict(os.environ)
if mode == "fail":
    env["VENS_MOCK_LLM_FAIL"] = "1"
if mode == "sleep":
    time.sleep(60)
os.execve(BINARY, [BINARY] + sys.argv[1:], env)
'''


def gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = os.path.realpath(tmp.name)
        self.state = os.path.join(self.dir, "state")
        os.makedirs(self.state)
        self.bins = {arm: self.fake(arm) for arm in ARMS}
        self.out = os.path.join(self.dir, "campaign")
        self.plan()

    def fake(self, arm):
        path = s.write(os.path.join(self.dir, "bin", f"vens-{arm}"),
                       f"#!{sys.executable}\nARM, STATE = {arm!r}, {self.state!r}\n{FAKE_VENS}")
        os.chmod(path, 0o755)
        return path

    def plan(self, **modes):
        s.write(os.path.join(self.state, "plan.json"), modes)

    def env(self, **extra):
        return {"PATH": os.environ.get("PATH", ""), "HOME": self.dir, **extra}

    def main(self, *extra, environ=None, models=("mock/mock",), scenarios=("comp_gdpr",), replicates=1, cap=3,
             timeout=30, parallel=1, bins=None, commits=(s.BEFORE_SHA, s.AFTER_SHA)):
        bins = bins or self.bins
        argv = ["--campaign", "c1", "--out", self.out, "--before", bins["before"], "--before-commit", commits[0],
                "--after", bins["after"], "--after-commit", commits[1], "--replicates", str(replicates),
                "--retry-cap", str(cap), "--timeout", str(timeout), "--parallel", str(parallel)]
        argv += [x for m in models for x in ("--model", m)] + [x for sc in scenarios for x in ("--scenario", sc)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ctx_runner.main(argv + list(extra), environ=self.env() if environ is None else environ)
        self.stdout, self.stderr = out.getvalue(), err.getvalue()
        return code

    def events(self, kind="start"):
        path = os.path.join(self.state, "events.jsonl")
        if not os.path.exists(path):
            return []
        with open(path) as fh:
            return [e for e in map(json.loads, fh) if e["event"] == kind]

    def record(self, rel):
        with open(os.path.join(self.out, rel, "attempt.json")) as fh:
            return json.load(fh)

    def doc(self):
        with open(os.path.join(self.out, campaign.CAMPAIGN)) as fh:
            return json.load(fh)

    def read(self):
        return {(r["what"]["replicate"], r["what"]["scenario"], r["what"]["arm"], r["what"]["run_attempt"]): r
                for r in campaign.read_campaign(self.out)}


def at(arm, k, scenario="comp_gdpr", replicate=1, model=("mock", "mock")):
    return campaign.folder(replicate, *model, scenario, arm, k)


class TestTheOrder(Base):
    def test_the_arms_back_to_back_replicate_by_replicate_model_by_model(self):
        models, scenarios = ("mock/mock", DATED), ("comp_gdpr", "comp_none")
        self.assertEqual(self.main(models=models, scenarios=scenarios, replicates=2, environ=self.env(**KEYS)), 0)
        want = [at(arm, 1, sc, r, tuple(m.split("/"))) for r in (1, 2) for m in models for sc in scenarios
                for arm in ARMS]
        self.assertEqual([e["folder"] for e in self.events()], want)
        starts = [self.record(f)["generate"]["started_at"] for f in want]
        self.assertEqual(starts, sorted(starts))
        self.assertEqual({e["cwd"] for e in self.events()}, {self.out})
        self.assertEqual(self.doc()["order"], "replicate, then model, then scenario; each unit the before's run then "
                                              "the after's, back to back")

    def test_parallel_units_side_by_side_each_back_to_back(self):
        self.plan(default="barrier", width=3)
        scenarios = ("comp_gdpr", "comp_none", "crit_low")
        self.assertEqual(self.main(scenarios=scenarios, replicates=2, parallel=3), 0)
        # three workers, two units each: four waves of three calls, each released with all three running
        barriers = self.events("barrier")
        self.assertEqual((len(barriers), {e["released"] for e in barriers}), (12, {True}))
        self.assertEqual((max(e["seen"] for e in barriers), sorted(e["seen"] for e in barriers)[-4:]), (3, [3] * 4))
        for r in (1, 2):
            for sc in scenarios:
                before, after = (self.record(at(arm, 1, sc, r))["generate"] for arm in ARMS)
                self.assertLessEqual(before["ended_at"], after["started_at"])
        self.assertEqual(self.doc()["parallelism"], 3)


class TestAttempts(Base):
    def test_a_failed_attempt_then_a_complete_one(self):
        self.plan(before=["fail", "ok"])
        self.assertEqual(self.main(), 0)
        recs = self.read()
        first = recs[(1, "comp_gdpr", "before", 1)]
        self.assertEqual((first["outcome"], first["failure"]["kind"], first["failure"]["cause"]),
                         ("failed", "scoring", "failed to generate risk scores: fake failure"))
        self.assertEqual([recs[(1, "comp_gdpr", arm, k)]["outcome"] for arm, k in (("before", 2), ("after", 1))],
                         ["complete", "complete"])
        self.assertEqual(len(recs), 3)

    def test_the_retry_cap_reached_is_recorded_as_such(self):
        self.plan(before=["fail"] * 3)
        self.assertEqual(self.main(cap=3), ctx_runner.EXIT_CAP_REACHED)
        self.assertEqual([self.record(at("before", k))["retry_cap_reached"] for k in (1, 2, 3)], [False, False, True])
        self.assertFalse(os.path.exists(os.path.join(self.out, at("before", 4))))
        recs = self.read()
        self.assertEqual([recs[(1, "comp_gdpr", "before", k)]["retry_cap_reached"] for k in (1, 2, 3)],
                         [False, False, True])
        self.assertEqual(recs[(1, "comp_gdpr", "after", 1)]["outcome"], "complete")
        self.assertIn(f"{at('before', 3)}: failed, exit 1: failed to generate risk scores: fake failure; the retry "
                      f"cap reached", self.stdout)
        self.assertIn("2 runs, 1 complete, 1 at the retry cap", self.stdout)

    def test_a_timeout_is_recorded_as_such(self):
        self.plan(before=["sleep", "ok"])
        self.assertEqual(self.main(timeout=1), 0)
        gen = self.record(at("before", 1))["generate"]
        self.assertEqual((gen["exit_status"], gen["timed_out"], gen["interrupted"]), (None, True, "timeout"))
        self.assertTrue(gen["ended_at"] > gen["started_at"])
        (slept,) = [e for e in self.events() if e["mode"] == "sleep"]
        self.assertTrue(gone(slept["pid"]))
        rec = self.read()[(1, "comp_gdpr", "before", 1)]
        self.assertEqual(rec["failure"], {"kind": "interrupted", "step": "generate", "cause": "timeout",
                                          "cause_source": "attempt.json"})
        self.assertIn("generate.exit_status", rec["unknown"])
        self.assertEqual(self.read()[(1, "comp_gdpr", "before", 2)]["outcome"], "complete")

    def test_a_stop_kills_the_attempt_running_and_starts_no_other(self):
        self.plan(before=["sleep"])

        def terminate():
            path, end = os.path.join(self.state, "events.jsonl"), time.time() + 30
            while time.time() < end and not (os.path.exists(path) and '"start"' in open(path).read()):
                time.sleep(0.05)
            os.kill(os.getpid(), signal.SIGTERM)

        threading.Thread(target=terminate, daemon=True).start()
        self.assertEqual(self.main(scenarios=("comp_gdpr", "comp_none"), timeout=60), 143)
        (started,) = self.events()
        self.assertTrue(gone(started["pid"]))
        doc = self.doc()
        self.assertEqual((doc["stopped"], doc["ended_at"] is not None), ("interrupted: SIGTERM", True))
        gen = self.record(at("before", 1))["generate"]
        self.assertEqual((gen["exit_status"], gen["interrupted"]), (None, runvens.STOPPED))
        recs = campaign.read_campaign(self.out)
        self.assertEqual(recs[0]["failure"]["cause"], "the runner was stopped")
        self.assertEqual([(r["outcome"], r["what"]["scenario"], r["what"]["arm"]) for r in recs[1:]],
                         [(None, "comp_gdpr", "after"), (None, "comp_none", "before"), (None, "comp_none", "after")])
        self.assertTrue(os.path.exists(os.path.join(self.out, campaign.SUMS)))


class TestKeys(Base):
    def test_each_arm_gets_its_own_key_and_the_model_and_nothing_else(self):
        self.plan(default="echo")
        self.assertEqual(self.main(models=(DATED,), environ=self.env(OPENAI_API_KEY="sk-shared", **KEYS)), 0)
        got = {e["arm"]: e for e in self.events()}
        for arm in ARMS:
            self.assertEqual((got[arm]["key"], got[arm]["model"]),
                             (KEYS[f"OPENAI_API_KEY_{arm.upper()}"], "gpt-5.4-mini-2026-03-17"))
            self.assertEqual(set(got[arm]["env"]) - PYTHON_ADDS, {"PATH", "HOME", "TZ", "OPENAI_MODEL",
                                                                  "OPENAI_API_KEY"})
            rec = self.record(at(arm, 1, model=("openai", "gpt-5.4-mini-2026-03-17")))
            self.assertEqual(rec["key_env"], f"OPENAI_API_KEY_{arm.upper()}")
        self.assertEqual(self.doc()["arms"]["after"]["keys"], {"openai": "OPENAI_API_KEY_AFTER"})
        held = []
        for d, _, names in os.walk(self.out):
            for n in names:
                with open(os.path.join(d, n), "rb") as fh:
                    data = fh.read()
                held += [n for k in KEYS.values() if k.encode() in data]
        self.assertEqual(held, [])
        with open(os.path.join(self.out, at("after", 1, model=("openai", "gpt-5.4-mini-2026-03-17")),
                               "vens.log")) as fh:
            self.assertIn('key="***"', fh.read())

    def test_a_missing_key_stops_the_runner_before_any_call(self):
        self.assertEqual(self.main(models=(DATED,), environ=self.env(OPENAI_API_KEY_BEFORE="sk-1")), 1)
        self.assertIn("OPENAI_API_KEY_AFTER is not set", self.stderr)
        self.assertEqual((self.events(), os.path.exists(self.out)), ([], False))

    def test_one_key_for_both_arms_is_refused(self):
        environ = self.env(OPENAI_API_KEY_BEFORE="sk-1", OPENAI_API_KEY_AFTER="sk-1")
        self.assertEqual(self.main(models=(DATED,), environ=environ), 1)
        self.assertIn("hold one key", self.stderr)
        self.assertEqual(self.events(), [])

    def test_a_key_in_an_attempts_files_stops_the_campaign(self):
        self.plan(before=["leak"])
        self.assertEqual(self.main(models=(DATED,), scenarios=("comp_gdpr", "comp_none"),
                                   environ=self.env(**KEYS)), 1)
        self.assertIn("OPENAI_API_KEY_BEFORE's key is in calls/run-1/batch-00001.response", self.stderr)
        self.assertTrue(self.doc()["stopped"].startswith("runner error: "))
        self.assertEqual(len(self.events()), 1)


class TestInputs(Base):
    def test_model_ids(self):
        parse = ctx_runner.parse_models
        self.assertEqual(parse([DATED, "anthropic/claude-haiku-4-5-20251001", "mock/mock"], []),
                         [{"provider": "openai", "model": "gpt-5.4-mini-2026-03-17", "dated": True},
                          {"provider": "anthropic", "model": "claude-haiku-4-5-20251001", "dated": True},
                          {"provider": "mock", "model": "mock", "dated": None}])
        for given in (["openai/gpt-5.4-mini"], ["anthropic/claude-sonnet-4-6"], ["mock/other"], ["gpt-5.4-mini"],
                      ["openai/../x"], [DATED, DATED]):
            with self.assertRaises(Refused):
                parse(given, [])
        self.assertEqual(parse(["anthropic/claude-sonnet-4-6"], ["claude-sonnet-4-6"]),
                         [{"provider": "anthropic", "model": "claude-sonnet-4-6", "dated": False}])
        with self.assertRaisesRegex(Refused, "no --model names it"):
            parse([DATED], ["claude-sonnet-4-6"])

    def test_the_binaries_and_their_commits(self):
        self.assertEqual(self.main(bins={"before": self.bins["after"], "after": self.bins["after"]}), 1)
        self.assertIn("one binary", self.stderr)
        self.assertEqual(self.main(commits=("43ab10b", s.AFTER_SHA)), 1)
        self.assertIn("give the full commit", self.stderr)
        self.assertEqual(self.main(commits=(s.AFTER_SHA, s.AFTER_SHA)), 1)
        self.assertIn("one commit", self.stderr)

    def test_the_record_names_what_ran(self):
        self.assertEqual(self.main(), 0)
        doc = self.doc()
        self.assertEqual({arm: (v["vens_sha"], v["binary_sha256"]) for arm, v in doc["arms"].items()},
                         {"before": (s.BEFORE_SHA, runvens.sha256(self.bins["before"])),
                          "after": (s.AFTER_SHA, runvens.sha256(self.bins["after"]))})
        self.assertEqual((doc["corpus"]["freeze_sha256"], doc["retry_cap"], doc["timeout_seconds"], doc["stopped"]),
                         (campaign.FROZEN, 3, 30, None))
        rec = self.record(at("after", 1))
        self.assertEqual((rec["vens_sha"], rec["vens_binary_sha256"], rec["llm_batch_size"], rec["freeze_sha256"]),
                         (s.AFTER_SHA, runvens.sha256(self.bins["after"]), 1, campaign.FROZEN))
        command = rec["command"]
        self.assertEqual(command[:2] + command[command.index("--llm-batch-size"):][:2],
                         ["vens", "generate", "--llm-batch-size", "1"])
        self.assertIn("--attest", command)
        self.assertEqual(command[command.index("--debug-dir") + 1], os.path.join(at("after", 1), "calls"))
        self.assertFalse({"--llm-temperature", "--llm-seed", "--strict"} & set(command))
        with open(os.path.join(self.out, campaign.SUMS)) as fh:
            sums = dict(reversed(line.rstrip("\n").split("  ", 1)) for line in fh)
        files = {os.path.relpath(os.path.join(d, n), self.out) for d, _, names in os.walk(self.out) for n in names}
        self.assertEqual(set(sums), files - {campaign.SUMS})
        self.assertTrue(all(runvens.sha256(os.path.join(self.out, p)) == h for p, h in sums.items()))
        for p in files:
            with open(os.path.join(self.out, p), "rb") as fh:
                self.assertNotIn(self.dir.encode(), fh.read(), p)


class TestTheFreeze(Base):
    def corpus(self):
        root = os.path.join(self.dir, "repo")
        shutil.copytree(os.path.join(ROOT, campaign.SCENARIOS), os.path.join(root, campaign.SCENARIOS))
        shutil.copy(os.path.join(ROOT, campaign.FREEZE), os.path.join(root, campaign.FREEZE))
        return root

    def refused(self, root, message):
        self.assertEqual(self.main("--root", root), 1)
        self.assertIn(message, self.stderr)
        self.assertEqual((self.events(), os.path.exists(self.out)), ([], False))

    def test_the_committed_corpus_is_the_frozen_one(self):
        sha, ids = campaign.check_corpus(ROOT)
        self.assertEqual((sha, len(ids)), (campaign.FROZEN, 46))
        self.assertEqual(campaign.check_corpus(self.corpus()), (sha, ids))

    def test_a_scenario_changed(self):
        root = self.corpus()
        with open(os.path.join(root, "scenarios", "comp_none", "config.yaml"), "a") as fh:
            fh.write("\n")
        self.refused(root, "scenarios/comp_none/config.yaml changed")

    def test_a_file_added_or_missing(self):
        root = self.corpus()
        s.write(os.path.join(root, "scenarios", "extra", "config.yaml"), "x")
        self.refused(root, "scenarios/extra/config.yaml not in the freeze")
        shutil.rmtree(os.path.join(root, "scenarios", "extra"))
        os.remove(os.path.join(root, "scenarios", "crit_low", "report.json"))
        self.refused(root, "scenarios/crit_low/report.json missing")

    def test_the_corpus_frozen_again(self):
        root = self.corpus()
        path = os.path.join(root, "scenarios", "comp_none", "config.yaml")
        with open(path, "a") as fh:
            fh.write("\n")
        with open(os.path.join(root, campaign.FREEZE)) as fh:
            freeze = json.load(fh)
        freeze["files"]["scenarios/comp_none/config.yaml"] = runvens.sha256(path)
        s.write(os.path.join(root, campaign.FREEZE), freeze)
        self.refused(root, "not the frozen corpus's")


class TestTheReader(Base):
    def test_a_campaign_through_the_command_line(self):
        self.assertEqual(self.main(), 0)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(read.main([self.out]), 0)
        recs = [json.loads(x) for x in out.getvalue().splitlines()]
        self.assertEqual([(r["what"]["arm"], r["what"]["campaign"], r["what"]["retry_cap"]) for r in recs],
                         [("before", "c1", 3), ("after", "c1", 3)])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(read.main(["--arm", "after", self.out]), 1)
        self.assertIn("a scenario campaign", err.getvalue())

    def test_an_archive_that_lost_an_attempt_is_refused(self):
        self.plan(before=["fail", "ok"])
        self.assertEqual(self.main(), 0)
        shutil.rmtree(os.path.join(self.out, at("after", 1)))
        with self.assertRaisesRegex(Refused, "after of replicate 1 .* ran to its end: a truncated archive"):
            campaign.read_campaign(self.out)
        shutil.rmtree(os.path.join(self.out, at("before", 1)))
        with self.assertRaisesRegex(Refused, "numbered with a gap"):
            campaign.read_campaign(self.out)

    def test_a_record_that_contradicts_the_campaign_is_refused(self):
        self.assertEqual(self.main(), 0)
        rec = self.record(at("after", 1))
        runvens.write_json(os.path.join(self.out, at("after", 1), "attempt.json"), {**rec, "vens_sha": s.BEFORE_SHA})
        with self.assertRaisesRegex(Refused, "attempt.json gives vens_sha"):
            campaign.read_campaign(self.out)

    def test_a_runner_killed_mid_attempt(self):
        # what a SIGKILL of the runner leaves: the attempt's start recorded, no end, campaign.json never completed
        self.assertEqual(self.main(scenarios=("comp_gdpr", "comp_none")), 0)
        rec = self.record(at("after", 1))
        runvens.write_json(os.path.join(self.out, at("after", 1), "attempt.json"),
                           {**rec, "generate": {**rec["generate"], "ended_at": None, "exit_status": None}})
        shutil.rmtree(os.path.join(self.out, "mock", "mock", "r1", "comp_none"))
        runvens.write_json(os.path.join(self.out, campaign.CAMPAIGN), {**self.doc(), "ended_at": None})
        recs = campaign.read_campaign(self.out)
        killed = recs[1]
        self.assertEqual((killed["outcome"], killed["failure"]["kind"], killed["failure"]["cause"]),
                         ("failed", "interrupted", None))
        self.assertIn("failure.cause", killed["unknown"])
        self.assertEqual([r["outcome"] for r in recs[2:]], [None, None])


class MockCampaign(Base):
    """On vens's own mock at both commits; each arm's binary behind a wrapper where the test needs one."""

    @classmethod
    def setUpClass(cls):
        cls.real = {"after": s.env("VB_VENS_AFTER"), "before": s.env("VB_VENS_BEFORE")}
        if None in cls.real.values():
            raise unittest.SkipTest("set VB_VENS_AFTER and VB_VENS_BEFORE to vens binaries built from b7c0435 and "
                                    "43ab10b to run the runner on the mock")
        with open(os.path.join(ROOT, "scenarios", "comp_gdpr", "report.json")) as fh:
            cls.cve = json.load(fh)["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"]

    def wrapped(self, modes):
        out = {}
        for arm in ARMS:
            path = s.write(os.path.join(self.dir, "wrap", f"vens-{arm}"), WRAPPER.format(
                python=sys.executable, count=os.path.join(self.state, f"wrap-{arm}"), binary=self.real[arm],
                modes=modes))
            os.chmod(path, 0o755)
            out[arm] = path
        return out


class TestOnTheMock(MockCampaign):
    def test_vens_mock_llm_fail_gives_a_failed_attempt_then_a_complete_one(self):
        self.assertEqual(self.main(bins=self.wrapped(["fail"])), 0)
        recs = self.read()
        for arm in ARMS:
            failed, done = recs[(1, "comp_gdpr", arm, 1)], recs[(1, "comp_gdpr", arm, 2)]
            self.assertEqual(failed["failure"], {"kind": "scoring", "step": "generate", "cause_source": "vens log",
                                                 "cause": "failed to generate risk scores: " + FORCED}, arm)
            self.assertEqual((failed["summary"]["llm_calls"], failed["calls"]["archived"], failed["retry_cap_reached"]),
                             (1, 1, False))
            self.assertEqual((done["outcome"], done["scores_usable"], done["problems"], done["models_attested"][0]),
                             ("complete", True, [], ["mock", "mock"]))
        self.assertEqual(recs[(1, "comp_gdpr", "after", 2)]["answers"]["rated"], 1)
        with open(os.path.join(self.out, at("after", 2), "vens.log")) as fh:
            self.assertNotIn(self.dir, fh.read())

    def test_vens_mock_llm_skip_gives_the_omission_stop_up_to_the_retry_cap(self):
        environ = self.env(VENS_MOCK_LLM_SKIP=self.cve)
        self.assertEqual(self.main(bins=self.real, cap=2, environ=environ), ctx_runner.EXIT_CAP_REACHED)
        self.assertEqual(self.doc()["mock_env"], {"VENS_MOCK_LLM_SKIP": self.cve})
        recs = self.read()
        for arm, cause in (("before", SKIPPED_BEFORE), ("after", SKIPPED)):
            for k in (1, 2):
                rec = recs[(1, "comp_gdpr", arm, k)]
                self.assertEqual(rec["failure"], {"kind": "scoring", "step": "generate", "cause_source": "vens log",
                                                  "cause": "failed to generate risk scores: " + cause.format(
                                                      cve=self.cve)})
                summ = rec["summary"]
                self.assertEqual((summ["failed"], summ["llm_calls"], summ["asked_again"]), (True, 2, 1))
                self.assertEqual((rec["recovery"]["planned"], rec["recovery"]["again_omission"]), (1, 1))
                self.assertEqual(rec["retry_cap_reached"], k == 2)
            self.assertEqual(self.record(at(arm, 1))["mock_env"], {"VENS_MOCK_LLM_SKIP": self.cve})

    def test_a_timeout_then_a_complete_attempt(self):
        self.assertEqual(self.main(bins=self.wrapped(["sleep"]), timeout=2), 0)
        recs = self.read()
        for arm in ARMS:
            killed, done = recs[(1, "comp_gdpr", arm, 1)], recs[(1, "comp_gdpr", arm, 2)]
            self.assertEqual((killed["outcome"], killed["failure"]["cause"], killed["steps"]["generate"]["timed_out"]),
                             ("failed", "timeout", True))
            self.assertEqual((done["outcome"], done["scores_usable"]), ("complete", True))


if __name__ == "__main__":
    unittest.main()
