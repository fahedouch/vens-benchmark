"""The scenario runner (ctx_runner.py) and the reading of its campaigns. Its order, parallelism, retries, record
check, timeout, guard, signals, sealing, keys, model ids, input snapshot and freeze on a fake vens that calls nothing;
on vens's own mock at both commits, a failed attempt then a complete one, the omission stop up to the retry cap, and
a timeout, read back by the reader. No model is called and no real key is used."""
import base64
import concurrent.futures
import contextlib
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import ctx_runner
from chain import attempt, campaign, read, runvens
from chain.errors import Refused
from tests import support as s
from tests.test_mock_runs import FORCED, SKIPPED, SKIPPED_BEFORE

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARMS = ("before", "after")
KEYS = {"OPENAI_API_KEY_BEFORE": "sk-fake-before-0001", "OPENAI_API_KEY_AFTER": "sk-fake-after-0002"}
DATED = "openai/gpt-5.4-mini-2026-03-17"
OPENAI = ("openai", "gpt-5.4-mini-2026-03-17")
# Variables Python sets in its own environment at startup, not given by the runner.
PYTHON_ADDS = {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}

# The fake vens: ROOT, ARM and STATE are set above this body. On success it leaves a complete record, built with
# tests/support.py. Each call takes the next mode of plan.json's list for "<arm>/<scenario>", else for its arm, else
# the default: ok; fail; sleep (killed at the timeout); echo, its arm's key's forms (plan.json's forms) in its log;
# leak, in a debug file too; no_answers, no_attestation; bad_calls, a folder where a call's file should be;
# straggler, a child that keeps its stderr; escape, the same child in a session of its own; tamper, its config
# changed; barrier, waiting until plan.json's width calls run at once.
FAKE_VENS = r'''
import fcntl, json, os, subprocess, sys, time
sys.path.insert(0, ROOT)
from tests import support as s
args = sys.argv[1:]
arg = lambda flag: args[args.index(flag) + 1]
config, report, out, calls = arg("--config-file"), args[-2], args[-1], arg("--debug-dir")
scenario, provider = config.split("/")[1], arg("--llm")
model = os.environ.get("OPENAI_MODEL") or os.environ.get("ANTHROPIC_MODEL") or "mock"
key = os.environ.get("OPENAI_API_KEY", "")

def locked(change):
    with open(os.path.join(STATE, "lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return change()

def bump(name, by):
    path = os.path.join(STATE, name)
    value = (int(open(path).read()) if os.path.exists(path) else 0) + by
    open(path, "w").write(str(value))
    return value

def event(kind, **kw):
    with open(os.path.join(STATE, "events.jsonl"), "a") as fh:
        fh.write(json.dumps({"arm": ARM, "scenario": scenario, "folder": os.path.dirname(out), "event": kind,
                             "t": time.time(), "pid": os.getpid(), **kw}) + "\n")

def log(level, msg, **kw):
    fields = "".join(f" {k}={json.dumps(v)}" for k, v in kw.items())
    sys.stderr.write(f"time=2026-11-20T10:00:00.000Z level={level} msg={json.dumps(msg)}{fields}\n")
    sys.stderr.flush()

plan = json.load(open(os.path.join(STATE, "plan.json")))
own = ARM + "/" + scenario if ARM + "/" + scenario in plan else ARM
n = locked(lambda: bump("count-" + own.replace("/", "-"), 1) - 1)
modes = plan.get(own, [])
mode = modes[n] if n < len(modes) else plan.get("default", "ok")
event("start", mode=mode, env=sorted(os.environ), model=os.environ.get("OPENAI_MODEL"), key=key, cwd=os.getcwd(),
      config_mode=oct(os.stat(config).st_mode & 0o777))
if mode == "barrier":
    # tickets in arrival order: a wave of width calls is released once its last ticket is taken
    ticket = locked(lambda: bump("tickets", 1) - 1)
    wave_end, end = (ticket // plan["width"] + 1) * plan["width"], time.time() + 5
    while locked(lambda: bump("tickets", 0)) < wave_end and time.time() < end:
        time.sleep(0.02)
    event("barrier", released=locked(lambda: bump("tickets", 0)) >= wave_end)
if mode == "sleep":
    time.sleep(60)
if mode == "fail":
    log("ERROR", "Error", error="failed to generate risk scores: fake failure")
    event("end")
    sys.exit(1)
if mode in ("straggler", "escape"):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=mode == "escape")
    event("child", child=child.pid)
if mode == "tamper":
    os.chmod(config, 0o644)
    with open(config, "a") as fh:
        fh.write("\n")
with open(report) as fh:
    cve = json.load(fh)["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"]
made = s.after_calls(cve) if ARM == "after" else s.before_calls(cve)
s.write_calls(os.path.join(calls, "run-1"), made)
if mode == "bad_calls":
    os.makedirs(os.path.join(calls, "run-1", "batch-00009.system.prompt"))
if mode != "no_attestation":
    s.write(out[:-len(".cdx.json")] + ".attestation.cdx.json", s.attestation(made, provider, model))
s.write(out, s.vex([(cve, s.VECTOR, s.SEVERITY, s.SCORE)]))
if ARM == "after" and mode != "no_answers":
    s.write(os.path.join(calls, "run-1", "answers.json"), s.answers_doc([(cve, s.VECTOR)]))
if mode in ("echo", "leak"):
    for form in plan["forms"][ARM]:
        log("WARN", "a key in the log", key=form)
if mode == "leak":
    with open(os.path.join(calls, "run-1", "batch-00001.response"), "w") as fh:
        fh.write(" ".join(plan["forms"][ARM]))
log("INFO", "Scoring run finished", rows=1, cves=1, llm_calls=len(made), asked_again=0, splits=0, failed=False)
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

# A runner that runs one vens through chain.runvens and is SIGKILLed once HOOK, one of runvens's steps, has returned
# and the pid file WAIT, if any, is there. ROOT, HOOK, WAIT, PIDS, CMD and FOLDER are set above this body.
PARENT = r'''
import os, signal, sys, time
sys.path.insert(0, ROOT)
from chain import runvens
real = getattr(runvens, HOOK)

def hooked(*args, **kw):
    out = real(*args, **kw)
    if HOOK == "_guard":
        open(os.path.join(PIDS, "guard"), "w").write(str(out.pid))
    end = time.time() + 5
    while WAIT and not os.path.exists(os.path.join(PIDS, WAIT)) and time.time() < end:
        time.sleep(0.02)
    os.kill(os.getpid(), signal.SIGKILL)

setattr(runvens, HOOK, hooked)
runvens.run(CMD, FOLDER, {}, env={"PATH": os.environ.get("PATH", "")}, timeout=60)
'''

# The vens that PARENT runs: it writes its pid, then sleeps, or leaves a child of its group running and exits 0.
SLEEPER = r'''
import os, subprocess, sys, time
mode, pids = sys.argv[1], sys.argv[2]
open(os.path.join(pids, "vens"), "w").write(str(os.getpid()))
if mode == "straggler":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    open(os.path.join(pids, "straggler"), "w").write(str(child.pid))
    sys.exit(0)
time.sleep(60)
'''


def forms(key):
    """The key as a log or a file could hold it: itself, its base64 alone, inside a longer encoded text at another
    byte alignment, and masked the way an SDK shows it."""
    return [key, base64.b64encode(key.encode()).decode(), "Basic " + base64.b64encode(b"u:" + key.encode()).decode(),
            key[:8] + "…" + key[-4:]]


def gone(pid, wait=5.0):
    end = time.time() + wait
    while time.time() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def overlap(starts, ends):
    """The most intervals open at once, an end counted before a start at the same time."""
    marks = sorted([(t, 1) for t in starts] + [(t, -1) for t in ends], key=lambda m: (m[0], m[1]))
    most = now = 0
    for _, step in marks:
        now += step
        most = max(most, now)
    return most


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
                       f"#!{sys.executable}\nROOT, ARM, STATE = {ROOT!r}, {arm!r}, {self.state!r}\n{FAKE_VENS}")
        os.chmod(path, 0o755)
        return path

    def plan(self, **modes):
        s.write(os.path.join(self.state, "plan.json"), modes)

    def env(self, **extra):
        return {"PATH": os.environ.get("PATH", ""), "HOME": self.dir, **extra}

    def argv(self, *extra, models=("mock/mock",), scenarios=("comp_gdpr",), replicates=1, cap=3, timeout=30,
             parallel=1, bins=None, commits=(s.BEFORE_SHA, s.AFTER_SHA)):
        bins = bins or self.bins
        argv = ["--campaign", "c1", "--out", self.out, "--before", bins["before"], "--before-commit", commits[0],
                "--after", bins["after"], "--after-commit", commits[1], "--replicates", str(replicates),
                "--retry-cap", str(cap), "--timeout", str(timeout), "--parallel", str(parallel)]
        argv += [x for m in models for x in ("--model", m)] + [x for sc in scenarios for x in ("--scenario", sc)]
        return argv + list(extra)

    def main(self, *extra, environ=None, **kw):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ctx_runner.main(self.argv(*extra, **kw), environ=self.env() if environ is None else environ)
        self.stdout, self.stderr = out.getvalue(), err.getvalue()
        return code

    def events(self, kind="start"):
        path = os.path.join(self.state, "events.jsonl")
        if not os.path.exists(path):
            return []
        with open(path) as fh:
            return [e for e in map(json.loads, fh) if e["event"] == kind]

    def started(self):
        path = os.path.join(self.state, "events.jsonl")
        return os.path.exists(path) and '"start"' in open(path).read()

    def signal_once_started(self, *signums):
        def send():
            end = time.time() + 30
            while time.time() < end and not self.started():
                time.sleep(0.05)
            for signum in signums:
                os.kill(os.getpid(), signum)

        threading.Thread(target=send, daemon=True).start()

    def record(self, rel):
        with open(os.path.join(self.out, rel, "attempt.json")) as fh:
            return json.load(fh)

    def rewrite(self, rel, **fields):
        runvens.write_json(os.path.join(self.out, rel, "attempt.json"), {**self.record(rel), **fields})

    def doc(self):
        with open(os.path.join(self.out, campaign.CAMPAIGN)) as fh:
            return json.load(fh)

    def reseal(self):
        """failures.jsonl and SHA256SUMS written again, as a consistent rewrite of the archive would leave them."""
        campaign.write_failures(self.out)
        campaign.write_sums(self.out)

    def read(self):
        return {(r["what"]["replicate"], r["what"]["scenario"], r["what"]["arm"], r["what"]["run_attempt"]): r
                for r in campaign.read_campaign(self.out)}

    def files(self):
        return [os.path.join(d, n) for d, _, names in os.walk(self.out) for n in names]

    def key_forms_held(self):
        held = []
        for path in self.files():
            with open(path, "rb") as fh:
                data = fh.read()
            held += [(os.path.relpath(path, self.out), f) for k in KEYS.values() for f in forms(k)
                     if f.encode() in data]
        return held


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
        # three workers, two units each: four waves of three calls, each released once its three have started
        self.assertEqual([e["released"] for e in self.events("barrier")], [True] * 12)
        starts, ends = [e["t"] for e in self.events()], [e["t"] for e in self.events("end")]
        self.assertEqual((len(starts), len(ends), overlap(starts, ends)), (12, 12, 3))
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
        for arm, k in (("before", 2), ("after", 1)):
            rec = recs[(1, "comp_gdpr", arm, k)]
            self.assertEqual((rec["outcome"], rec["scores_usable"], rec["problems"]), ("complete", True, []))
            self.assertEqual(rec["steps"]["record_check"], {"passed": True, "cause": None})
        self.assertEqual(len(recs), 3)

    def test_an_incomplete_record_is_a_failed_attempt_with_its_cause(self):
        self.plan(after=["no_answers", "ok"], before=["no_attestation"] * 2)
        self.assertEqual(self.main(cap=2), ctx_runner.EXIT_CAP_REACHED)
        recs = self.read()
        gap = recs[(1, "comp_gdpr", "after", 1)]
        self.assertEqual(gap["failure"], {"kind": "later_step", "step": "record_check", "cause": "no answers.json",
                                          "cause_source": "attempt.json"})
        self.assertEqual((gap["outcome"], gap["steps"]["generate"]["exit_status"]), ("failed", 0))
        self.assertEqual(recs[(1, "comp_gdpr", "after", 2)]["outcome"], "complete")
        last = recs[(1, "comp_gdpr", "before", 2)]
        self.assertEqual((last["failure"]["cause"].split(";")[0], last["retry_cap_reached"]), ("no attestation", True))
        self.assertIn(f"{at('after', 1)}: failed, the record check: no answers.json", self.stdout)

    def test_calls_that_do_not_read_are_a_gap_not_a_stop(self):
        self.plan(before=["bad_calls", "ok"])
        self.assertEqual(self.main(), 0)
        recs = self.read()
        bad = recs[(1, "comp_gdpr", "before", 1)]
        self.assertEqual((bad["failure"]["step"], bad["steps"]["generate"]["exit_status"]), ("record_check", 0))
        self.assertIn("a call that does not read", bad["failure"]["cause"])
        self.assertEqual(recs[(1, "comp_gdpr", "before", 2)]["outcome"], "complete")

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

    def test_a_child_holding_stderr_is_killed_with_vens_group(self):
        self.plan(before=["straggler"])
        began = time.time()
        self.assertEqual(self.main(timeout=30), 0)
        self.assertLess(time.time() - began, 10)
        (child,) = self.events("child")
        self.assertTrue(gone(child["child"]))
        self.assertEqual(self.record(at("before", 1))["generate"]["log_complete"], True)

    def test_a_child_out_of_vens_group_holding_stderr_bounds_the_drain(self):
        self.plan(before=["escape"])
        with mock.patch.object(runvens, "DRAIN", 0.3):
            began = time.time()
            code = self.main(timeout=30)
        (child,) = self.events("child")
        os.kill(child["child"], signal.SIGKILL)
        self.assertEqual(code, 1)
        self.assertLess(time.time() - began, 10)
        cause = ("vens's log was not written whole: a write failed, or a process out of vens's group kept its stderr "
                 "open")
        self.assertIn(cause, self.stderr)
        rec = self.record(at("before", 1))
        self.assertEqual((rec["generate"]["log_complete"], rec["record_check"]), (False, {"passed": False,
                                                                                        "cause": cause}))
        got = self.read()[(1, "comp_gdpr", "before", 1)]
        self.assertEqual((got["failure"]["step"], got["failure"]["cause"], got["steps"]["generate"]["exit_status"]),
                         ("record_check", cause, 0))

    def test_the_failures_index(self):
        self.plan(before=["fail", "ok"])
        self.assertEqual(self.main(), 0)
        with open(os.path.join(self.out, campaign.FAILURES)) as fh:
            (line,) = map(json.loads, fh)
        self.assertEqual({k: line[k] for k in ("folder", "arm", "attempt", "kind", "cause", "retry_cap_reached")},
                         {"folder": at("before", 1), "arm": "before", "attempt": 1, "kind": "scoring",
                          "cause": "failed to generate risk scores: fake failure", "retry_cap_reached": False})
        s.write(os.path.join(self.out, campaign.FAILURES), "")
        campaign.write_sums(self.out)
        with self.assertRaisesRegex(Refused, "failures.jsonl lists 0 failed attempts, the attempt records give 1"):
            campaign.read_campaign(self.out)
        s.write(os.path.join(self.out, at("before", 1), "attempt.json"), "{cut")
        (entry,) = campaign.failures(self.out)
        self.assertTrue(entry["cause"].startswith("the reader could not read it: "), entry)


class TestRunvens(Base):
    def test_an_error_between_the_start_and_the_end_kills_vens(self):
        folder, pidfile = os.path.join(self.dir, "a"), os.path.join(self.dir, "pid")
        cmd = [sys.executable, "-c", f"import os, time; open({pidfile!r}, 'w').write(str(os.getpid())); "
                                     f"time.sleep(60)"]

        def failing_drain(*args):
            end = time.time() + 10
            while time.time() < end and not os.path.exists(pidfile):
                time.sleep(0.05)
            raise RuntimeError("no thread for the log")

        with mock.patch.object(runvens, "_drain", failing_drain):
            with self.assertRaisesRegex(RuntimeError, "no thread for the log"):
                runvens.run(cmd, folder, {}, env={}, timeout=60)
        with open(pidfile) as fh:
            self.assertTrue(gone(int(fh.read())))
        self.assertEqual(runvens._LIVE, set())
        gen = self.record(folder)["generate"]
        self.assertEqual((gen["exit_status"], gen["interrupted"]),
                         (None, "the runner failed: RuntimeError('no thread for the log')"))

    def test_a_launch_that_fails_is_read_as_such(self):
        folder = os.path.join(self.dir, "a")
        with self.assertRaisesRegex(OSError, "vens did not start: "):
            runvens.run([os.path.join(self.dir, "no-vens")], folder, {"runner": "scenarios", "arm": "after"}, env={})
        rec = self.record(folder)
        self.assertEqual(rec["generate"]["started_at"], None)
        self.assertTrue(rec["setup_error"].startswith("vens did not start: "))
        for started in (None, "2026-11-20T10:00:00.000000Z"):
            self.rewrite(folder, generate={**rec["generate"], "started_at": started})
            got = attempt.read_attempt(folder)
            self.assertEqual((got["outcome"], got["failure"]["cause"], got["failure"]["cause_source"]),
                             ("failed", rec["setup_error"], "attempt.json"), started)

    def test_vens_gets_exactly_its_environment(self):
        folder, out = os.path.join(self.dir, "a"), os.path.join(self.dir, "env.json")
        cmd = [sys.executable, "-S", "-c", f"import json, os; json.dump(dict(os.environ), open({out!r}, 'w'))"]
        rec = runvens.run(cmd, folder, {}, env={"PATH": "/usr/bin", "A_KEY": "sk-x"})
        self.assertEqual(rec["generate"]["exit_status"], 0)
        with open(out) as fh:
            self.assertEqual(set(json.load(fh)) - PYTHON_ADDS, {"PATH", "A_KEY"})

    def kill_the_runner_at(self, hook, mode, wait=None):
        """PARENT run on SLEEPER, SIGKILLed after hook: the pid files it leaves."""
        pids = os.path.join(self.dir, "pids")
        os.makedirs(pids)
        sleeper = s.write(os.path.join(self.dir, "sleeper.py"), SLEEPER)
        header = (f"ROOT, HOOK, WAIT, PIDS = {ROOT!r}, {hook!r}, {wait!r}, {pids!r}\n"
                  f"CMD, FOLDER = {[sys.executable, sleeper, mode, pids]!r}, {os.path.join(self.dir, 'a')!r}\n")
        parent = s.write(os.path.join(self.dir, "parent.py"), header + PARENT)
        done = subprocess.run([sys.executable, parent], timeout=60)
        self.assertEqual(done.returncode, -signal.SIGKILL)
        return {n: int(open(os.path.join(pids, n)).read()) for n in os.listdir(pids)}

    def test_a_runner_killed_once_the_guard_runs_leaves_nothing(self):
        pids = self.kill_the_runner_at("_guard", "sleep")
        self.assertTrue(gone(pids["guard"]))
        if "vens" in pids:
            self.assertTrue(gone(pids["vens"]))

    def test_a_runner_killed_while_vens_runs_leaves_nothing(self):
        pids = self.kill_the_runner_at("_drain", "sleep", wait="vens")
        self.assertTrue(gone(pids["vens"]))

    def test_a_runner_killed_after_vens_ended_leaves_no_child_of_it(self):
        pids = self.kill_the_runner_at("_report", "straggler")
        self.assertTrue(gone(pids["straggler"]))
        self.assertTrue(gone(pids["vens"]))


class TestSignals(Base):
    def stopped(self, signum, code, *more):
        self.plan(before=["sleep"])
        self.signal_once_started(signum, *more)
        began = time.time()
        self.assertEqual(self.main(scenarios=("comp_gdpr", "comp_none"), timeout=60), code)
        self.assertLess(time.time() - began, 15)
        (started,) = self.events()
        self.assertTrue(gone(started["pid"]))
        doc = self.doc()
        self.assertEqual((doc["stopped"], doc["ended_at"] is not None),
                         (f"interrupted: {signal.Signals(signum).name}", True))
        gen = self.record(at("before", 1))["generate"]
        self.assertEqual((gen["exit_status"], gen["interrupted"]), (None, runvens.STOPPED))
        recs = campaign.read_campaign(self.out)
        self.assertEqual(recs[0]["failure"]["cause"], "the runner was stopped")
        self.assertEqual([(r["outcome"], r["what"]["scenario"], r["what"]["arm"]) for r in recs[1:]],
                         [(None, "comp_gdpr", "after"), (None, "comp_none", "before"), (None, "comp_none", "after")])

    def test_sigterm(self):
        self.stopped(signal.SIGTERM, 143)

    def test_sighup(self):
        self.stopped(signal.SIGHUP, 129)

    def test_a_second_signal_while_stopping_changes_nothing(self):
        self.stopped(signal.SIGINT, 130, signal.SIGINT, signal.SIGTERM)

    def test_a_signal_while_stopping_after_a_worker_error(self):
        self.plan(**{"before/comp_gdpr": ["tamper"], "before/comp_none": ["sleep"]})
        report = runvens._report

        def signalled_report(guard, deadline, stop):
            line, why = report(guard, deadline, stop)
            if why == runvens.STOPPED:
                # the main thread now waits for this worker in the pool's shutdown
                time.sleep(0.5)
                os.kill(os.getpid(), signal.SIGINT)
                time.sleep(0.3)
            return line, why

        with mock.patch.object(runvens, "_report", signalled_report):
            code = self.main(scenarios=("comp_gdpr", "comp_none"), parallel=2, timeout=60)
        self.assertEqual(code, 1)
        self.assertTrue(self.doc()["stopped"].startswith("runner error: "))
        self.assertTrue(os.path.exists(os.path.join(self.out, campaign.FAILURES)))
        campaign.check_sums(self.out)
        (slept,) = [e for e in self.events() if e["mode"] == "sleep"]
        self.assertTrue(gone(slept["pid"]))

    def test_sigterm_while_the_units_are_submitted(self):
        self.plan(default="sleep")
        submit, calls = concurrent.futures.ThreadPoolExecutor.submit, []

        def signalling_submit(ex, *args, **kw):
            calls.append(1)
            if len(calls) == 2:
                os.kill(os.getpid(), signal.SIGTERM)
            return submit(ex, *args, **kw)

        began = time.time()
        with mock.patch.object(concurrent.futures.ThreadPoolExecutor, "submit", signalling_submit):
            code = self.main(scenarios=("comp_gdpr", "comp_none", "crit_low"), timeout=60)
        self.assertEqual(code, 143)
        self.assertLess(time.time() - began, 15)
        self.assertLessEqual(len(self.events()), 1)
        self.assertTrue(all(gone(e["pid"]) for e in self.events()))
        self.assertEqual(self.doc()["stopped"], "interrupted: SIGTERM")

    def test_sigkill_of_the_runner_leaves_no_vens_running(self):
        self.plan(before=["sleep"])
        runner = subprocess.Popen([sys.executable, os.path.join(ROOT, "ctx_runner.py"), *self.argv(timeout=60)],
                                  env=self.env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 30
        while time.time() < end and not self.started():
            time.sleep(0.05)
        runner.kill()
        runner.wait()
        (started,) = self.events()
        self.assertTrue(gone(started["pid"]))
        self.assertIsNone(self.doc()["ended_at"])


class TestSealing(Base):
    def test_an_error_while_finishing_still_leaves_sums(self):
        with mock.patch.object(campaign, "write_failures", side_effect=RuntimeError("disk full")):
            with self.assertRaisesRegex(RuntimeError, "disk full"):
                self.main()
        campaign.check_sums(self.out)

    def test_an_error_in_the_runner_names_its_cause(self):
        def failing_drain(*args):
            raise OSError("disk full")

        with mock.patch.object(runvens, "_drain", failing_drain):
            self.assertEqual(self.main(), 1)
        self.assertIn(f"stopped: {at('before', 1)}: the runner failed: OSError('disk full')", self.stderr)
        self.assertNotIn("did not start", self.stderr)


class TestKeys(Base):
    def test_each_arm_gets_its_own_key_and_the_model_and_nothing_else(self):
        self.plan(default="echo", forms={arm: forms(KEYS[f"OPENAI_API_KEY_{arm.upper()}"]) for arm in ARMS})
        self.assertEqual(self.main(models=(DATED,), environ=self.env(OPENAI_API_KEY="sk-shared", **KEYS)), 0)
        got = {e["arm"]: e for e in self.events()}
        for arm in ARMS:
            self.assertEqual((got[arm]["key"], got[arm]["model"]),
                             (KEYS[f"OPENAI_API_KEY_{arm.upper()}"], "gpt-5.4-mini-2026-03-17"))
            self.assertEqual(set(got[arm]["env"]) - PYTHON_ADDS, {"PATH", "HOME", "TZ", "OPENAI_MODEL",
                                                                  "OPENAI_API_KEY"})
            rec = self.record(at(arm, 1, model=OPENAI))
            self.assertEqual(rec["key_env"], f"OPENAI_API_KEY_{arm.upper()}")
        self.assertEqual(self.doc()["arms"]["after"]["keys"], {"openai": "OPENAI_API_KEY_AFTER"})
        with open(os.path.join(self.out, at("after", 1, model=OPENAI), "vens.log")) as fh:
            log = fh.read()
        self.assertIn('key="***"', log)
        self.assertNotIn("sk-fake", log)
        self.assertEqual(self.key_forms_held(), [])

    def test_a_key_in_an_attempts_files_is_cut_out_and_stops_the_campaign(self):
        self.plan(before=["leak"], forms={"before": forms(KEYS["OPENAI_API_KEY_BEFORE"])})
        self.assertEqual(self.main(models=(DATED,), scenarios=("comp_gdpr", "comp_none"),
                                   environ=self.env(**KEYS)), 1)
        response = os.path.join("calls", "run-1", "batch-00001.response")
        cause = f"a form of OPENAI_API_KEY_BEFORE's key was in {response}, now cut out"
        self.assertIn(cause, self.stderr)
        doc = self.doc()
        self.assertTrue(doc["stopped"].startswith("runner error: "))
        self.assertEqual(doc["redacted"], [os.path.join(at("before", 1, model=OPENAI), response)])
        rec = self.record(at("before", 1, model=OPENAI))
        self.assertEqual((rec["redacted"], rec["record_check"]), ([response], {"passed": False, "cause": cause}))
        got = self.read()[(1, "comp_gdpr", "before", 1)]
        self.assertEqual((got["failure"]["step"], got["failure"]["cause"], got["steps"]["generate"]["exit_status"]),
                         ("record_check", cause, 0))
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(self.key_forms_held(), [])
        campaign.check_sums(self.out)

    def test_the_whole_archive_is_swept(self):
        # a key in a mock variable reaches campaign.json and the mock's records, which no attempt's own sweep reads
        environ = self.env(VENS_MOCK_LLM_SKIP=KEYS["OPENAI_API_KEY_BEFORE"], **KEYS)
        self.assertEqual(self.main(models=("mock/mock", DATED), environ=environ), 1)
        doc = self.doc()
        self.assertTrue(doc["stopped"].startswith("runner error: a form of a key was in "), doc["stopped"])
        self.assertIn(campaign.CAMPAIGN, doc["redacted"])
        self.assertIn(os.path.join(at("before", 1), "attempt.json"), doc["redacted"])
        self.assertEqual(doc["mock_env"], {"VENS_MOCK_LLM_SKIP": "***"})
        self.assertEqual(self.key_forms_held(), [])
        campaign.check_sums(self.out)
        self.assertEqual(len(campaign.read_campaign(self.out)), 4)

    def test_a_key_suffix(self):
        environ = self.env(**{f"{k}_SCENARIOS": v for k, v in KEYS.items()})
        self.assertEqual(self.main("--key-suffix", "SCENARIOS", models=(DATED,), environ=environ), 0)
        self.assertEqual(self.record(at("after", 1, model=OPENAI))["key_env"], "OPENAI_API_KEY_AFTER_SCENARIOS")
        self.assertEqual({e["arm"]: e["key"] for e in self.events()},
                         {"before": KEYS["OPENAI_API_KEY_BEFORE"], "after": KEYS["OPENAI_API_KEY_AFTER"]})
        shutil.rmtree(self.out)
        self.assertEqual(self.main("--key-suffix", "SCENARIOS", models=(DATED,), environ=self.env(**KEYS)), 1)
        self.assertIn("OPENAI_API_KEY_BEFORE_SCENARIOS is not set", self.stderr)
        self.assertEqual(self.main("--key-suffix", "scenarios", models=(DATED,), environ=environ), 1)
        self.assertIn("capitals, digits and '_' only", self.stderr)

    def test_a_missing_key_stops_the_runner_before_any_call(self):
        self.assertEqual(self.main(models=(DATED,), environ=self.env(OPENAI_API_KEY_BEFORE="sk-1")), 1)
        self.assertIn("OPENAI_API_KEY_AFTER is not set", self.stderr)
        self.assertEqual((self.events(), os.path.exists(self.out)), ([], False))

    def test_one_key_for_both_arms_is_refused(self):
        environ = self.env(OPENAI_API_KEY_BEFORE="sk-1", OPENAI_API_KEY_AFTER="sk-1")
        self.assertEqual(self.main(models=(DATED,), environ=environ), 1)
        self.assertIn("hold one key", self.stderr)
        self.assertEqual(self.events(), [])

    def test_the_key_forms_cut_out(self):
        key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123"
        text = "\n".join(forms(key) + ["Basic " + base64.b64encode(b"ab" + key.encode()).decode(),
                                       base64.urlsafe_b64encode(b"\xff" + key.encode()).decode(), "sk-proj-***0123"])
        clean = runvens.secret_pattern(key).sub(b"***", text.encode()).decode()
        self.assertEqual([line for line in clean.splitlines() if "***" not in line], [])
        self.assertNotIn("abcdefghij", clean)
        self.assertIsNone(runvens.secret_pattern(""))


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
        with self.assertRaisesRegex(Refused, "not a model known to have no dated id"):
            parse(["openai/gpt-5.4-mini"], ["gpt-5.4-mini"])

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
        campaign.check_sums(self.out)
        for path in self.files():
            with open(path, "rb") as fh:
                self.assertNotIn(self.dir.encode(), fh.read(), path)

    def test_the_input_snapshot_is_read_only_and_checked_after_each_attempt(self):
        self.plan(before=["ok", "tamper"])
        self.assertEqual(self.main(scenarios=("comp_gdpr", "comp_none")), 1)
        self.assertEqual({e["config_mode"] for e in self.events()}, {"0o444"})
        config = os.path.join("scenarios", "comp_none", "config.yaml")
        cause = f"{config} changed during the attempt, no longer the frozen corpus's"
        self.assertIn(cause, self.stderr)
        self.assertEqual(self.record(at("before", 1, "comp_none"))["record_check"], {"passed": False, "cause": cause})
        self.assertTrue(self.doc()["stopped"].startswith("runner error: "))
        with self.assertRaisesRegex(Refused, f"{config} changed"):
            campaign.read_campaign(self.out)


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
        files, ids = campaign.check_corpus(ROOT)
        self.assertEqual((runvens.sha256(os.path.join(ROOT, campaign.FREEZE)), len(files), len(ids)),
                         (campaign.FROZEN, 93, 46))
        self.assertEqual(campaign.check_corpus(self.corpus()), (files, ids))

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
        self.assertEqual([(r["what"]["arm"], r["what"]["campaign"], r["what"]["retry_cap"], r["scores_usable"])
                          for r in recs], [("before", "c1", 3, True), ("after", "c1", 3, True)])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(read.main(["--arm", "after", self.out]), 1)
        self.assertIn("a scenario campaign", err.getvalue())

    def test_a_tampered_archive_is_refused(self):
        self.assertEqual(self.main(), 0)
        log = os.path.join(self.out, at("after", 1), "vens.log")
        s.write(os.path.join(self.out, at("after", 1), "vex.cdx.json.123.tmp"), "a kill mid-write")
        campaign.read_campaign(self.out)
        with open(log, "a") as fh:
            fh.write("one more line\n")
        with self.assertRaisesRegex(Refused, "SHA256SUMS does not match the archive: .*vens.log changed"):
            campaign.read_campaign(self.out)
        campaign.write_sums(self.out)
        s.write(os.path.join(self.out, "extra.txt"), "x")
        with self.assertRaisesRegex(Refused, "extra.txt not listed"):
            campaign.read_campaign(self.out)
        os.remove(os.path.join(self.out, campaign.SUMS))
        with self.assertRaisesRegex(Refused, "without its SHA256SUMS"):
            campaign.read_campaign(self.out)

    def test_a_malformed_campaign_or_failures_index_is_refused(self):
        self.assertEqual(self.main(), 0)
        doc = self.doc()
        failures = os.path.join(self.out, campaign.FAILURES)
        s.write(failures, "{cut\n")
        campaign.write_sums(self.out)
        with self.assertRaisesRegex(Refused, "line 1 does not read"):
            campaign.read_campaign(self.out)
        os.remove(failures)
        campaign.write_sums(self.out)
        with self.assertRaisesRegex(Refused, "without its failures.jsonl"):
            campaign.read_campaign(self.out)
        for missing in ("corpus", "arms"):
            runvens.write_json(os.path.join(self.out, campaign.CAMPAIGN),
                               {k: v for k, v in doc.items() if k != missing})
            with self.assertRaisesRegex(Refused, f"campaign.json lacks {missing}"):
                campaign.read_campaign(self.out)

    def test_another_freeze_is_refused_unless_named(self):
        self.assertEqual(self.main(), 0)
        path = os.path.join(self.out, campaign.FREEZE)
        os.chmod(path, 0o644)
        with open(path, "a") as fh:
            fh.write("\n")
        other = runvens.sha256(path)
        runvens.write_json(os.path.join(self.out, campaign.CAMPAIGN),
                           {**self.doc(), "corpus": {**self.doc()["corpus"], "freeze_sha256": other}})
        for arm in ARMS:
            self.rewrite(at(arm, 1), freeze_sha256=other)
        self.reseal()
        with self.assertRaisesRegex(Refused, f"its corpus's freeze is {other}, not {campaign.FROZEN}"):
            campaign.read_campaign(self.out)
        self.assertEqual(len(campaign.read_campaign(self.out, freeze=other)), 2)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(read.main([self.out]), 1)
            self.assertEqual(read.main(["--freeze-sha256", other, self.out]), 0)

    def test_an_input_other_than_the_scenarios_is_refused(self):
        self.assertEqual(self.main(), 0)
        self.rewrite(at("after", 1), config="scenarios/comp_none/config.yaml")
        self.reseal()
        with self.assertRaisesRegex(Refused, "attempt.json gives config"):
            campaign.read_campaign(self.out)

    def test_an_archive_that_lost_an_attempt_is_refused(self):
        self.plan(before=["fail", "ok"])
        self.assertEqual(self.main(), 0)
        shutil.rmtree(os.path.join(self.out, at("after", 1)))
        self.reseal()
        with self.assertRaisesRegex(Refused, "after of replicate 1 .* ran to its end: a truncated archive"):
            campaign.read_campaign(self.out)
        shutil.rmtree(os.path.join(self.out, at("before", 1)))
        self.reseal()
        with self.assertRaisesRegex(Refused, "numbered with a gap"):
            campaign.read_campaign(self.out)

    def test_a_record_that_contradicts_the_campaign_is_refused(self):
        self.assertEqual(self.main(), 0)
        self.rewrite(at("after", 1), vens_sha=s.BEFORE_SHA)
        self.reseal()
        with self.assertRaisesRegex(Refused, "attempt.json gives vens_sha"):
            campaign.read_campaign(self.out)

    def test_a_runner_killed_mid_attempt(self):
        # what a SIGKILL of the runner leaves: the attempt's start recorded, no end, campaign.json never completed,
        # no failures.jsonl and no SHA256SUMS
        self.assertEqual(self.main(scenarios=("comp_gdpr", "comp_none")), 0)
        rec = self.record(at("after", 1))
        self.rewrite(at("after", 1), generate={**rec["generate"], "ended_at": None, "exit_status": None},
                     record_check=None)
        shutil.rmtree(os.path.join(self.out, "mock", "mock", "r1", "comp_none"))
        runvens.write_json(os.path.join(self.out, campaign.CAMPAIGN), {**self.doc(), "ended_at": None})
        for name in (campaign.SUMS, campaign.FAILURES):
            os.remove(os.path.join(self.out, name))
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
            self.assertEqual(done["steps"]["record_check"], {"passed": True, "cause": None})
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
