"""vens-demo's baseline.yml run step by step against a fake vens, as GitHub runs a job: the attempt record each
attempt leaves, read back as the four outcomes; the run name the dispatch script finds its run by; the key each arm
runs on. No test reaches GitHub or a model.

    VB_BASELINE   a baseline.yml that writes the attempt record; PyYAML (requirements.txt) reads it
"""
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace

from chain import attempt, dispatch, read
from tests import support as s

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VID = "CVE-2099-0001"
CAUSE = "failed to generate risk scores: LLM evaluation failed: 503"
DISPATCH_ID = "0f3c9a2b7d41"
SECRETS = {"OPENAI_API_KEY": "shared-openai", "ANTHROPIC_API_KEY": "shared-anthropic",
           "OPENAI_API_KEY_BEFORE": "openai-before", "OPENAI_API_KEY_AFTER": "openai-after",
           "ANTHROPIC_API_KEY_BEFORE": "anthropic-before", "ANTHROPIC_API_KEY_AFTER": "anthropic-after"}
NO_AFTER_KEY = {k: v for k, v in SECRETS.items() if k != "OPENAI_API_KEY_AFTER"}
# The schema chain/attempt.py documents for baseline.yml, in its order.
RECORD_KEYS = ["record", "runner", "arm", "provider", "model", "llm_batch_size", "vens_ref", "vens_sha",
               "vens_binary_sha256", "run_id", "run_attempt", "job", "context", "replicate", "archived_scan", "config",
               "generate", "enrich", "archive_check", "provenance"]
UTC = r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$"

FAKE_VENS = r'''#!{python}
import os, sys, time
sys.path.insert(0, {root!r})
from tests import support as s
mode, args = os.environ["FAKE_VENS"], sys.argv[1:]
if args[0] == "enrich":
    if mode == "enrich-fails":
        sys.exit("Error: enrich failed")
    s.write(os.path.abspath(args[args.index("--output") + 1]), {{"enriched": True}})
    sys.exit(0)
out = os.path.abspath(args[-1])
run_dir = os.path.abspath(os.path.join(args[args.index("--debug-dir") + 1], "run-1"))
before = os.environ["ARM"] == "before"
calls = s.before_calls({vid!r}) if before else s.after_calls({vid!r})
if mode in ("hang", "generate-fails"):
    s.write_calls(run_dir, [(calls[0][0], calls[0][1], None)])
    print(s.line("INFO", "Scoring vulnerabilities", rows=1), file=sys.stderr, flush=True)
    if mode == "hang":
        time.sleep(600)
    print(s.summary_line(rows=1, cves=1, llm_calls=1, asked_again=0, splits=0, failed=True), file=sys.stderr)
    print(s.error_line({cause!r}), file=sys.stderr)
    sys.exit(1)
s.write_calls(run_dir, calls)
if not before:
    s.write(os.path.join(run_dir, "answers.json"), s.answers_doc([({vid!r}, s.VECTOR)]))
model = "another-model" if mode == "archive-fails" else os.environ["MODEL"]
s.write(out[:-len(".cdx.json")] + ".attestation.cdx.json", s.attestation(calls, os.environ["PROVIDER"], model))
s.write(out, s.vex([({vid!r}, s.VECTOR, s.SEVERITY, s.SCORE)]))
summary = dict(rows=2, cves=1, llm_calls=2) if before else dict(rows=1, cves=1, llm_calls=2, calls__M=1, calls__O=1)
print(s.summary_line(**summary, asked_again=0, splits=0, failed=False), file=sys.stderr)
'''


# GitHub's expressions, as far as baseline.yml uses them: && and || give one of their operands.
_TOKEN = re.compile(r"\s*(?:'((?:[^']|'')*)'|(==|!=|&&|\|\||[()!,])|([A-Za-z_][\w.-]*))")


def _text(v):
    return "true" if v is True else "false" if v is False else "" if v is None else str(v)


def _truthy(v):
    return v not in (None, False, "", 0)


class _Expr:
    def __init__(self, expr, ctx):
        self.tokens, self.ctx, self.i, pos, expr = [], ctx, 0, 0, expr.strip()
        while pos < len(expr):
            m = _TOKEN.match(expr, pos)
            if m is None:
                raise ValueError(f"cannot read {expr[pos:]!r}")
            lit, op, name = m.groups()
            self.tokens.append(("lit", lit.replace("''", "'")) if lit is not None else ("op", op) if op else
                               ("name", name))
            pos = m.end()

    def value(self):
        v = self.or_()
        if self.i != len(self.tokens):
            raise ValueError(f"left over: {self.tokens[self.i:]}")
        return v

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else (None, None)

    def take(self, op=None):
        tok = self.peek()
        if op is not None and tok != ("op", op):
            raise ValueError(f"expected {op!r}, got {tok}")
        self.i += 1
        return tok

    def or_(self):
        v = self.and_()
        while self.peek() == ("op", "||"):
            self.take()
            w = self.and_()
            v = v if _truthy(v) else w
        return v

    def and_(self):
        v = self.cmp()
        while self.peek() == ("op", "&&"):
            self.take()
            w = self.cmp()
            v = w if _truthy(v) else v
        return v

    def cmp(self):
        v = self.unary()
        if self.peek() in (("op", "=="), ("op", "!=")):
            op = self.take()[1]
            w = self.unary()
            same = v.casefold() == w.casefold() if isinstance(v, str) and isinstance(w, str) else v == w
            return same if op == "==" else not same
        return v

    def unary(self):
        if self.peek() == ("op", "!"):
            self.take()
            return not _truthy(self.unary())
        return self.primary()

    def primary(self):
        kind, value = self.take()
        if kind == "lit":
            return value
        if (kind, value) == ("op", "("):
            v = self.or_()
            self.take(")")
            return v
        if kind != "name":
            raise ValueError(f"unexpected {value!r}")
        if value in ("true", "false"):
            return value == "true"
        if value == "format":
            self.take("(")
            args = [self.or_()]
            while self.peek() == ("op", ","):
                self.take()
                args.append(self.or_())
            self.take(")")
            return re.sub(r"\{(\d+)\}", lambda m: _text(args[1 + int(m.group(1))]), args[0])
        node = self.ctx
        for part in value.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        # A secret that is not set reads as an empty string.
        return "" if node is None and value.startswith("secrets.") else node


def render(text, ctx):
    return re.sub(r"\$\{\{(.*?)\}\}", lambda m: _text(_Expr(m.group(1), ctx).value()), text)


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def context(arm="after", provider="openai", commit=s.AFTER_SHA, run_id=2001, secrets=None):
    a = SimpleNamespace(archived_run="2026-09-23", provider=provider, model=s.MODEL, batch_size=1, arm=arm)
    return {"inputs": dispatch.inputs(a, commit, DISPATCH_ID),
            "matrix": {"replicate": "1", "context": {"file": "contexts/internal.yaml", "slug": "internal"}},
            "steps": {"build": {"outputs": {"sha": commit}}},
            "github": {"run_id": run_id, "run_attempt": 1, "sha": "f" * 40},
            "secrets": SECRETS if secrets is None else secrets}


class Base(unittest.TestCase):
    def setUp(self):
        path = s.env("VB_BASELINE")
        if path is None:
            self.skipTest("set VB_BASELINE to a vens-demo baseline.yml with the attempt record (see this file)")
        try:
            import yaml
        except ImportError:
            self.fail("VB_BASELINE is set but PyYAML is not installed: pip install -r requirements.txt")
        with open(path, encoding="utf-8") as fh:
            self.wf = yaml.safe_load(fh)
        # YAML 1.1 reads the key `on` as true.
        self.wf["on"] = self.wf.pop(True, self.wf.get("on"))
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.fake = s.write(os.path.join(self.dir, "bin", "vens"),
                            FAKE_VENS.format(python=sys.executable, root=ROOT, vid=VID, cause=CAUSE))
        os.chmod(self.fake, 0o755)

    def step(self, job, key):
        return next(st for st in self.wf["jobs"][job]["steps"] if key in (st.get("id"), st.get("name")))

    def env(self, st, ctx, ws, **extra):
        base = {"PATH": os.environ["PATH"], "HOME": self.dir, "GITHUB_RUN_ID": str(ctx["github"]["run_id"]),
                "GITHUB_RUN_ATTEMPT": str(ctx["github"]["run_attempt"]),
                "GITHUB_OUTPUT": os.path.join(ws, ".output"), "GITHUB_STEP_SUMMARY": os.path.join(ws, ".summary")}
        wide = {k: render(str(v), ctx) for k, v in (self.wf.get("env") or {}).items()}
        mine = {k: render(str(v), ctx) for k, v in (st.get("env") or {}).items()}
        return {**base, **wide, **mine, **extra}

    def bash(self, st, ctx, ws, cancel=False, **extra):
        """Runs a step as the runner does, `bash -e {0}`; with cancel, as the runner cancels it: SIGINT to the shell
        alone once vens has started, SIGTERM after, then whatever the shell left running is killed."""
        script = s.write(os.path.join(self.dir, "step.sh"), render(st["run"], ctx))
        with open(os.path.join(self.dir, "step.out"), "w") as out:
            p = subprocess.Popen(["bash", "-e", script], cwd=ws, env=self.env(st, ctx, ws, **extra), stdout=out,
                                 stderr=subprocess.STDOUT, start_new_session=True)
            if cancel:
                log = os.path.join(ws, "vens-internal.log")
                for _ in range(200):
                    if os.path.exists(log) and os.path.getsize(log):
                        break
                    time.sleep(0.05)
                os.kill(p.pid, signal.SIGINT)
                time.sleep(0.3)
                os.kill(p.pid, signal.SIGTERM)
            rc = p.wait(timeout=60)
            with contextlib.suppress(ProcessLookupError):
                os.killpg(p.pid, signal.SIGKILL)
        return rc

    def output(self):
        with open(os.path.join(self.dir, "step.out")) as fh:
            return fh.read()


class TestRunName(Base):
    def test_the_run_name_is_the_title_the_dispatch_script_looks_for(self):
        for did in (DISPATCH_ID, ""):
            ctx = context()
            ctx["inputs"]["dispatch-id"] = did
            name = render(self.wf["run-name"], ctx)
            self.assertEqual(name, dispatch.title("2026-09-23", "openai", s.MODEL, 1, s.AFTER_SHA, did or None))
            meta = attempt.run_meta({"id": 1, "display_title": name})
            self.assertEqual((meta["model"], meta["vens_ref"], meta["dispatch_id"]),
                             (s.MODEL, s.AFTER_SHA, did or None))

    def test_the_inputs_the_script_passes_are_the_workflows(self):
        declared = self.wf["on"]["workflow_dispatch"]["inputs"]
        passed = context()["inputs"]
        self.assertEqual(set(passed) - set(declared), set())
        self.assertEqual({k for k, v in declared.items() if v.get("required")} - set(passed), set())
        self.assertEqual(declared["arm"]["options"], list(dispatch.ARMS))


class TestKeys(Base):
    def keys(self, **kw):
        st = self.step("score", "vens")
        return {k: render(st["env"][k], context(**kw)) for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY")}

    def test_each_arm_runs_on_its_own_key(self):
        for provider, other in (("openai", "ANTHROPIC"), ("anthropic", "OPENAI")):
            for arm in dispatch.ARMS:
                self.assertEqual(self.keys(provider=provider, arm=arm),
                                 {f"{provider.upper()}_API_KEY": f"{provider}-{arm}", f"{other}_API_KEY": ""})

    def test_no_fallback_to_the_shared_key(self):
        self.assertEqual(self.keys(secrets=NO_AFTER_KEY)["OPENAI_API_KEY"], "")
        self.assertEqual(self.keys(arm="")["OPENAI_API_KEY"], "")

    def plan(self, ctx):
        ws = os.path.join(self.dir, "plan")
        os.makedirs(ws, exist_ok=True)
        return self.bash(self.step("plan", "n"), ctx, ws)

    def test_the_plan_stops_a_run_whose_arm_has_no_key(self):
        self.assertEqual(self.plan(context()), 0)
        self.assertEqual(self.plan(context(secrets=NO_AFTER_KEY)), 1)
        self.assertIn("::error::secret OPENAI_API_KEY_AFTER is not set", self.output())
        self.assertEqual(self.plan(context(arm="")), 1)
        self.assertIn("::error::arm must be before or after", self.output())
        ctx = context()
        ctx["inputs"]["dispatch-id"] = "a b"
        self.assertEqual(self.plan(ctx), 1)

    def test_the_score_step_stops_before_vens_without_its_key(self):
        ws = os.path.join(self.dir, "ws")
        os.makedirs(ws)
        rc = self.bash(self.step("score", "vens"), context(secrets=NO_AFTER_KEY), ws, VENS=self.fake, FAKE_VENS="ok")
        self.assertEqual(rc, 1)
        self.assertIn("::error::secret OPENAI_API_KEY_AFTER is not set", self.output())
        self.assertEqual(os.listdir(ws), [])


class TestTheAttemptRecord(Base):
    """Each case runs the score job from its Score step on, each step skipped after a failure unless if: always();
    the downloads are then read with chain.read through a dispatch log, as a campaign's are."""

    def job(self, root, mode, arm, run_id):
        commit = s.BEFORE_SHA if arm == "before" else s.AFTER_SHA
        ctx = context(arm=arm, commit=commit, run_id=run_id)
        ws = os.path.join(self.dir, f"ws-{run_id}")
        os.makedirs(ws)
        steps = self.wf["jobs"]["score"]["steps"]
        conclusion = "success"
        for st in steps[steps.index(self.step("score", "vens")):]:
            if conclusion != "success" and "always()" not in str(st.get("if", "")):
                outcome = "skipped"
            elif "uses" in st:
                self.upload(st, ctx, ws, os.path.join(root, str(run_id)))
                outcome = "success"
            else:
                cancel = mode == "hang" and st.get("id") == "vens"
                rc = self.bash(st, ctx, ws, cancel=cancel, VENS=self.fake, FAKE_VENS=mode)
                outcome = "cancelled" if cancel else "success" if rc == 0 else "failure"
                conclusion = outcome if conclusion == "success" else conclusion
            if st.get("id"):
                ctx["steps"][st["id"]] = {"outcome": outcome}
        times = {"status": "completed", "run_attempt": 1, "started_at": "2026-11-20T10:00:00Z",
                 "completed_at": "2026-11-20T10:05:00Z"}
        s.write(os.path.join(root, str(run_id), "jobs.json"), {"jobs": [
            {"id": 1, "name": "plan", "conclusion": "success", **times},
            {"id": 2, "name": render(self.wf["jobs"]["score"]["name"], ctx), "conclusion": conclusion, **times}]})
        s.write(os.path.join(root, str(run_id), "run.json"),
                {"id": run_id, "run_attempt": 1, "display_title": render(self.wf["run-name"], ctx)})
        line = {"campaign": "c1", "arm": arm, "repo": "venslabs/vens-demo", "vens_ref": commit, "vens_commit": commit,
                "provider": "openai", "model": s.MODEL, "batch_size": 1, "archived_run": "2026-09-23",
                "dispatch_id": DISPATCH_ID, "replicate": run_id - 2000, "run_id": run_id, "run_attempt": 1,
                "time": "2026-11-20T10:00:00Z", "replaces": None}
        return [{**line, "run_id": None, "run_attempt": None, "action": "pending"}, {**line, "action": "dispatch"}]

    def upload(self, st, ctx, ws, run_dir):
        folder = os.path.join(run_dir, render(st["with"]["name"], ctx))
        for rel in render(st["with"]["path"], ctx).split():
            src = os.path.join(ws, rel)
            if os.path.isdir(src):
                shutil.copytree(src, os.path.join(folder, rel))
            elif os.path.exists(src):
                os.makedirs(folder, exist_ok=True)
                shutil.copy(src, os.path.join(folder, rel))

    def read(self, cases):
        """The records python3 -m chain.read prints for one run per (mode, arm), in the cases' order."""
        root = os.path.join(self.dir, "downloads")
        lines = [l for n, (mode, arm) in enumerate(cases, 1) for l in self.job(root, mode, arm, 2000 + n)]
        log = s.write(os.path.join(self.dir, "dispatch-log.jsonl"),
                      "".join(json.dumps({f: l[f] for f in dispatch.FIELDS}) + "\n" for l in lines))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = read.main(["--dispatch-log", log, "--commit", f"after={s.AFTER_SHA}", "--commit",
                              f"before={s.BEFORE_SHA}", root])
        self.assertEqual(code, 0, err.getvalue())
        recs = {r["what"]["run_id"]: r for r in map(json.loads, out.getvalue().splitlines())}
        return [recs[2000 + n] for n in range(1, len(cases) + 1)]

    def test_the_four_outcomes(self):
        ok, before, gen, enrich, check, hang = self.read(
            [("ok", "after"), ("ok", "before"), ("generate-fails", "after"), ("enrich-fails", "after"),
             ("archive-fails", "after"), ("hang", "after")])

        # A complete attempt, every step passed.
        for rec, arm in ((ok, "after"), (before, "before")):
            self.assertEqual((rec["outcome"], rec["failure"], rec["what"]["arm"]), ("complete", None, arm))
            self.assertTrue(rec["scores_usable"], rec["problems"] + rec["incomplete"])
            self.assertEqual(rec["unknown"], [])
        # A scoring that did not complete.
        self.assertEqual((gen["outcome"], gen["failure"]), ("failed", {
            "kind": "scoring", "step": "generate", "cause": CAUSE, "cause_source": "vens log"}))
        self.assertTrue(gen["summary"]["failed"])
        # A scoring that completed and a later step that failed.
        self.assertEqual((enrich["outcome"], enrich["failure"]), ("failed", {
            "kind": "later_step", "step": "enrich", "cause": "vens enrich exited 1", "cause_source": "attempt.json"}))
        self.assertEqual((check["outcome"], check["failure"]), ("failed", {
            "kind": "later_step", "step": "archive_check", "cause": "archive check failure",
            "cause_source": "attempt.json"}))
        for rec in (enrich, check):
            self.assertEqual((rec["summary"]["failed"], rec["calls"]["archived"]), (False, 2))
        # A scoring interrupted: its start and no exit status, the job's conclusion its cause.
        self.assertEqual((hang["outcome"], hang["failure"]), ("failed", {
            "kind": "interrupted", "step": "generate", "cause": "job cancelled", "cause_source": "jobs.json"}))
        self.assertIn("generate.exit_status", hang["unknown"])
        self.assertEqual(hang["calls"]["archived"], 1)

    def test_what_each_record_holds(self):
        recs = self.read([("ok", "after"), ("generate-fails", "after"), ("enrich-fails", "after"),
                          ("archive-fails", "after"), ("hang", "after")])
        ok, gen, enrich, check, hang = [load(os.path.join(r["folder"], "attempt.json")) for r in recs]
        for rec in recs:
            self.assertIn("vens-internal.log", os.listdir(rec["folder"]))
        for rj in (ok, gen, enrich, check, hang):
            self.assertEqual(list(rj), RECORD_KEYS)
            self.assertRegex(rj["generate"]["started_at"], UTC)
        with open(self.fake, "rb") as fh:
            binary = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual({k: ok[k] for k in RECORD_KEYS[:16]},
                         {"record": 1, "runner": "baseline.yml", "arm": "after", "provider": "openai",
                          "model": s.MODEL, "llm_batch_size": 1, "vens_ref": s.AFTER_SHA, "vens_sha": s.AFTER_SHA,
                          "vens_binary_sha256": binary, "run_id": 2001, "run_attempt": 1, "job": "internal · run 1",
                          "context": "internal", "replicate": 1, "archived_scan": "runs/2026-09-23/scan/scan.json",
                          "config": "contexts/internal.yaml"})
        for t in (ok["generate"]["ended_at"], ok["enrich"]["started_at"], ok["enrich"]["ended_at"]):
            self.assertRegex(t, UTC)
        steps = lambda rj: (rj["generate"]["exit_status"], (rj["enrich"] or {}).get("exit_status"),
                            rj["archive_check"], rj["provenance"])
        self.assertEqual(steps(ok), (0, 0, "success", True))
        self.assertEqual((steps(gen), gen["enrich"]), ((1, None, "skipped", False), None))
        self.assertEqual(steps(enrich), (0, 1, "skipped", False))
        self.assertEqual(steps(check), (0, 0, "failure", False))
        self.assertEqual((steps(hang), hang["generate"]["ended_at"]), ((None, None, "skipped", False), None))


if __name__ == "__main__":
    unittest.main()
