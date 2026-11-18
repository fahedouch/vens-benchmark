"""The dispatch script against a fake gh: no test reaches GitHub, and none can start a workflow run."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

from chain import dispatch
from chain.attempt import Refused
from tests import support as s

FAKE_GH = r'''#!{python}
import datetime, json, os, sys
path = os.environ["FAKE_GH_STATE"]
with open(path) as fh:
    state = json.load(fh)
args = sys.argv[1:]
with open(path + ".calls", "a") as fh:
    fh.write(json.dumps(args) + "\n")
def save():
    with open(path, "w") as fh:
        json.dump(state, fh)
if args[:1] == ["api"] and args[1].startswith("repos/venslabs/vens/commits/"):
    print(json.dumps({{"sha": state["commits"][args[1].rsplit("/", 1)[1]]}}))
elif args[:1] == ["api"] and "/actions/runs/" in args[1]:
    run = state["runs"].get(args[1].rsplit("/", 1)[1])
    if run is None:
        sys.exit("HTTP 404")
    print(json.dumps(run))
elif args[:2] == ["workflow", "run"]:
    f = dict(args[i + 1].split("=", 1) for i, a in enumerate(args) if a == "-f")
    title = (f"baseline · {{f['archived-run']}} · {{f['provider']}}/{{f['model']}} · batch {{f['batch-size']}} · "
             f"x{{f['replicates']}} · vens {{f['vens-ref']}}")
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    first = state["next_id"]
    for _ in range(state.get("copies", 1)):
        rid = state["next_id"]
        state["next_id"] += 1
        state["runs"][str(rid)] = {{"id": rid, "display_title": title, "run_attempt": 1, "status": "queued",
                                   "conclusion": None, "created_at": now}}
    save()
    print("Created workflow_dispatch event for baseline.yml at main")
    if state.get("print_url"):
        print(f"https://github.com/venslabs/vens-demo/actions/runs/{{first}}")
elif args[:2] == ["run", "list"]:
    print(json.dumps([{{"databaseId": r["id"], "createdAt": r["created_at"], "displayTitle": r["display_title"]}}
                      for r in state["runs"].values()]))
elif args[:2] == ["run", "rerun"]:
    run = state["runs"][args[2]]
    run.update(run_attempt=run["run_attempt"] + 1, status="queued", conclusion=None)
    save()
else:
    sys.exit("unexpected gh call: " + " ".join(args))
'''


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.gh = os.path.join(self.dir, "bin", "gh")
        s.write(self.gh, FAKE_GH.format(python=sys.executable))
        os.chmod(self.gh, 0o755)
        self.state = os.path.join(self.dir, "state.json")
        self.save({"commits": {"fa7fc9a": s.AFTER_SHA, s.AFTER_SHA: s.AFTER_SHA}, "runs": {}, "next_id": 5001,
                   "print_url": True})
        self.log = os.path.join(self.dir, "dispatch-log.jsonl")
        os.environ["FAKE_GH_STATE"] = self.state
        self.addCleanup(os.environ.pop, "FAKE_GH_STATE", None)

    def save(self, state):
        s.write(self.state, state)

    def load(self):
        with open(self.state) as fh:
            return json.load(fh)

    def calls(self):
        with open(self.state + ".calls") as fh:
            return [json.loads(x) for x in fh]

    def args(self, **kw):
        base = dict(log=self.log, campaign="c1", arm="after", vens_ref="fa7fc9a", provider="openai",
                    model=s.MODEL, replicate=1, batch_size=1, archived_run="2026-09-23", repo="venslabs/vens-demo",
                    workflow_ref="main", max_side_by_side=0, run_id=None, retry_cap=4)
        return SimpleNamespace(**{**base, **kw})

    def finish(self, run_id, conclusion):
        state = self.load()
        state["runs"][str(run_id)].update(status="completed", conclusion=conclusion)
        self.save(state)


class TestDispatch(Base):
    def test_a_dispatch_logs_its_run(self):
        line = dispatch.dispatch(self.args(), self.gh, sleep=lambda _: None)
        self.assertEqual({k: line[k] for k in ("campaign", "arm", "vens_ref", "vens_commit", "provider", "model",
                                                "batch_size", "replicate", "run_id", "run_attempt", "action",
                                                "replaces")},
                         {"campaign": "c1", "arm": "after", "vens_ref": "fa7fc9a", "vens_commit": s.AFTER_SHA,
                          "provider": "openai", "model": s.MODEL, "batch_size": 1, "replicate": 1, "run_id": 5001,
                          "run_attempt": 1, "action": "dispatch", "replaces": None})
        self.assertRegex(line["time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(dispatch.load(self.log), [line])
        run = [c for c in self.calls() if c[:2] == ["workflow", "run"]][0]
        self.assertIn(f"vens-ref={s.AFTER_SHA}", run)
        self.assertIn("replicates=1", run)

    def test_the_run_id_read_back_from_the_run_list(self):
        self.save({**self.load(), "print_url": False})
        line = dispatch.dispatch(self.args(), self.gh, sleep=lambda _: None)
        self.assertEqual(line["run_id"], 5001)
        self.assertTrue(any(c[:2] == ["run", "list"] for c in self.calls()))

    def test_two_new_runs_with_the_title_are_not_told_apart(self):
        self.save({**self.load(), "print_url": False, "copies": 2})
        with self.assertRaises(dispatch.DispatchError):
            dispatch.dispatch(self.args(), self.gh, sleep=lambda _: None)
        self.assertFalse(os.path.exists(self.log))

    def test_a_replicate_dispatched_twice_is_refused(self):
        dispatch.dispatch(self.args(), self.gh, sleep=lambda _: None)
        with self.assertRaises(Refused):
            dispatch.dispatch(self.args(), self.gh, sleep=lambda _: None)

    def test_side_by_side(self):
        dispatch.dispatch(self.args(arm="before"), self.gh, sleep=lambda _: None)
        with self.assertRaises(Refused):
            dispatch.dispatch(self.args(max_side_by_side=1), self.gh, sleep=lambda _: None)
        line = dispatch.dispatch(self.args(max_side_by_side=2), self.gh, sleep=lambda _: None)
        self.assertEqual(line["run_id"], 5002)


class TestRerun(Base):
    def test_a_rerun_replaces_the_attempt_before(self):
        first = dispatch.dispatch(self.args(), self.gh, sleep=lambda _: None)
        self.finish(first["run_id"], "failure")
        line = dispatch.rerun(self.args(run_id=first["run_id"]), self.gh, sleep=lambda _: None)
        self.assertEqual((line["run_id"], line["run_attempt"], line["replaces"], line["action"], line["replicate"]),
                         (first["run_id"], 2, 1, "rerun-failed", 1))
        self.assertIn(["run", "rerun", str(first["run_id"]), "--failed", "-R", "venslabs/vens-demo"], self.calls())
        self.assertEqual(len(dispatch.load(self.log)), 2)

    def test_the_retry_cap(self):
        first = dispatch.dispatch(self.args(), self.gh, sleep=lambda _: None)
        self.finish(first["run_id"], "failure")
        dispatch.rerun(self.args(run_id=first["run_id"], retry_cap=2), self.gh, sleep=lambda _: None)
        self.finish(first["run_id"], "failure")
        with self.assertRaises(Refused):
            dispatch.rerun(self.args(run_id=first["run_id"], retry_cap=2), self.gh, sleep=lambda _: None)

    def test_nothing_to_rerun(self):
        first = dispatch.dispatch(self.args(), self.gh, sleep=lambda _: None)
        self.finish(first["run_id"], "success")
        with self.assertRaises(Refused):
            dispatch.rerun(self.args(run_id=first["run_id"]), self.gh, sleep=lambda _: None)

    def test_a_run_not_in_the_log(self):
        with self.assertRaises(Refused):
            dispatch.rerun(self.args(run_id=42), self.gh, sleep=lambda _: None)


class TestTheLog(Base):
    def test_a_line_without_a_field(self):
        s.write(self.log, json.dumps({"campaign": "c1"}) + "\n")
        with self.assertRaises(dispatch.DispatchError):
            dispatch.load(self.log)

    def test_a_rerun_without_its_dispatch(self):
        line = {f: None for f in dispatch.FIELDS}
        s.write(self.log, json.dumps({**line, "run_id": 1, "run_attempt": 2, "action": "rerun-failed",
                                      "replaces": 1}) + "\n")
        with self.assertRaises(dispatch.DispatchError):
            dispatch.load(self.log)


class TestCommandLine(Base):
    def test_the_command_reaches_only_the_gh_it_is_given(self):
        empty = os.path.join(self.dir, "empty")
        os.makedirs(empty)
        env = {"PATH": empty, "HOME": self.dir, "GH": self.gh, "FAKE_GH_STATE": self.state}
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        r = subprocess.run([sys.executable, "-m", "chain.dispatch", "dispatch", "--log", self.log, "--campaign", "c1",
                            "--arm", "after", "--vens-ref", "fa7fc9a", "--provider", "openai", "--model", s.MODEL,
                            "--replicate", "3"], cwd=root, env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["replicate"], 3)
        self.assertIsNone(shutil.which("gh", path=env["PATH"]))

    def test_a_missing_gh_is_an_error(self):
        s.write(self.log, json.dumps({"campaign": "c1", "arm": "after", "repo": "venslabs/vens-demo", "vens_ref": "x",
                                      "vens_commit": "x", "provider": "openai", "model": s.MODEL, "batch_size": 1,
                                      "archived_run": "2026-09-23", "replicate": 1, "run_id": 1, "run_attempt": 1,
                                      "time": "t", "action": "dispatch", "replaces": None}) + "\n")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = dispatch.main(["--gh", os.path.join(self.dir, "nowhere"), "rerun", "--log", self.log, "--run-id",
                                  "1", "--retry-cap", "4"])
        self.assertEqual(code, 1)
        self.assertIn("error: gh:", err.getvalue())


if __name__ == "__main__":
    unittest.main()
