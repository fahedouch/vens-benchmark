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
    if state.get("workflow_fails"):
        sys.exit("HTTP 502")
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

NO_SLEEP = {"sleep": lambda _: None}


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.gh = os.path.join(self.dir, "bin", "gh")
        s.write(self.gh, FAKE_GH.format(python=sys.executable))
        os.chmod(self.gh, 0o755)
        self.state = os.path.join(self.dir, "state.json")
        self.save({"commits": {"fa7fc9a": s.AFTER_SHA, s.AFTER_SHA: s.AFTER_SHA, "43ab10b": s.BEFORE_SHA},
                   "runs": {}, "next_id": 5001, "print_url": True})
        self.log = os.path.join(self.dir, "dispatch-log.jsonl")
        os.environ["FAKE_GH_STATE"] = self.state
        self.addCleanup(os.environ.pop, "FAKE_GH_STATE", None)

    def save(self, state):
        s.write(self.state, state)

    def load(self):
        with open(self.state) as fh:
            return json.load(fh)

    def calls(self):
        if not os.path.exists(self.state + ".calls"):
            return []
        with open(self.state + ".calls") as fh:
            return [json.loads(x) for x in fh]

    def args(self, **kw):
        base = dict(log=self.log, campaign="c1", arm="after", vens_ref="fa7fc9a", provider="openai",
                    model=s.MODEL, replicate=1, batch_size=1, archived_run="2026-09-23", repo="venslabs/vens-demo",
                    workflow_ref="main", max_side_by_side=2, run_id=None, retry_cap=4, no_run=False)
        return SimpleNamespace(**{**base, **kw})

    def go(self, **kw):
        return dispatch.dispatch(self.args(**kw), self.gh, **NO_SLEEP)

    def finish(self, run_id, conclusion="success"):
        state = self.load()
        state["runs"][str(run_id)].update(status="completed", conclusion=conclusion)
        self.save(state)

    def workflow_runs(self):
        return [c for c in self.calls() if c[:2] == ["workflow", "run"]]


class TestDispatch(Base):
    def test_a_dispatch_logs_a_pending_line_then_its_run(self):
        line = self.go()
        self.assertEqual({k: line[k] for k in ("campaign", "arm", "vens_ref", "vens_commit", "provider", "model",
                                                "batch_size", "replicate", "run_id", "run_attempt", "action",
                                                "replaces")},
                         {"campaign": "c1", "arm": "after", "vens_ref": "fa7fc9a", "vens_commit": s.AFTER_SHA,
                          "provider": "openai", "model": s.MODEL, "batch_size": 1, "replicate": 1, "run_id": 5001,
                          "run_attempt": 1, "action": "dispatch", "replaces": None})
        self.assertRegex(line["time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        pending, logged = dispatch.load(self.log)
        self.assertEqual((pending["action"], pending["run_id"], logged), ("pending", None, line))
        self.assertEqual(dispatch.open_pending(dispatch.load(self.log)), [])
        (run,) = self.workflow_runs()
        self.assertIn(f"vens-ref={s.AFTER_SHA}", run)
        self.assertIn("replicates=1", run)

    def test_the_run_id_read_back_from_the_run_list(self):
        self.save({**self.load(), "print_url": False})
        self.assertEqual(self.go()["run_id"], 5001)
        self.assertTrue(any(c[:2] == ["run", "list"] for c in self.calls()))

    def test_a_replicate_dispatched_twice_is_refused(self):
        self.go()
        with self.assertRaises(Refused):
            self.go()
        self.assertEqual(len(self.workflow_runs()), 1)


class TestPending(Base):
    def test_a_failure_after_the_dispatch_keeps_its_pending_line(self):
        self.save({**self.load(), "print_url": False, "copies": 2})
        with self.assertRaises(dispatch.DispatchError):
            self.go()
        lines = dispatch.load(self.log)
        self.assertEqual([l["action"] for l in lines], ["pending"])
        with self.assertRaisesRegex(Refused, "pending dispatch"):
            self.go()
        self.assertEqual(len(self.workflow_runs()), 1)
        with self.assertRaisesRegex(Refused, "carry the pending dispatch's title"):
            dispatch.resolve(self.args(no_run=True), self.gh)
        line = dispatch.resolve(self.args(run_id=5001), self.gh)
        self.assertEqual((line["action"], line["run_id"], line["run_attempt"], line["time"]),
                         ("resolved", 5001, 1, lines[0]["time"]))
        self.assertEqual(dispatch.open_pending(dispatch.load(self.log)), [])
        with self.assertRaisesRegex(Refused, "already run 5001"):
            self.go()

    def test_resolve_checks_the_run(self):
        self.save({**self.load(), "workflow_fails": True})
        with self.assertRaises(dispatch.DispatchError):
            self.go()
        state = self.load()
        state["runs"]["7"] = {"id": 7, "display_title": "baseline · other", "run_attempt": 1, "status": "queued",
                              "conclusion": None, "created_at": "2026-11-20T10:00:00Z"}
        self.save(state)
        with self.assertRaisesRegex(Refused, "not the pending dispatch"):
            dispatch.resolve(self.args(run_id=7), self.gh)
        with self.assertRaisesRegex(Refused, "no pending dispatch"):
            dispatch.resolve(self.args(arm="before", run_id=7), self.gh)

    def test_a_dispatch_that_started_no_run_is_abandoned_then_dispatched_again(self):
        self.save({**self.load(), "workflow_fails": True})
        with self.assertRaises(dispatch.DispatchError):
            self.go()
        line = dispatch.resolve(self.args(no_run=True), self.gh)
        self.assertEqual(line["action"], "abandoned")
        self.save({**self.load(), "workflow_fails": False})
        self.assertEqual(self.go()["run_id"], 5001)
        self.assertEqual([l["action"] for l in dispatch.load(self.log)], ["pending", "abandoned", "pending",
                                                                          "dispatch"])


class TestPairingAndCap(Base):
    def test_the_pair_of_a_replicate_then_the_next_once_both_ended(self):
        before = self.go(arm="before", vens_ref="43ab10b")
        with self.assertRaisesRegex(Refused, "replicate 1 of the after is not dispatched"):
            self.go(replicate=2, arm="before", vens_ref="43ab10b")
        after = self.go()
        with self.assertRaisesRegex(Refused, "has not ended"):
            self.go(replicate=2)
        self.finish(before["run_id"])
        with self.assertRaisesRegex(Refused, f"run {after['run_id']}, has not ended"):
            self.go(replicate=2)
        self.finish(after["run_id"], "failure")
        self.assertEqual(self.go(replicate=2)["replicate"], 2)

    def test_no_replicate_before_its_turn(self):
        with self.assertRaisesRegex(Refused, "replicate 1 of the before is not dispatched"):
            self.go(replicate=2)

    def test_no_replicate_after_a_later_one(self):
        rows = []
        for arm, rep, run_id in (("before", 1, 11), ("before", 2, 12), ("after", 2, 22)):
            line = {f: None for f in dispatch.FIELDS}
            line.update(campaign="c1", arm=arm, repo="venslabs/vens-demo", vens_ref="x", vens_commit="x",
                        provider="openai", model=s.MODEL, batch_size=1, archived_run="2026-09-23", replicate=rep,
                        time="2026-11-20T10:00:00Z")
            rows += [{**line, "action": "pending"}, {**line, "action": "dispatch", "run_id": run_id, "run_attempt": 1}]
        s.write(self.log, "".join(json.dumps(r) + "\n" for r in rows))
        state = self.load()
        for run_id in (11, 12, 22):
            state["runs"][str(run_id)] = {"id": run_id, "display_title": "t", "run_attempt": 1, "status": "completed",
                                          "conclusion": "success", "created_at": "2026-11-20T10:00:00Z"}
        self.save(state)
        with self.assertRaisesRegex(Refused, "replicate 2 of c1 is already dispatched"):
            self.go(max_side_by_side=9)

    def test_the_cap_counts_runs_not_ended_and_pending_dispatches(self):
        self.go(arm="before", vens_ref="43ab10b", max_side_by_side=1)
        with self.assertRaisesRegex(Refused, "at the cap of 1"):
            self.go(max_side_by_side=1)
        self.assertEqual(self.go(max_side_by_side=2)["arm"], "after")
        with self.assertRaisesRegex(Refused, "at the cap of 2"):
            self.go(model="claude-sonnet-4-6", provider="anthropic", max_side_by_side=2)

    def test_the_cap_is_required_and_positive(self):
        with self.assertRaises(dispatch.DispatchError):
            self.go(max_side_by_side=0)
        for bad in ([], ["--max-side-by-side", "0"]):
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                dispatch.main(["--gh", self.gh, "dispatch", "--log", self.log, "--campaign", "c1", "--arm", "after",
                               "--vens-ref", "fa7fc9a", "--provider", "openai", "--model", s.MODEL, "--replicate",
                               "1", *bad])
        self.assertEqual(self.workflow_runs(), [])


class TestRerun(Base):
    def test_a_rerun_replaces_the_attempt_before(self):
        first = self.go()
        self.finish(first["run_id"], "failure")
        line = dispatch.rerun(self.args(run_id=first["run_id"]), self.gh, **NO_SLEEP)
        self.assertEqual((line["run_id"], line["run_attempt"], line["replaces"], line["action"], line["replicate"]),
                         (first["run_id"], 2, 1, "rerun-failed", 1))
        self.assertIn(["run", "rerun", str(first["run_id"]), "--failed", "-R", "venslabs/vens-demo"], self.calls())

    def test_the_retry_cap(self):
        first = self.go()
        self.finish(first["run_id"], "failure")
        dispatch.rerun(self.args(run_id=first["run_id"], retry_cap=2), self.gh, **NO_SLEEP)
        self.finish(first["run_id"], "failure")
        with self.assertRaisesRegex(Refused, "retry cap"):
            dispatch.rerun(self.args(run_id=first["run_id"], retry_cap=2), self.gh, **NO_SLEEP)

    def test_no_rerun_once_the_next_pair_is_dispatched(self):
        before = self.go(arm="before", vens_ref="43ab10b")
        after = self.go()
        self.finish(before["run_id"], "failure")
        self.finish(after["run_id"])
        self.go(replicate=2, arm="before", vens_ref="43ab10b")
        with self.assertRaisesRegex(Refused, "not rerun after"):
            dispatch.rerun(self.args(run_id=before["run_id"]), self.gh, **NO_SLEEP)

    def test_nothing_to_rerun(self):
        first = self.go()
        self.finish(first["run_id"], "success")
        with self.assertRaises(Refused):
            dispatch.rerun(self.args(run_id=first["run_id"]), self.gh, **NO_SLEEP)

    def test_a_run_not_in_the_log(self):
        with self.assertRaises(Refused):
            dispatch.rerun(self.args(run_id=42), self.gh, **NO_SLEEP)


class TestTheLog(Base):
    def line(self, **kw):
        base = {f: None for f in dispatch.FIELDS}
        base.update(campaign="c1", arm="after", repo="r", vens_ref="x", vens_commit="x", provider="openai",
                    model=s.MODEL, batch_size=1, archived_run="2026-09-23", replicate=1, time="t")
        return {**base, **kw}

    def write(self, *lines):
        s.write(self.log, "".join(json.dumps(line) + "\n" for line in lines))

    def test_a_line_without_a_field(self):
        self.write({"campaign": "c1"})
        with self.assertRaises(dispatch.DispatchError):
            dispatch.load(self.log)

    def test_a_dispatch_without_its_pending_line(self):
        self.write(self.line(action="dispatch", run_id=1, run_attempt=1))
        with self.assertRaisesRegex(dispatch.DispatchError, "no pending dispatch"):
            dispatch.load(self.log)

    def test_a_rerun_without_its_attempt_before(self):
        self.write(self.line(action="pending"), self.line(action="dispatch", run_id=1, run_attempt=1),
                   self.line(action="rerun-failed", run_id=1, run_attempt=3, replaces=2))
        with self.assertRaisesRegex(dispatch.DispatchError, "without its attempt before"):
            dispatch.load(self.log)

    def test_a_rerun_that_changes_its_run(self):
        for change in ({"arm": "before"}, {"model": "claude-sonnet-4-6"}, {"replicate": 2}):
            self.write(self.line(action="pending"), self.line(action="dispatch", run_id=1, run_attempt=1),
                       self.line(action="rerun-failed", run_id=1, run_attempt=2, replaces=1, **change))
            with self.assertRaisesRegex(dispatch.DispatchError, "a rerun changes"):
                dispatch.load(self.log)

    def test_a_run_of_two_replicates(self):
        self.write(self.line(action="pending"), self.line(action="dispatch", run_id=1, run_attempt=1),
                   self.line(action="pending", replicate=2), self.line(action="dispatch", run_id=1, run_attempt=1,
                                                                       replicate=2))
        with self.assertRaisesRegex(dispatch.DispatchError, "already another replicate's"):
            dispatch.load(self.log)


class TestCommandLine(Base):
    def test_the_command_reaches_only_the_gh_it_is_given(self):
        empty = os.path.join(self.dir, "empty")
        os.makedirs(empty)
        env = {"PATH": empty, "HOME": self.dir, "GH": self.gh, "FAKE_GH_STATE": self.state}
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        r = subprocess.run([sys.executable, "-m", "chain.dispatch", "dispatch", "--log", self.log, "--campaign", "c1",
                            "--arm", "before", "--vens-ref", "43ab10b", "--provider", "openai", "--model", s.MODEL,
                            "--replicate", "1", "--max-side-by-side", "2"], cwd=root, env=env, capture_output=True,
                           text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["vens_commit"], s.BEFORE_SHA)
        self.assertIsNone(shutil.which("gh", path=env["PATH"]))

    def test_a_missing_gh_is_an_error(self):
        line = {f: None for f in dispatch.FIELDS}
        line.update(campaign="c1", arm="after", repo="venslabs/vens-demo", vens_ref="x", vens_commit="x",
                    provider="openai", model=s.MODEL, batch_size=1, archived_run="2026-09-23", replicate=1, time="t")
        s.write(self.log, json.dumps({**line, "action": "pending"}) + "\n"
                + json.dumps({**line, "action": "dispatch", "run_id": 1, "run_attempt": 1}) + "\n")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = dispatch.main(["--gh", os.path.join(self.dir, "nowhere"), "rerun", "--log", self.log, "--run-id",
                                  "1", "--retry-cap", "4", "--max-side-by-side", "2"])
        self.assertEqual(code, 1)
        self.assertIn("error: gh:", err.getvalue())


if __name__ == "__main__":
    unittest.main()
