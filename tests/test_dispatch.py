"""The dispatch script against a fake gh: no test reaches GitHub, and none can start a workflow run."""
import contextlib
import datetime
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from chain import dispatch
from chain.attempt import Refused
from tests import support as s

FAKE_GH = r'''#!{python}
import datetime, json, os, sys, time, urllib.parse
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
elif args[:1] == ["api"] and "/actions/workflows/" in args[1]:
    query = dict(urllib.parse.parse_qsl(args[1].split("?", 1)[1]))
    hidden = set(state.get("hidden", []))
    if hidden:
        state["hidden"] = []
        save()
    runs = sorted((r for r in state["runs"].values() if str(r["id"]) not in hidden),
                  key=lambda r: (r["created_at"], r["id"]), reverse=True)[:state.get("cap")]
    size, page = int(query["per_page"]), int(query["page"])
    print(json.dumps({{"workflow_runs": runs[(page - 1) * size:page * size]}}))
elif args[:1] == ["api"] and "/actions/runs/" in args[1]:
    run = state["runs"].get(args[1].rsplit("/", 1)[1])
    if run is None:
        sys.exit("HTTP 404")
    print(json.dumps(run))
elif args[:2] == ["workflow", "run"]:
    if state.get("workflow_fails"):
        sys.exit("HTTP 502")
    time.sleep(state.get("delay", 0))
    f = dict(args[i + 1].split("=", 1) for i, a in enumerate(args) if a == "-f")
    title = (f"baseline · {{f['archived-run']}} · {{f['provider']}}/{{f['model']}} · batch {{f['batch-size']}} · "
             f"x{{f['replicates']}} · vens {{f['vens-ref']}}"
             + (f" · dispatch {{f['dispatch-id']}}" if f.get("dispatch-id") else ""))
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    first = state["next_id"]
    for _ in range(state.get("copies", 1)):
        rid = state["next_id"]
        state["next_id"] += 1
        state["runs"][str(rid)] = {{"id": rid, "display_title": title, "run_attempt": 1, "status": "queued",
                                   "conclusion": None, "created_at": now}}
        if state.get("hide_new"):
            state["hidden"] = state.get("hidden", []) + [str(rid)]
    save()
    print("Created workflow_dispatch event for baseline.yml at main")
    if state.get("print_url"):
        print(f"https://github.com/venslabs/vens-demo/actions/runs/{{first}}")
elif args[:2] == ["run", "rerun"]:
    run = state["runs"][args[2]]
    if not state.get("rerun_lags"):
        run.update(run_attempt=run["run_attempt"] + 1, status="queued", conclusion=None)
    save()
else:
    sys.exit("unexpected gh call: " + " ".join(args))
'''

NO_SLEEP = {"sleep": lambda _: None}
GITHUB_CAP = 1000  # the most runs GitHub lists for a search filtered by event
LATER = lambda: dispatch.utc_now() + datetime.timedelta(minutes=16)


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

    def set(self, **kw):
        self.save({**self.load(), **kw})

    def calls(self):
        if not os.path.exists(self.state + ".calls"):
            return []
        with open(self.state + ".calls") as fh:
            return [json.loads(x) for x in fh]

    def args(self, **kw):
        base = dict(log=self.log, campaign="c1", arm="after", vens_ref="fa7fc9a", provider="openai",
                    model=s.MODEL, replicate=1, batch_size=1, archived_run="2026-09-23", repo="venslabs/vens-demo",
                    workflow_ref="main", max_side_by_side=2, run_id=None, retry_cap=4, no_run=False, no_rerun=False,
                    stray=False)
        return SimpleNamespace(**{**base, **kw})

    def go(self, **kw):
        return dispatch.dispatch(self.args(**kw), self.gh, **NO_SLEEP)

    def finish(self, run_id, conclusion="success"):
        state = self.load()
        state["runs"][str(run_id)].update(status="completed", conclusion=conclusion)
        self.save(state)

    def add_run(self, run_id, title, created_at):
        state = self.load()
        state["runs"][str(run_id)] = {"id": run_id, "display_title": title, "run_attempt": 1, "status": "queued",
                                      "conclusion": None, "created_at": created_at}
        self.save(state)

    def failed_dispatch(self):
        self.set(workflow_fails=True)
        with self.assertRaises(dispatch.DispatchError):
            self.go()
        self.set(workflow_fails=False)
        (pending,) = dispatch.open_pending(dispatch.load(self.log))
        return pending

    def title(self, line):
        return dispatch.title("2026-09-23", "openai", s.MODEL, 1, s.AFTER_SHA, line["dispatch_id"])

    def workflow_runs(self):
        return [c for c in self.calls() if c[:2] == ["workflow", "run"]]

    def reruns(self):
        return [c for c in self.calls() if c[:2] == ["run", "rerun"]]

    def actions(self):
        return [l["action"] for l in dispatch.load(self.log)]


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
        (run,) = self.workflow_runs()
        self.assertIn(f"vens-ref={s.AFTER_SHA}", run)
        self.assertIn("replicates=1", run)

    def test_the_run_is_named_with_the_arm_and_dispatch_id_passed(self):
        line = self.go()
        self.assertRegex(line["dispatch_id"], r"^[0-9a-f]{12}$")
        (run,) = self.workflow_runs()
        self.assertIn("arm=after", run)
        self.assertIn(f"dispatch-id={line['dispatch_id']}", run)
        self.assertEqual(self.load()["runs"]["5001"]["display_title"], self.title(line))
        self.assertEqual(line["dispatch_id"], dispatch.load(self.log)[0]["dispatch_id"])

    def test_a_run_of_the_same_inputs_and_another_dispatch_id_is_not_taken(self):
        # a late run of an abandoned dispatch, or another campaign's: same inputs, same title but for the id
        self.set(print_url=False)
        self.add_run(4000, self.title({"dispatch_id": "0123456789ab"}), dispatch._stamp(dispatch.utc_now()))
        self.assertEqual(self.go()["run_id"], 5001)

    def test_the_run_read_back_from_the_run_list_once_it_appears(self):
        self.set(print_url=False, hide_new=True)
        self.assertEqual(self.go()["run_id"], 5001)
        listings = [c for c in self.calls() if c[:1] == ["api"] and "/actions/workflows/" in c[1]]
        self.assertEqual(len(listings), 2)

    def test_a_replicate_dispatched_twice_is_refused(self):
        self.go()
        with self.assertRaises(Refused):
            self.go()
        self.assertEqual(len(self.workflow_runs()), 1)


class TestConcurrentCommands(Base):
    def launch(self, *args):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = {"PATH": os.path.dirname(self.gh), "HOME": self.dir, "GH": self.gh, "FAKE_GH_STATE": self.state}
        base = ["dispatch", "--log", self.log, "--campaign", "c1", "--provider", "openai", "--model", s.MODEL]
        return subprocess.Popen([sys.executable, "-m", "chain.dispatch", *base, *args], cwd=root, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def race(self, *commands):
        self.set(delay=1)
        procs = [self.launch(*c) for c in commands]
        return sorted(p.wait() for p in procs)

    def test_one_replicate_is_not_dispatched_twice(self):
        cmd = ["--arm", "after", "--vens-ref", "fa7fc9a", "--replicate", "1", "--max-side-by-side", "4"]
        self.assertEqual(self.race(cmd, cmd), [0, 2])
        self.assertEqual(len(self.workflow_runs()), 1)
        self.assertEqual(self.actions(), ["pending", "dispatch"])

    def test_the_cap_holds(self):
        self.assertEqual(self.race(
            ["--arm", "after", "--vens-ref", "fa7fc9a", "--replicate", "1", "--max-side-by-side", "1"],
            ["--arm", "before", "--vens-ref", "43ab10b", "--replicate", "1", "--max-side-by-side", "1"]), [0, 2])
        self.assertEqual(len(self.workflow_runs()), 1)


class TestPending(Base):
    def test_a_failure_after_the_dispatch_keeps_its_pending_line(self):
        self.set(print_url=False, copies=2)
        with self.assertRaises(dispatch.DispatchError):
            self.go()
        self.assertEqual(self.actions(), ["pending"])
        with self.assertRaisesRegex(Refused, "pending dispatch"):
            self.go()
        self.assertEqual(len(self.workflow_runs()), 1)
        with self.assertRaisesRegex(Refused, "carry the pending dispatch's title"):
            dispatch.resolve(self.args(no_run=True), self.gh, now=LATER)
        line = dispatch.resolve(self.args(run_id=5001), self.gh)
        self.assertEqual((line["action"], line["run_id"], line["run_attempt"]), ("resolved", 5001, 1))
        with self.assertRaisesRegex(Refused, "already run 5001"):
            self.go()

    def test_resolve_checks_the_run(self):
        pending = self.failed_dispatch()
        want = self.title(pending)
        self.add_run(7, "baseline · other", pending["time"])
        self.add_run(8, want, "2026-01-01T00:00:00Z")
        with self.assertRaisesRegex(Refused, "not the pending dispatch"):
            dispatch.resolve(self.args(run_id=7), self.gh)
        self.add_run(9, self.title({"dispatch_id": "0123456789ab"}), pending["time"])
        with self.assertRaisesRegex(Refused, "not the pending dispatch"):
            dispatch.resolve(self.args(run_id=9), self.gh)
        with self.assertRaisesRegex(Refused, "before the pending dispatch"):
            dispatch.resolve(self.args(run_id=8), self.gh)
        with self.assertRaisesRegex(Refused, "no pending dispatch"):
            dispatch.resolve(self.args(arm="before", run_id=7), self.gh)

    def test_no_run_waits_15_minutes(self):
        self.failed_dispatch()
        with self.assertRaisesRegex(Refused, "no sooner than 0:15:00"):
            dispatch.resolve(self.args(no_run=True), self.gh)
        line = dispatch.resolve(self.args(no_run=True), self.gh, now=LATER)
        self.assertEqual(line["action"], "abandoned")
        self.assertEqual(self.go()["run_id"], 5001)
        self.assertEqual(self.actions(), ["pending", "abandoned", "pending", "dispatch"])
        ids = [l["dispatch_id"] for l in dispatch.load(self.log)]
        self.assertTrue(ids[0] == ids[1] != ids[2] == ids[3], ids)

    def test_no_run_finds_a_run_past_the_first_page(self):
        pending = self.failed_dispatch()
        want = self.title(pending)
        self.add_run(10, want, pending["time"])
        for n in range(11, 14):
            self.add_run(n, "baseline · other", pending["time"].replace("Z", "") + "Z")
        with mock.patch.object(dispatch, "PER_PAGE", 2):
            with self.assertRaisesRegex(Refused, r"runs \[10\] carry"):
                dispatch.resolve(self.args(no_run=True), self.gh, now=LATER)

    def test_no_run_refused_when_the_search_is_cut_short(self):
        pending = self.failed_dispatch()
        for n in range(11, 15):
            self.add_run(n, "baseline · other", pending["time"])
        with mock.patch.object(dispatch, "PER_PAGE", 2), mock.patch.object(dispatch, "MAX_PAGES", 1):
            with self.assertRaisesRegex(Refused, "did not reach"):
                dispatch.resolve(self.args(no_run=True), self.gh, now=LATER)
        self.assertEqual(self.actions(), ["pending"])

    def test_no_run_refused_when_github_caps_the_listing(self):
        # 1,000 newer runs fill GitHub's cap: the run the pending dispatch started is listed on no page, and the
        # empty page after the cap is no end of the list.
        pending = self.failed_dispatch()
        want = self.title(pending)
        start = dispatch._parse(pending["time"]) + datetime.timedelta(minutes=10)
        state = self.load()
        state["runs"] = {str(n): {"id": n, "display_title": "baseline · other", "run_attempt": 1, "status": "queued",
                                  "conclusion": None,
                                  "created_at": dispatch._stamp(start + datetime.timedelta(seconds=n))}
                         for n in range(GITHUB_CAP)}
        state["runs"]["5000"] = {"id": 5000, "display_title": want, "run_attempt": 1, "status": "queued",
                                 "conclusion": None, "created_at": pending["time"]}
        self.save({**state, "cap": GITHUB_CAP})
        with self.assertRaisesRegex(Refused, "did not reach .* within GitHub's cap of 1000 runs"):
            dispatch.resolve(self.args(no_run=True), self.gh, now=LATER)
        self.assertEqual(self.actions(), ["pending"])
        pages = [c for c in self.calls() if c[:1] == ["api"] and "/actions/workflows/" in c[1]]
        self.assertEqual(len(pages), GITHUB_CAP // dispatch.PER_PAGE)

    def test_no_run_refused_while_a_run_the_log_does_not_name_came_after_it(self):
        pending = self.failed_dispatch()
        self.go(arm="before", vens_ref="43ab10b")
        since = dispatch._parse(pending["time"])
        self.add_run(11, "baseline · older", dispatch._stamp(since - dispatch.SKEW - datetime.timedelta(minutes=1)))
        # created three minutes after the request, under the workflow's default title
        self.add_run(13, "baseline.yml", dispatch._stamp(since + datetime.timedelta(minutes=3)))
        with self.assertRaisesRegex(Refused, r"runs \[13\], which no line of the log names, were created since"):
            dispatch.resolve(self.args(no_run=True), self.gh, now=LATER)
        state = self.load()
        del state["runs"]["13"]
        self.save(state)
        self.assertEqual(dispatch.resolve(self.args(no_run=True), self.gh, now=LATER)["action"], "abandoned")


class TestLateRuns(Base):
    def abandoned(self):
        pending = self.failed_dispatch()
        dispatch.resolve(self.args(no_run=True), self.gh, now=LATER)
        return pending

    def late(self, pending, run_id=4000):
        # GitHub starts the abandoned dispatch's run after all
        self.add_run(run_id, self.title(pending), dispatch._stamp(dispatch.utc_now()))

    def test_a_late_run_blocks_any_new_dispatch_and_rerun_whatever_its_end(self):
        self.go(arm="before", vens_ref="43ab10b")
        self.late(self.abandoned())
        self.finish(5001, "failure")
        logged = self.actions()
        for conclusion in (None, "cancelled"):
            if conclusion:
                self.finish(4000, conclusion)
            for kw in ({}, {"campaign": "c2"}):
                with self.assertRaisesRegex(Refused, r"runs \[4000\] carry the dispatch id of an abandoned dispatch"):
                    self.go(**kw)
            with self.assertRaisesRegex(Refused, r"runs \[4000\] carry the dispatch id"):
                dispatch.rerun(self.args(run_id=5001), self.gh, **NO_SLEEP)
        self.assertEqual((len(self.workflow_runs()), self.reruns(), self.actions()), (2, [], logged))

    def test_a_late_run_attached_to_its_abandoned_dispatch(self):
        pending = self.abandoned()
        self.late(pending)
        self.add_run(4001, self.title({"dispatch_id": "0123456789ab"}), dispatch._stamp(dispatch.utc_now()))
        with self.assertRaisesRegex(Refused, "not the pending dispatch"):
            dispatch.resolve(self.args(run_id=4001), self.gh)
        self.finish(4000, "success")
        with self.assertRaisesRegex(Refused, "was not dispatched again: attach run 4000 with resolve --run-id"):
            dispatch.resolve(self.args(run_id=4000, stray=True), self.gh)
        line = dispatch.resolve(self.args(run_id=4000), self.gh)
        self.assertEqual((line["action"], line["run_id"], line["dispatch_id"], line["time"]),
                         ("resolved", 4000, pending["dispatch_id"], pending["time"]))
        self.assertEqual(self.actions(), ["pending", "abandoned", "resolved"])
        with self.assertRaisesRegex(Refused, "already run 4000"):
            self.go()
        self.assertEqual(self.go(arm="before", vens_ref="43ab10b")["action"], "dispatch")

    def stray(self, conclusion):
        """A late run after its replicate was dispatched again, recorded a stray once ended."""
        pending = self.abandoned()
        self.assertEqual(self.go()["run_id"], 5001)
        self.late(pending)
        with self.assertRaisesRegex(Refused, "carry the dispatch id"):
            self.go(arm="before", vens_ref="43ab10b")
        with self.assertRaisesRegex(Refused, "run 4000 is queued: a stray run is recorded once it has ended"):
            dispatch.resolve(self.args(run_id=4000, stray=True), self.gh)
        with self.assertRaisesRegex(Refused, "no pending dispatch"):
            dispatch.resolve(self.args(run_id=4000), self.gh)
        self.add_run(4001, self.title({"dispatch_id": "0123456789ab"}), dispatch._stamp(dispatch.utc_now()))
        self.finish(4001, conclusion)
        with self.assertRaisesRegex(Refused, "of no abandoned dispatch"):
            dispatch.resolve(self.args(run_id=4001, stray=True), self.gh)
        self.finish(4000, conclusion)
        line = dispatch.resolve(self.args(run_id=4000, stray=True), self.gh)
        self.assertEqual({k: line[k] for k in ("action", "run_id", "run_attempt", "conclusion", "dispatch_id",
                                                "replicate", "arm")},
                         {"action": "stray", "run_id": 4000, "run_attempt": 1, "conclusion": conclusion,
                          "dispatch_id": pending["dispatch_id"], "replicate": 1, "arm": "after"})
        self.assertEqual(self.actions(), ["pending", "abandoned", "pending", "dispatch", "stray"])
        self.assertEqual(dispatch.index(dispatch.load(self.log))[4000], {1: line})
        self.assertEqual(self.go(arm="before", vens_ref="43ab10b")["run_id"], 5002)
        with self.assertRaisesRegex(Refused, "run 4000 is a stray run: never rerun"):
            dispatch.rerun(self.args(run_id=4000), self.gh, **NO_SLEEP)
        with self.assertRaisesRegex(Refused, "already in the log"):
            dispatch.resolve(self.args(run_id=4000, stray=True), self.gh)

    def test_a_completed_late_run_recorded_as_a_stray(self):
        self.stray("success")

    def test_a_cancelled_late_run_recorded_as_a_stray(self):
        self.stray("cancelled")

    def test_check_late(self):
        pending = self.abandoned()
        self.go()
        self.late(pending)
        self.finish(4000, "success")
        check = lambda: dispatch.main(["--gh", self.gh, "check-late", "--log", self.log])
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(check(), 2)
        self.assertIn("runs [4000] carry the dispatch id of an abandoned dispatch", err.getvalue())
        dispatch.resolve(self.args(run_id=4000, stray=True), self.gh)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(check(), 0)
        self.assertEqual(json.loads(out.getvalue())["abandoned"], [pending["dispatch_id"]])

    def test_no_dispatch_while_the_run_list_does_not_reach_the_abandoned_dispatch(self):
        pending = self.abandoned()
        for n in range(11, 15):
            self.add_run(n, "baseline · other", dispatch._stamp(dispatch.utc_now()))
        with mock.patch.object(dispatch, "PER_PAGE", 2), mock.patch.object(dispatch, "MAX_PAGES", 1):
            with self.assertRaisesRegex(Refused, f"did not reach {pending['time']}, the oldest abandoned dispatch"):
                self.go(arm="before", vens_ref="43ab10b")


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
    def test_a_rerun_logs_a_pending_line_then_its_attempt(self):
        first = self.go()
        self.finish(first["run_id"], "failure")
        line = dispatch.rerun(self.args(run_id=first["run_id"]), self.gh, **NO_SLEEP)
        self.assertEqual((line["run_id"], line["run_attempt"], line["replaces"], line["action"], line["replicate"]),
                         (first["run_id"], 2, 1, "rerun-failed", 1))
        self.assertEqual(self.actions(), ["pending", "dispatch", "rerun-pending", "rerun-failed"])
        self.assertIn(["run", "rerun", str(first["run_id"]), "--failed", "-R", "venslabs/vens-demo"], self.calls())

    def test_a_rerun_the_api_does_not_show_stays_pending(self):
        first = self.go()
        self.finish(first["run_id"], "failure")
        self.set(rerun_lags=True)
        with self.assertRaisesRegex(dispatch.DispatchError, "pending rerun stays"):
            dispatch.rerun(self.args(run_id=first["run_id"]), self.gh, **NO_SLEEP)
        self.assertEqual(self.actions()[-1], "rerun-pending")
        with self.assertRaisesRegex(Refused, "has a pending rerun"):
            dispatch.rerun(self.args(run_id=first["run_id"]), self.gh, **NO_SLEEP)
        with self.assertRaisesRegex(Refused, "is at attempt 1, not the 2"):
            dispatch.resolve_rerun(self.args(run_id=first["run_id"]), self.gh)
        state = self.load()
        state["runs"][str(first["run_id"])]["run_attempt"] = 2
        self.save(state)
        line = dispatch.resolve_rerun(self.args(run_id=first["run_id"]), self.gh)
        self.assertEqual((line["action"], line["run_attempt"], line["replaces"]), ("rerun-failed", 2, 1))
        self.assertEqual(len(self.reruns()), 1)

    def test_a_rerun_that_started_no_attempt_is_abandoned(self):
        first = self.go()
        self.finish(first["run_id"], "failure")
        self.set(rerun_lags=True)
        with self.assertRaises(dispatch.DispatchError):
            dispatch.rerun(self.args(run_id=first["run_id"]), self.gh, **NO_SLEEP)
        with self.assertRaisesRegex(Refused, "no sooner than 0:15:00"):
            dispatch.resolve_rerun(self.args(run_id=first["run_id"], no_rerun=True), self.gh)
        line = dispatch.resolve_rerun(self.args(run_id=first["run_id"], no_rerun=True), self.gh, now=LATER)
        self.assertEqual(line["action"], "rerun-abandoned")
        self.set(rerun_lags=False)
        self.assertEqual(dispatch.rerun(self.args(run_id=first["run_id"]), self.gh, **NO_SLEEP)["run_attempt"], 2)

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
                    model=s.MODEL, batch_size=1, archived_run="2026-09-23", dispatch_id="d1", replicate=1, time="t")
        return {**base, **kw}

    def write(self, *lines):
        s.write(self.log, "".join(json.dumps(line) + "\n" for line in lines))

    def started(self):
        return [self.line(action="pending"), self.line(action="dispatch", run_id=1, run_attempt=1)]

    def test_a_line_without_a_field(self):
        self.write({"campaign": "c1"})
        with self.assertRaises(dispatch.DispatchError):
            dispatch.load(self.log)

    def test_a_line_cut_mid_write(self):
        s.write(self.log, json.dumps(self.line(action="pending")) + "\n" + json.dumps(self.started()[1])[:40])
        with self.assertRaisesRegex(dispatch.DispatchError, r"dispatch-log.jsonl:2: not a JSON line, cut short"):
            dispatch.load(self.log)
        s.write(self.log, "[]\n")
        with self.assertRaisesRegex(dispatch.DispatchError, "a JSON list, not a line of the log"):
            dispatch.load(self.log)

    def test_a_dispatch_without_its_pending_line(self):
        self.write(self.line(action="dispatch", run_id=1, run_attempt=1))
        with self.assertRaisesRegex(dispatch.DispatchError, "no pending dispatch"):
            dispatch.load(self.log)

    def test_a_rerun_without_its_pending_rerun(self):
        self.write(*self.started(), self.line(action="rerun-failed", run_id=1, run_attempt=2, replaces=1))
        with self.assertRaisesRegex(dispatch.DispatchError, "no pending rerun"):
            dispatch.load(self.log)

    def test_a_rerun_that_skips_an_attempt(self):
        self.write(*self.started(), self.line(action="rerun-pending", run_id=1, run_attempt=3, replaces=2))
        with self.assertRaisesRegex(dispatch.DispatchError, "without its attempt before"):
            dispatch.load(self.log)

    def test_a_rerun_that_changes_its_run(self):
        for change in ({"arm": "before"}, {"model": "claude-sonnet-4-6"}, {"replicate": 2}):
            self.write(*self.started(), self.line(action="rerun-pending", run_id=1, run_attempt=2, replaces=1,
                                                  **change))
            with self.assertRaisesRegex(dispatch.DispatchError, "a rerun changes"):
                dispatch.load(self.log)

    def test_a_line_that_changes_its_dispatch_id(self):
        self.write(self.line(action="pending"), self.line(action="dispatch", run_id=1, run_attempt=1, dispatch_id="d2"))
        with self.assertRaisesRegex(dispatch.DispatchError, r"a dispatch line changes \['dispatch_id'\]"):
            dispatch.load(self.log)
        self.write(*self.started(), self.line(action="rerun-pending", run_id=1, run_attempt=2, replaces=1,
                                              dispatch_id="d2"))
        with self.assertRaisesRegex(dispatch.DispatchError, "a rerun changes"):
            dispatch.load(self.log)

    def test_a_late_run_resolved_after_its_abandoned_dispatch(self):
        late = self.line(action="resolved", run_id=1, run_attempt=1)
        self.write(self.line(action="pending"), self.line(action="abandoned"), late)
        self.assertEqual([l["action"] for l in dispatch.load(self.log)], ["pending", "abandoned", "resolved"])
        self.write(self.line(action="pending"), self.line(action="abandoned"), self.line(action="pending",
                                                                                         dispatch_id="d2"), late)
        with self.assertRaisesRegex(dispatch.DispatchError, r"changes \['dispatch_id'\]"):
            dispatch.load(self.log)
        self.write(self.line(action="pending"), self.line(action="abandoned"), self.line(action="dispatch", run_id=1,
                                                                                         run_attempt=1))
        with self.assertRaisesRegex(dispatch.DispatchError, "a dispatch line with no pending dispatch"):
            dispatch.load(self.log)

    def test_a_stray_line(self):
        abandoned = [self.line(action="pending"), self.line(action="abandoned")]
        again = [self.line(action="pending", dispatch_id="d2"),
                 self.line(action="dispatch", dispatch_id="d2", run_id=1, run_attempt=1)]
        stray = self.line(action="stray", run_id=2, run_attempt=2, conclusion="success")
        self.write(*abandoned, *again, stray)
        lines = dispatch.load(self.log)
        self.assertEqual(dispatch.index(lines)[2], {1: stray, 2: stray})
        for bad, why in (([*abandoned, stray], "no abandoned dispatch dispatched again"),
                         ([*abandoned, *again, {**stray, "model": "m"}], "a stray line changes"),
                         ([*abandoned, *again, {**stray, "conclusion": None}], "how it ended"),
                         ([*abandoned, *again, {**stray, "run_id": 1}], "already another line's"),
                         ([*abandoned, *again, stray, stray], "no abandoned dispatch dispatched again"),
                         ([*abandoned, *again, stray, self.line(action="rerun-pending", run_id=2, run_attempt=3,
                                                                 replaces=2)], "a stray run")):
            self.write(*bad)
            with self.assertRaisesRegex(dispatch.DispatchError, why):
                dispatch.load(self.log)

    def test_a_run_of_two_replicates(self):
        self.write(*self.started(), self.line(action="pending", replicate=2),
                   self.line(action="dispatch", run_id=1, run_attempt=1, replicate=2))
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
