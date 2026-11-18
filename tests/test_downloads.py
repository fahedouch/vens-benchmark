"""baseline.yml downloads read through the dispatch log: one-replicate runs all named r1, a failed
attempt and its replacement under one run id, and the folders and jobs the reader refuses, records or flags."""
import contextlib
import io
import json
import os
import tempfile
import unittest

from chain import attempt, dispatch, downloads, read
from chain.attempt import Refused
from tests import support as s

FAILED = {"generate": {"started_at": "2026-11-20T10:00:00Z", "ended_at": "2026-11-20T10:00:30Z", "exit_status": 1}}
CAUSE = "failed to generate risk scores: LLM evaluation failed: 503"
COMMITS = {"before": s.BEFORE_SHA, "after": s.AFTER_SHA}


def log_line(run_id, replicate, attempt=1, arm="after", model=s.MODEL, commit=s.AFTER_SHA):
    return {"campaign": "c1", "arm": arm, "repo": "venslabs/vens-demo", "vens_ref": commit, "vens_commit": commit,
            "provider": "openai", "model": model, "batch_size": 1, "archived_run": "2026-09-23",
            "replicate": replicate, "run_id": run_id, "run_attempt": attempt, "time": "2026-11-20T10:00:00Z",
            "action": "dispatch" if attempt == 1 else "rerun-failed", "replaces": None if attempt == 1 else attempt - 1}


def as_logged(*lines):
    """The lines as the dispatch script writes them: each dispatch after its pending line, each rerun after its
    pending rerun."""
    out = []
    for line in lines:
        if line["action"] == "dispatch":
            out.append({**line, "run_id": None, "run_attempt": None, "action": "pending"})
        if line["action"] == "rerun-failed":
            out.append({**line, "action": "rerun-pending"})
        out.append(line)
    return out


class TestTheHelper(unittest.TestCase):
    def test_the_lines_load_as_a_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = s.write(os.path.join(tmp, "log.jsonl"), "".join(
                json.dumps(l) + "\n" for l in as_logged(log_line(1, 1), log_line(1, 1, attempt=2))))
            self.assertEqual([l["action"] for l in dispatch.load(path)],
                             ["pending", "dispatch", "rerun-pending", "rerun-failed"])


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name

    def run_json(self, run_id, attempts=1, commit=s.AFTER_SHA):
        s.write(os.path.join(self.root, str(run_id), "run.json"),
                {"id": run_id, "run_attempt": attempts, "display_title":
                    f"baseline · 2026-09-23 · openai/{s.MODEL} · batch 1 · x1 · vens {commit}"})

    def complete(self, run_id, attempt=1, **kw):
        log = [s.summary_line(rows=1, cves=1, llm_calls=2, asked_again=0, splits=0, calls__M=1, calls__O=1,
                              failed=False)]
        return s.baseline_folder(self.root, run_id, "internal", 1, attempt, record=s.COMPLETE_RECORD, log=log, **kw)

    def failed(self, run_id, attempt=1):
        log = [s.summary_line(rows=1, cves=1, llm_calls=1, asked_again=0, splits=0, calls__M=1, failed=True),
               s.error_line(CAUSE)]
        calls = [(s.SYSTEM, s.after_human("Q M?", ["CVE-2099-0001"]), None)]
        return s.baseline_folder(self.root, run_id, "internal", 1, attempt, record=FAILED, log=log, calls=calls,
                                 vex_file=False, provenance=False, answers=False)

    def log_file(self, *lines):
        return s.write(os.path.join(self.root, "log.jsonl"), "".join(json.dumps(l) + "\n" for l in as_logged(*lines)))


class TestTheDispatchLog(Base):
    def test_two_downloads_both_r1_mapped_to_replicates_1_and_2(self):
        for run_id in (1001, 1002):
            self.complete(run_id)
            self.run_json(run_id)
        recs = downloads.read_downloads(self.root, lines=as_logged(log_line(1001, 1), log_line(1002, 2)))
        self.assertEqual([(r["what"]["run_id"], r["what"]["replicate_in_run"], r["what"]["replicate"]) for r in recs],
                         [(1001, 1, 1), (1002, 1, 2)])
        self.assertEqual({r["what"]["arm"] for r in recs}, {"after"})
        self.assertTrue(all(r["scores_usable"] for r in recs))

    def test_a_failed_attempt_and_its_replacement(self):
        self.failed(1003, attempt=1)
        self.complete(1003, attempt=2)
        self.run_json(1003, attempts=2)
        recs = downloads.read_run(os.path.join(self.root, "1003"),
                                  lines=as_logged(log_line(1003, 3), log_line(1003, 3, attempt=2)))
        got = [(r["what"]["run_attempt"], r["what"]["replicate"], r["outcome"]) for r in recs]
        self.assertEqual(got, [(1, 3, "failed"), (2, 3, "complete")])
        self.assertEqual(recs[0]["failure"]["cause"], CAUSE)

    def test_a_folder_no_line_names(self):
        self.complete(1004)
        with self.assertRaisesRegex(Refused, "no line of the dispatch log names run 1004"):
            downloads.read_run(os.path.join(self.root, "1004"), lines=as_logged(log_line(1001, 1)))

    def test_an_attempt_no_line_logs(self):
        self.failed(1005, attempt=1)
        self.complete(1005, attempt=2)
        with self.assertRaisesRegex(Refused, "attempt 2 is not in the dispatch log"):
            downloads.read_run(os.path.join(self.root, "1005"), lines=as_logged(log_line(1005, 1)))

    def test_a_record_with_another_commit(self):
        self.complete(1006, commit=s.BEFORE_SHA)
        with self.assertRaisesRegex(Refused, "gives vens"):
            downloads.read_run(os.path.join(self.root, "1006"), lines=as_logged(log_line(1006, 1)))

    def test_a_folder_of_another_model(self):
        self.complete(1007, model="claude-sonnet-4-6", provider="anthropic")
        with self.assertRaisesRegex(Refused, "gives model"):
            downloads.read_run(os.path.join(self.root, "1007"), lines=as_logged(log_line(1007, 1)))

    def test_two_runs_in_one_folder(self):
        self.complete(1008)
        self.run_json(1008)
        s.write(os.path.join(self.root, "1008", "run.json"), {"id": 999})
        with self.assertRaisesRegex(Refused, "one folder holds one workflow run"):
            downloads.read_run(os.path.join(self.root, "1008"), lines=as_logged(log_line(1008, 1)))

    def test_a1_whose_record_says_attempt_2(self):
        folder = self.complete(1009)
        s.write(os.path.join(folder, "attempt.json"),
                {"record": 1, "runner": "baseline.yml", "arm": "after", "run_id": 1009, "run_attempt": 2,
                 **s.COMPLETE_RECORD})
        with self.assertRaisesRegex(Refused, "the name gives run_attempt 1, attempt.json 2"):
            downloads.read_run(os.path.join(self.root, "1009"),
                               lines=as_logged(log_line(1009, 1), log_line(1009, 1, attempt=2)))

    def test_a_logged_attempt_with_neither_folder_nor_job(self):
        self.complete(1010)
        self.run_json(1010, attempts=2)
        recs = downloads.read_run(os.path.join(self.root, "1010"),
                                  lines=as_logged(log_line(1010, 1), log_line(1010, 1, attempt=2)))
        self.assertEqual([r["outcome"] for r in recs], ["complete", None])
        self.assertEqual(recs[1]["problems"], ["run 1010 attempt 2 is in the dispatch log, with no artefact folder "
                                               "and no job"])

    def test_a_logged_run_not_downloaded_and_a_pending_dispatch(self):
        self.complete(1011)
        self.run_json(1011)
        lines = as_logged(log_line(1011, 1), log_line(1012, 2))
        pending = {**log_line(None, 3), "run_attempt": None, "action": "pending"}
        recs = downloads.read_downloads(self.root, lines=lines + [pending])
        self.assertEqual([r["outcome"] for r in recs], ["complete", None, None])
        self.assertEqual(recs[1]["problems"], ["run 1012 attempt 1 is in the dispatch log, its download is not"])
        self.assertEqual(recs[2]["problems"], ["a pending dispatch of replicate 3 of the after the log never "
                                               "resolved"])

    def test_the_commit_expected_of_each_arm(self):
        self.complete(1013)
        self.complete(1014, commit=s.BEFORE_SHA)
        self.assertTrue(downloads.read_run(os.path.join(self.root, "1013"), arm="after", commits=COMMITS)[0][
                            "scores_usable"])
        with self.assertRaisesRegex(Refused, "not the after's"):
            downloads.read_run(os.path.join(self.root, "1014"), arm="after", commits=COMMITS)


class TestCommandLine(Base):
    def main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = read.main(list(args))
        return code, [json.loads(x) for x in out.getvalue().splitlines()], err.getvalue()

    def test_a_campaign_through_its_dispatch_log(self):
        for run_id in (1001, 1002):
            self.complete(run_id)
            self.run_json(run_id)
        log = self.log_file(log_line(1001, 1), log_line(1002, 2))
        code, recs, _ = self.main("--dispatch-log", log, self.root)
        self.assertEqual((code, [r["what"]["replicate"] for r in recs]), (0, [1, 2]))
        code, recs, _ = self.main("--dispatch-log", log, os.path.join(self.root, "1002"))
        self.assertEqual((code, [r["what"]["replicate"] for r in recs]), (0, [2]))

    def test_one_attempt_folder(self):
        folder = self.complete(1003)
        code, recs, _ = self.main("--arm", "after", "--commit", f"after={s.AFTER_SHA}", folder)
        self.assertEqual((code, len(recs), recs[0]["outcome"]), (0, 1, "complete"))

    def test_one_attempt_folder_checked_against_the_log(self):
        folder = self.complete(1004)
        log = self.log_file(log_line(1004, 7))
        code, recs, _ = self.main("--dispatch-log", log, folder)
        self.assertEqual((code, recs[0]["what"]["replicate"]), (0, 7))
        log = self.log_file(log_line(1001, 1))
        code, recs, err = self.main("--dispatch-log", log, folder)
        self.assertEqual((code, recs), (1, []))
        self.assertIn("no line of the dispatch log names run 1004", err)

    def test_a_refused_folder(self):
        self.complete(1005)
        log = self.log_file(log_line(1001, 1))
        code, recs, err = self.main("--dispatch-log", log, os.path.join(self.root, "1005"))
        self.assertEqual((code, recs), (1, []))
        self.assertIn("refused: ", err)

    def test_one_folder_without_a_log_matched_with_its_run(self):
        folder = self.complete(1006, provenance=False)
        os.remove(os.path.join(folder, "attempt.json"))
        self.run_json(1006)
        s.write(os.path.join(self.root, "1006", "jobs.json"),
                {"jobs": [{"id": 9, "run_attempt": 1, "name": "internal · run 1", "conclusion": "failure"}]})
        failures = s.write(os.path.join(self.root, "failures.txt"),
                           f"run 1006 | attempt 1 | job 9 | internal · run 1 | "
                           f'level=ERROR msg=Error error="{CAUSE}"\n')
        code, recs, _ = self.main("--arm", "after", "--failures", failures, folder)
        self.assertEqual((code, recs[0]["outcome"], recs[0]["failure"]["cause"]), (0, "failed", CAUSE))
        self.assertEqual(recs[0]["job"]["id"], 9)

    def test_a_run_folder_with_jobs_and_no_artefact(self):
        run_dir = os.path.join(self.root, "run")
        s.write(os.path.join(run_dir, "run.json"), {"id": 1007, "display_title":
                f"baseline · 2026-09-23 · openai/{s.MODEL} · batch 1 · x1 · vens {s.AFTER_SHA}"})
        s.write(os.path.join(run_dir, "jobs.json"),
                {"jobs": [{"id": 1, "run_attempt": 1, "name": "internal · run 1", "conclusion": "cancelled"}]})
        code, recs, _ = self.main("--arm", "after", run_dir)
        self.assertEqual((code, [r["failure"]["cause"] for r in recs]), (0, ["job cancelled"]))

    def test_a_run_folder_with_nothing_to_read(self):
        run_dir = os.path.join(self.root, "run")
        s.write(os.path.join(run_dir, "run.json"), {"id": 1008})
        code, recs, err = self.main(run_dir)
        self.assertEqual((code, recs), (1, []))
        self.assertIn("a workflow run with no attempt", err)
        empty = os.path.join(self.root, "empty")
        os.makedirs(empty)
        code, recs, err = self.main(empty)
        self.assertEqual((code, recs), (1, []))
        self.assertIn("no attempt", err)


class TestJobsAndFailures(Base):
    def test_both_jobs_shapes(self):
        flat = [{"attempt": 2, "id": 7, "name": "internal · run 1", "conclusion": "failure", "started_at": "a",
                 "completed_at": "b"}]
        api = {"total_count": 1, "jobs": [{"run_attempt": 2, "id": 7, "name": "internal · run 1",
                                           "conclusion": "failure", "status": "completed", "steps": []}]}
        for doc in (flat, api):
            path = s.write(os.path.join(self.root, "jobs.json"), doc)
            (job,) = downloads.load_jobs(path)
            self.assertEqual((job["id"], job["run_attempt"], job["conclusion"]), (7, 2, "failure"))

    def test_both_failures_formats(self):
        err = f'time=2026-11-15T21:53:23.498Z level=ERROR msg=Error error="{CAUSE}"'
        path = s.write(os.path.join(self.root, "failures.txt"),
                       f"attempt 1 | job 11 | internal · run 3 | {err}\n"
                       f"run 1001 | attempt 2 | job 12 | internal-api · run 6 | {err}\n")
        got = downloads.load_failures(path)
        self.assertEqual([(f["run_id"], f["attempt"], f["job_id"], f["job"], f["error"]) for f in got],
                         [(None, 1, 11, "internal · run 3", CAUSE), (1001, 2, 12, "internal-api · run 6", CAUSE)])

    def test_jobs_that_did_not_succeed_without_an_artefact(self):
        self.complete(1020)
        self.run_json(1020)
        s.write(os.path.join(self.root, "1020", "jobs.json"),
                {"jobs": [{"id": 1, "run_attempt": 1, "name": "internal · run 1", "conclusion": "success"},
                          {"id": 2, "run_attempt": 1, "name": "internal-api · run 1", "conclusion": "cancelled"},
                          {"id": 3, "run_attempt": 1, "name": "internet-facing · run 1", "conclusion": "failure"},
                          {"id": 4, "run_attempt": 1, "name": "plan", "conclusion": "success"},
                          {"id": 5, "run_attempt": 1, "name": "internal · run 2", "conclusion": None}]})
        recs = downloads.read_run(os.path.join(self.root, "1020"), lines=as_logged(log_line(1020, 1)))
        self.assertEqual(len(recs), 3)
        for rec, cause in ((recs[1], "job cancelled"), (recs[2], "job failure")):
            self.assertEqual((rec["folder"], rec["outcome"], rec["failure"]["kind"], rec["failure"]["cause"]),
                             (None, "failed", None, cause))
            self.assertEqual((rec["what"]["replicate"], rec["problems"]), (1, ["artefact missing"]))
            for field in attempt.RECORD + ("calls", "vens_commit", "failure.kind"):
                self.assertIn(field, rec["unknown"])

    def test_a_job_that_succeeded_without_its_artefact_is_refused(self):
        self.complete(1024)
        self.run_json(1024)
        s.write(os.path.join(self.root, "1024", "jobs.json"),
                {"jobs": [{"id": 1, "run_attempt": 1, "name": "internal · run 1", "conclusion": "success"},
                          {"id": 2, "run_attempt": 1, "name": "internal-api · run 1", "conclusion": "success"}]})
        with self.assertRaisesRegex(Refused, r"job 2 \(internal-api · run 1, attempt 1\) succeeded, yet its artefact "
                                             r"is not in the download"):
            downloads.read_run(os.path.join(self.root, "1024"), lines=as_logged(log_line(1024, 1)))

    def test_jobs_a_rerun_carries_over(self):
        log = [s.summary_line(rows=1, cves=1, llm_calls=2, asked_again=0, splits=0, calls__M=1, calls__O=1,
                              failed=False)]
        s.baseline_folder(self.root, 1023, "internal-api", 1, 1, record=s.COMPLETE_RECORD, log=log)
        self.failed(1023, attempt=1)
        self.complete(1023, attempt=2)
        self.run_json(1023, attempts=2)
        done = {"started_at": "2026-11-20T10:00:00Z", "completed_at": "2026-11-20T10:05:00Z"}
        s.write(os.path.join(self.root, "1023", "jobs.json"), {"jobs": [
            {"id": 1, "run_attempt": 1, "name": "internal-api · run 1", "conclusion": "success", **done},
            {"id": 2, "run_attempt": 1, "name": "internal · run 1", "conclusion": "failure",
             "started_at": "2026-11-20T10:06:00Z", "completed_at": "2026-11-20T10:07:00Z"},
            {"id": 3, "run_attempt": 2, "name": "internal-api · run 1", "conclusion": "success", **done},
            {"id": 4, "run_attempt": 2, "name": "internal · run 1", "conclusion": "success",
             "started_at": "2026-11-20T11:00:00Z", "completed_at": "2026-11-20T11:05:00Z"}]})
        recs = downloads.read_run(os.path.join(self.root, "1023"),
                                  lines=as_logged(log_line(1023, 1), log_line(1023, 1, attempt=2)))
        self.assertEqual(sorted((r["what"]["context"], r["what"]["run_attempt"], r["outcome"]) for r in recs),
                         [("internal", 1, "failed"), ("internal", 2, "complete"), ("internal-api", 1, "complete")])

    def test_a_job_of_an_attempt_no_line_logs(self):
        self.complete(1021)
        self.run_json(1021, attempts=2)
        s.write(os.path.join(self.root, "1021", "jobs.json"),
                {"jobs": [{"id": 1, "run_attempt": 2, "name": "internal · run 1", "conclusion": "failure"}]})
        with self.assertRaisesRegex(Refused, "attempt 2 is not in the dispatch log"):
            downloads.read_run(os.path.join(self.root, "1021"), lines=as_logged(log_line(1021, 1)))

    def test_without_a_log_the_folders_must_agree(self):
        self.complete(1022)
        other = s.baseline_folder(self.root, 1022, "internal", 2, 1, record=None, commit=s.BEFORE_SHA)
        self.assertTrue(os.path.isdir(other))
        with self.assertRaisesRegex(Refused, "disagree"):
            downloads.read_run(os.path.join(self.root, "1022"))


if __name__ == "__main__":
    unittest.main()
