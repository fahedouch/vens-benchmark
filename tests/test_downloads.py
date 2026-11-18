"""baseline.yml downloads read through the dispatch log (step 4, Q8): one-replicate runs all named r1, a failed
attempt and its replacement under one run id, and the folders the reader refuses."""
import contextlib
import io
import json
import os
import tempfile
import unittest

from chain import downloads, read
from chain.attempt import Refused
from tests import support as s

FAILED = {"generate": {"started_at": "2026-11-20T10:00:00Z", "ended_at": "2026-11-20T10:00:30Z", "exit_status": 1}}
CAUSE = "failed to generate risk scores: LLM evaluation failed: 503"


def log_line(run_id, replicate, attempt=1, arm="after", model=s.MODEL, commit=s.AFTER_SHA):
    return {"campaign": "c1", "arm": arm, "repo": "venslabs/vens-demo", "vens_ref": commit, "vens_commit": commit,
            "provider": "openai", "model": model, "batch_size": 1, "archived_run": "2026-09-23",
            "replicate": replicate, "run_id": run_id, "run_attempt": attempt, "time": "2026-11-20T10:00:00Z",
            "action": "dispatch" if attempt == 1 else "rerun-failed", "replaces": None if attempt == 1 else attempt - 1}


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


class TestTheDispatchLog(Base):
    def test_two_downloads_both_r1_mapped_to_replicates_1_and_2(self):
        for run_id in (1001, 1002):
            self.complete(run_id)
            self.run_json(run_id)
        recs = downloads.read_downloads(self.root, lines=[log_line(1001, 1), log_line(1002, 2)])
        self.assertEqual([(r["what"]["run_id"], r["what"]["replicate_in_run"], r["what"]["replicate"]) for r in recs],
                         [(1001, 1, 1), (1002, 1, 2)])
        self.assertEqual({r["what"]["arm"] for r in recs}, {"after"})
        self.assertTrue(all(r["scores_usable"] for r in recs))

    def test_a_failed_attempt_and_its_replacement(self):
        self.failed(1003, attempt=1)
        self.complete(1003, attempt=2)
        self.run_json(1003, attempts=2)
        recs = downloads.read_run(os.path.join(self.root, "1003"),
                                  lines=[log_line(1003, 3), log_line(1003, 3, attempt=2)])
        got = [(r["what"]["run_attempt"], r["what"]["replicate"], r["outcome"]) for r in recs]
        self.assertEqual(got, [(1, 3, "failed"), (2, 3, "complete")])
        self.assertEqual(recs[0]["failure"]["cause"], CAUSE)

    def test_a_folder_no_line_names(self):
        self.complete(1004)
        with self.assertRaisesRegex(Refused, "no line of the dispatch log names run 1004"):
            downloads.read_run(os.path.join(self.root, "1004"), lines=[log_line(1001, 1)])

    def test_an_attempt_no_line_logs(self):
        self.failed(1005, attempt=1)
        self.complete(1005, attempt=2)
        with self.assertRaisesRegex(Refused, "attempt 2 is not in the dispatch log"):
            downloads.read_run(os.path.join(self.root, "1005"), lines=[log_line(1005, 1)])

    def test_a_record_with_another_commit(self):
        self.complete(1006, commit=s.BEFORE_SHA)
        with self.assertRaisesRegex(Refused, "gives vens"):
            downloads.read_run(os.path.join(self.root, "1006"), lines=[log_line(1006, 1)])

    def test_a_folder_of_another_model(self):
        self.complete(1007, model="claude-sonnet-4-6", provider="anthropic")
        with self.assertRaisesRegex(Refused, "gives model"):
            downloads.read_run(os.path.join(self.root, "1007"), lines=[log_line(1007, 1)])

    def test_two_runs_in_one_folder(self):
        self.complete(1008)
        self.run_json(1008)
        s.write(os.path.join(self.root, "1008", "run.json"), {"id": 999})
        with self.assertRaisesRegex(Refused, "one folder holds one workflow run"):
            downloads.read_run(os.path.join(self.root, "1008"), lines=[log_line(1008, 1)])


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
        log = s.write(os.path.join(self.root, "log.jsonl"),
                      "".join(json.dumps(line) + "\n" for line in (log_line(1001, 1), log_line(1002, 2))))
        code, recs, _ = self.main("--dispatch-log", log, self.root)
        self.assertEqual((code, [r["what"]["replicate"] for r in recs]), (0, [1, 2]))
        code, recs, _ = self.main("--dispatch-log", log, os.path.join(self.root, "1002"))
        self.assertEqual((code, [r["what"]["replicate"] for r in recs]), (0, [2]))

    def test_one_attempt_folder(self):
        folder = self.complete(1003)
        code, recs, _ = self.main("--arm", "after", folder)
        self.assertEqual((code, len(recs), recs[0]["outcome"]), (0, 1, "complete"))

    def test_a_refused_folder(self):
        self.complete(1004)
        log = s.write(os.path.join(self.root, "log.jsonl"), json.dumps(log_line(1001, 1)) + "\n")
        code, recs, err = self.main("--dispatch-log", log, os.path.join(self.root, "1004"))
        self.assertEqual((code, recs), (1, []))
        self.assertIn("refused: ", err)


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

    def test_a_failed_job_without_an_artefact(self):
        self.complete(1009)
        self.run_json(1009)
        s.write(os.path.join(self.root, "1009", "jobs.json"),
                {"jobs": [{"id": 1, "run_attempt": 1, "name": "internal · run 1", "conclusion": "success"},
                          {"id": 2, "run_attempt": 1, "name": "internal · run 2", "conclusion": "cancelled"},
                          {"id": 3, "run_attempt": 1, "name": "internal · run 3", "conclusion": None}]})
        recs = downloads.read_run(os.path.join(self.root, "1009"), lines=[log_line(1009, 1)])
        self.assertEqual(len(recs), 2)
        lost = recs[1]
        self.assertEqual((lost["folder"], lost["outcome"], lost["failure"]["kind"], lost["failure"]["cause"]),
                         (None, "failed", "interrupted", "job cancelled"))
        self.assertIn("calls", lost["unknown"])

    def test_without_a_log_the_folders_must_agree(self):
        self.complete(1010)
        other = s.baseline_folder(self.root, 1010, "internal", 2, 1, record=None, commit=s.BEFORE_SHA)
        self.assertTrue(os.path.isdir(other))
        with self.assertRaisesRegex(Refused, "disagree"):
            downloads.read_run(os.path.join(self.root, "1010"))


if __name__ == "__main__":
    unittest.main()
