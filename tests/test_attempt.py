"""The attempt record (step 4, section 2.1): its four outcomes told apart, and a download made before the record
read with its added fields unknown, none inferred."""
import os
import tempfile
import unittest

from chain import attempt
from tests import support as s

A = "CVE-2099-0001"
GEN_OK = {"started_at": "2026-11-20T10:00:00Z", "ended_at": "2026-11-20T10:01:00Z", "exit_status": 0}
CAUSE = f"failed to generate risk scores: model returned no answer to Motive (M) for {A} after asking again; " \
        f"stopping the run"


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = tmp.name

    def folder(self, record, **kw):
        kw.setdefault("log", [s.summary_line(rows=1, cves=1, llm_calls=2, asked_again=0, splits=0, calls__M=1,
                                             calls__O=1, failed=False)])
        return s.baseline_folder(self.root, 1001, "internal", 1, 1, record=record, **kw)


class TestOutcomes(Base):
    def test_a_complete_attempt(self):
        rec = attempt.read_attempt(self.folder(s.COMPLETE_RECORD))
        self.assertEqual((rec["outcome"], rec["failure"], rec["scores_usable"]), ("complete", None, True))
        self.assertEqual(rec["record"], "attempt.json")
        self.assertEqual(rec["what"]["arm"], "after")
        self.assertEqual(rec["archive_check"], {"passed": True, "reason": ""})
        self.assertEqual(rec["ratings"][A]["vector"], s.VECTOR)
        self.assertEqual(rec["problems"], [])

    def test_a_scoring_that_fails(self):
        log = [s.again_line("M", [A]), s.summary_line(rows=1, cves=1, llm_calls=2, asked_again=1, splits=0,
                                                      calls__M=2, failed=True), s.error_line(CAUSE)]
        calls = [(s.SYSTEM, s.after_human("Q M?", [A]), s.reply([A], skip=[A]))] * 2
        record = {"generate": {**GEN_OK, "exit_status": 1}}
        rec = attempt.read_attempt(self.folder(record, log=log, calls=calls, vex_file=False, provenance=False,
                                               answers=False), arm="after")
        self.assertEqual(rec["outcome"], "failed")
        self.assertEqual(rec["failure"], {"kind": "scoring", "step": "generate", "cause": CAUSE,
                                          "cause_source": "vens log"})
        self.assertEqual((rec["summary"]["failed"], rec["recovery"]["recovery_calls"]), (True, 1))
        self.assertEqual(rec["calls"]["kinds"], ["planned", "again_omission"])
        self.assertFalse(rec["scores_usable"])

    def test_a_scoring_that_completes_and_an_enrichment_that_fails(self):
        record = {**s.COMPLETE_RECORD, "enrich": {"exit_status": 1}, "archive_check": "skipped", "provenance": False}
        rec = attempt.read_attempt(self.folder(record, provenance=False), arm="after")
        self.assertEqual(rec["outcome"], "failed")
        self.assertEqual(rec["failure"], {"kind": "later_step", "step": "enrich", "cause": "vens enrich exited 1",
                                          "cause_source": "attempt.json"})
        self.assertEqual((rec["calls"]["archived"], rec["recovery"]["planned"]), (2, 2))
        self.assertIsNotNone(rec["ratings"])
        self.assertFalse(rec["scores_usable"])

    def test_a_scoring_that_completes_and_an_archive_check_that_fails(self):
        record = {**s.COMPLETE_RECORD, "archive_check": "failure", "provenance": False}
        rec = attempt.read_attempt(self.folder(record, provenance=False), arm="after")
        self.assertEqual(rec["failure"], {"kind": "later_step", "step": "archive_check",
                                          "cause": "archive check failure", "cause_source": "attempt.json"})
        self.assertEqual(rec["calls"]["archived"], 2)
        self.assertFalse(rec["scores_usable"])

    def test_an_interrupted_scoring_cancelled(self):
        record = {"generate": {"started_at": "2026-11-20T10:00:00Z"}}
        job = {"id": 1, "name": "internal · run 1", "run_attempt": 1, "conclusion": "cancelled"}
        rec = attempt.read_attempt(self.folder(record, log=[], vex_file=False, provenance=False, answers=False),
                                   job=job, arm="after")
        self.assertEqual(rec["failure"], {"kind": "interrupted", "step": "generate", "cause": "job cancelled",
                                          "cause_source": "jobs.json"})
        self.assertIn("generate.exit_status", rec["unknown"])
        self.assertNotIn("generate.started_at", rec["unknown"])
        self.assertEqual(rec["calls"]["archived"], 2)

    def test_an_interrupted_scoring_timed_out_with_no_calls_uploaded(self):
        folder = self.folder({"generate": {"started_at": "2026-11-20T10:00:00Z"}}, log=[], vex_file=False,
                             provenance=False, answers=False)
        for name in os.listdir(os.path.join(folder, "calls", "run-1")):
            os.remove(os.path.join(folder, "calls", "run-1", name))
        os.rmdir(os.path.join(folder, "calls", "run-1"))
        os.rmdir(os.path.join(folder, "calls"))
        job = {"id": 1, "name": "internal · run 1", "run_attempt": 1, "conclusion": "timed_out"}
        rec = attempt.read_attempt(folder, job=job, arm="after")
        self.assertEqual(rec["failure"]["cause"], "job timed_out")
        self.assertIn("calls", rec["unknown"])
        self.assertIsNone(rec["calls"]["archived"])

    def test_a_scenario_run_timed_out(self):
        folder = os.path.join(self.root, "scenario")
        s.write(os.path.join(folder, "attempt.json"), {"record": 1, "runner": "scenarios", "arm": "after",
                                                       "generate": {"started_at": "2026-11-20T10:00:00Z",
                                                                    "ended_at": "2026-11-20T10:03:00Z",
                                                                    "timed_out": True}})
        rec = attempt.read_attempt(folder)
        self.assertEqual(rec["failure"], {"kind": "interrupted", "step": "generate", "cause": "timeout",
                                          "cause_source": "attempt.json"})

    def test_a_complete_run_without_answers_json_is_an_incomplete_record(self):
        rec = attempt.read_attempt(self.folder(s.COMPLETE_RECORD, answers=False), arm="after")
        self.assertEqual(rec["outcome"], "complete")
        self.assertEqual(rec["incomplete"], ["a complete run's VEX without its answers.json"])
        self.assertFalse(rec["scores_usable"])

    def test_the_before_writes_no_answers_json(self):
        rec = attempt.read_attempt(self.folder(s.COMPLETE_RECORD, arm="before"))
        self.assertEqual((rec["what"]["arm"], rec["incomplete"], rec["scores_usable"]), ("before", [], True))

    def test_an_arm_the_record_contradicts(self):
        rec = attempt.read_attempt(self.folder(s.COMPLETE_RECORD), arm="before")
        self.assertIn("arm after from the attempt.json, before taken", rec["problems"])

    def test_reply_unreadable_in_answers_json_and_the_summary(self):
        log = [s.summary_line(rows=1, cves=1, llm_calls=2, asked_again=0, splits=0, calls__M=1, calls__O=1,
                              defects__reply_unreadable=1, failed=False)]
        folder = self.folder(s.COMPLETE_RECORD, log=log)
        path = os.path.join(folder, "calls", "run-1", "answers.json")
        s.write(path, s.answers_doc([(A, s.VECTOR)], defects={"reply_unreadable": 1}))
        rec = attempt.read_attempt(folder)
        self.assertEqual((rec["summary"]["defects"], rec["answers"]["defects"], rec["problems"]),
                         ({"reply_unreadable": 1}, {"reply_unreadable": 1}, []))
        s.write(path, s.answers_doc([(A, s.VECTOR)]))
        rec = attempt.read_attempt(folder)
        self.assertIn("answers.json's counters or defects differ from the run summary's", rec["problems"])

    def test_another_attested_model(self):
        folder = self.folder(s.COMPLETE_RECORD)
        att = os.path.join(folder, "vex-internal.attestation.cdx.json")
        s.write(att, s.attestation(s.after_calls(A), "openai", "gpt-5.4-mini"))
        rec = attempt.read_attempt(folder, arm="after")
        self.assertFalse(rec["scores_usable"])
        self.assertIn("attested [('openai', 'gpt-5.4-mini')]", rec["archive_check"]["reason"])


class TestBeforeTheRecord(Base):
    def test_a_complete_download_its_added_fields_unknown(self):
        rec = attempt.read_attempt(self.folder(None, log=None, answers=False), arm="before")
        self.assertEqual((rec["record"], rec["outcome"]), (None, "complete"))
        self.assertEqual(rec["implied"], ["generate.exit_status", "enrich.exit_status", "archive_check"])
        for field in ("generate.started_at", "generate.ended_at", "enrich.started_at", "enrich.ended_at",
                      "vens_binary_sha256", "log", "summary"):
            self.assertIn(field, rec["unknown"])
        self.assertIsNone(rec["summary"])
        self.assertEqual(rec["recovery"]["archived_calls"], 2)
        self.assertTrue(rec["scores_usable"])

    def test_a_failed_download_read_as_0b_read_it(self):
        folder = self.folder(None, log=None, provenance=False, vex_file=False, answers=False)
        os.remove(os.path.join(folder, "vex-internal.attestation.cdx.json"))
        failure = {"attempt": 1, "job": "internal · run 1", "error": CAUSE}
        rec = attempt.read_attempt(folder, arm="before", failure_line=failure)
        self.assertEqual(rec["failure"], {"kind": None, "step": None, "cause": CAUSE, "cause_source": "failures.txt",
                                          "reason": attempt.NO_PROVENANCE})
        for field in ("failure.kind", "failure.step", "generate.exit_status"):
            self.assertIn(field, rec["unknown"])
        self.assertEqual(rec["implied"], [])

    def test_a_vex_without_provenance_or_record_is_refused(self):
        folder = self.folder(None, log=None, provenance=False)
        with self.assertRaises(attempt.Refused):
            attempt.read_attempt(folder, arm="before")


class TestNames(unittest.TestCase):
    def test_model_ids_with_dashes(self):
        self.assertEqual(attempt.parse_name("baseline-gpt-5.4-mini-2026-03-17-internal-api-r1-a2"),
                         {"model": "gpt-5.4-mini-2026-03-17", "context": "internal-api", "replicate": 1, "attempt": 2})
        self.assertEqual(attempt.parse_name("baseline-claude-sonnet-4-6-internal-r10-a1")["context"], "internal")
        self.assertIsNone(attempt.parse_name("baseline-x-elsewhere-r1-a1"))

    def test_run_meta(self):
        meta = attempt.run_meta({"id": 7, "display_title": "baseline · 2026-09-23 · anthropic/claude-sonnet-4-6 · "
                                                           "batch 1 · x10 · vens 9ac9ef4"})
        self.assertEqual(meta, {"run_id": 7, "archived_run": "2026-09-23", "provider": "anthropic",
                                "model": "claude-sonnet-4-6", "batch_size": 1, "replicates": 10,
                                "vens_ref": "9ac9ef4"})


if __name__ == "__main__":
    unittest.main()
