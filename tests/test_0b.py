"""The reader against 0B's (step 4, PR 1): on 0B's two archived phases, actual baseline.yml downloads with failed
jobs among them, the new reader gives read0b.py's per-CVE score, T and B, and reads the failed attempts, the ones
whose calls/ alone is archived, as 0B's amended reader does (its A6).

VB_0B_MEASUREMENTS names the folder holding 0b-phase1 and 0b-phase2; VB_0B_READ0B, 0B's read0b.py, to compare
with its own functions (numpy needed). The archives are read through a mirror, never written."""
import importlib.util
import os
import tarfile
import tempfile
import unittest
import warnings

from chain import attempt, downloads
from tests import support as s

PHASES = {"0b-phase1": (119, 8806, 10), "0b-phase2": (180, 13320, 3)}


def mirror(src, dst):
    """src's run folders as symlinks under dst, with calls.tar.gz extracted beside them."""
    for run in sorted(d for d in os.listdir(src) if d.isdigit()):
        for name in os.listdir(os.path.join(src, run)):
            path = os.path.join(src, run, name)
            if os.path.isdir(path):
                os.makedirs(os.path.join(dst, run, name))
                for f in os.listdir(path):
                    os.symlink(os.path.join(path, f), os.path.join(dst, run, name, f))
            else:
                os.makedirs(os.path.join(dst, run), exist_ok=True)
                os.symlink(path, os.path.join(dst, run, name))
    with tarfile.open(os.path.join(src, "calls.tar.gz")) as tar:
        tar.extractall(dst, filter="data")
    return dst


def load_read0b(path):
    spec = importlib.util.spec_from_file_location("read0b", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def quiet(fn, *args, **kwargs):
    """0B's frozen reader leaves files to the garbage collector; its ResourceWarnings say nothing here."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        return fn(*args, **kwargs)


class TestAgainst0B(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.meas = s.env("VB_0B_MEASUREMENTS")
        if cls.meas is None:
            raise unittest.SkipTest("set VB_0B_MEASUREMENTS to the folder holding 0b-phase1 and 0b-phase2 to run "
                                    "the test against 0B's reader")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dirs, cls.records = {}, {}
        for phase in PHASES:
            src = os.path.join(cls.meas, phase)
            cls.dirs[phase] = mirror(src, os.path.join(cls.tmp.name, phase))
            failures = downloads.load_failures(os.path.join(src, "failures.txt"))
            cls.records[phase] = downloads.read_downloads(cls.dirs[phase], arm="before", failures=failures)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_counts(self):
        for phase, (complete, ratings, failed) in PHASES.items():
            recs = self.records[phase]
            done = [r for r in recs if r["outcome"] == "complete"]
            self.assertEqual(len(done), complete, phase)
            self.assertTrue(all(r["scores_usable"] for r in done), phase)
            self.assertEqual(sum(len(r["ratings"]) for r in done), ratings, phase)
            self.assertEqual(sum(1 for r in recs if r["outcome"] == "failed"), failed, phase)
            self.assertEqual([p for r in recs for p in r["problems"]], [], phase)

    def test_the_failed_attempts_as_a6_reads_them(self):
        for phase in PHASES:
            failed = [r for r in self.records[phase] if r["outcome"] == "failed"]
            self.assertTrue(all(r["failure"]["reason"] == attempt.NO_PROVENANCE for r in failed), phase)
            self.assertTrue(all(r["failure"]["cause"] and r["failure"]["cause_source"] == "failures.txt"
                                for r in failed), phase)
            self.assertTrue(all(r["folder"] is not None and r["calls"]["archived"] for r in failed), phase)
            self.assertTrue(all("failure.step" in r["unknown"] for r in failed), phase)

    def test_score_t_and_b_as_read0b_reads_them(self):
        path = s.env("VB_0B_READ0B")
        read0b = None
        if path is not None:
            try:
                read0b = load_read0b(path)
            except ImportError as e:
                self.skipTest(f"read0b.py does not import here: {e}")
        for phase in PHASES:
            for rec in (r for r in self.records[phase] if r["outcome"] == "complete"):
                vex = [os.path.join(rec["folder"], n) for n in os.listdir(rec["folder"])
                       if n.startswith("vex-") and not n.endswith(".attestation.cdx.json")][0]
                if read0b is not None:
                    want, mismatch = quiet(read0b.load_vex, vex, rescore=False)
                    self.assertEqual(mismatch, 0)
                else:
                    want = {vid: (((r["levels"]["SL"] + r["levels"]["ED"]) / 2) * ((r["levels"]["LC"]
                                                                                       + r["levels"]["FD"]) / 2),
                                  r["levels"]["LC"], r["levels"]["FD"]) for vid, r in rec["ratings"].items()}
                got = {vid: (r["score"], r["T"], r["B"]) for vid, r in rec["ratings"].items()}
                self.assertEqual(got, want, rec["folder"])

    def test_the_failed_attempts_as_read0b_lists_them(self):
        path = s.env("VB_0B_READ0B")
        if path is None:
            self.skipTest("set VB_0B_READ0B to compare with read0b.py's own load_dir")
        try:
            read0b = load_read0b(path)
        except ImportError as e:
            self.skipTest(f"read0b.py does not import here: {e}")
        for phase in PHASES:
            want = {(meta["run_id"], meta["context"], meta["replicate"], meta["attempt"], why)
                    for run in sorted(os.listdir(self.dirs[phase]))
                    for _, meta, data, why in quiet(read0b.load_dir, os.path.join(self.dirs[phase], run))
                    if data is None}
            got = {(r["what"]["run_id"], r["what"]["context"], r["what"]["replicate_in_run"], r["what"]["run_attempt"],
                    r["failure"]["reason"]) for r in self.records[phase] if r["outcome"] == "failed"}
            self.assertEqual(got, want, phase)


if __name__ == "__main__":
    unittest.main()
