"""Target (i) per CVE through the calculator: VB_JAR, the calculator's 1.0.1 JAR, and a JDK (VB_JDK, JAVA_HOME or
javac's folder)."""
import os
import tempfile
import unittest

from chain import javacheck, legal
from tests import records as r
from tests import support as s

BEFORE = r.group_vector(3, 4, 2, 3)


class TestLegal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jar, cls.jdk = s.env("VB_JAR"), javacheck.jdk_bin()
        if cls.jar is None or cls.jdk is None:
            raise unittest.SkipTest("set VB_JAR and a JDK (VB_JDK or JAVA_HOME) to run the Java check per CVE")

    def test_each_cve_accepted_or_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            after = s.write(os.path.join(tmp, "after.cdx.json"), s.vex([
                ("CVE-A", s.VECTOR, s.SEVERITY, s.SCORE), ("CVE-B", None, None, None),
                ("CVE-C", s.VECTOR, s.SEVERITY, s.SCORE), ("CVE-C", s.VECTOR, s.SEVERITY, s.SCORE),
                ("CVE-X", s.VECTOR, s.SEVERITY, s.SCORE)]))
            before = s.write(os.path.join(tmp, "before.cdx.json"), s.vex([("CVE-A", BEFORE, "low", 8.75)]))
            got = legal.accepted({"a": ("after", after, {"CVE-A", "CVE-B", "CVE-C", "CVE-D"}),
                                  "b": ("before", before, {"CVE-A"})}, self.jdk, self.jar)
        accepted = {name: {vid: x["accepted"] for vid, x in per.items()} for name, per in got.items()}
        # CVE-B listed without a rating, CVE-C listed twice, CVE-D missing; CVE-X, not the report's, not declared;
        # main's vector, its group levels copied four times, is off the calculator's enumeration
        self.assertEqual(accepted, {"a": {"CVE-A": True, "CVE-B": False, "CVE-C": False, "CVE-D": False},
                                    "b": {"CVE-A": False}})
        self.assertEqual(got["a"]["CVE-A"], {"accepted": True, "sub_off": False, "severity_off": False,
                                             "score_off": False})

    def test_an_after_score_off_is_accepted_and_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            vex = s.write(os.path.join(tmp, "after.cdx.json"), s.vex([("CVE-A", s.VECTOR, "low", s.SCORE + 1)]))
            got = legal.accepted({"a": ("after", vex, {"CVE-A"})}, self.jdk, self.jar)["a"]["CVE-A"]
        self.assertEqual(got, {"accepted": True, "sub_off": False, "severity_off": True, "score_off": True})


if __name__ == "__main__":
    unittest.main()
