"""The Java check on the mock's ratings of one scenario at both commits (tests/fixtures/mock):
every failure path on its own input, in both arms, the sub-score path through the stub calculator, and the driver
failing on any exit or verdict other than the one each input must give."""
import contextlib
import io
import os
import tempfile
import unittest

from chain import cdx, javacheck, javarun
from tests import support as s

AFTER = os.path.join(s.FIXTURES, "mock", "comp_gdpr.after.cdx.json")
BEFORE = os.path.join(s.FIXTURES, "mock", "comp_gdpr.before.cdx.json")
REPORT = os.path.join(s.FIXTURES, "mock", "comp_gdpr.report.json")
FAKE_JAVA = '#!/bin/sh\ncat "$FAKE_JAVA_OUT" 2>/dev/null\nexit 0\n'


class TestTheDriverOnCheck4Output(unittest.TestCase):
    """The driver against a calculator run that exits 0 with its output missing or wrong: no JDK needed."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.jdk = os.path.join(tmp.name, "bin")
        os.chmod(s.write(os.path.join(self.jdk, "java"), FAKE_JAVA), 0o755)
        self.out = os.path.join(tmp.name, "out.txt")
        os.environ["FAKE_JAVA_OUT"] = self.out
        self.addCleanup(os.environ.pop, "FAKE_JAVA_OUT", None)
        self.groups = [("after, comp_gdpr", "after", [(AFTER, REPORT)]),
                       ("before, comp_gdpr", "before", [(BEFORE, REPORT)])]
        self.lines = ["after, comp_gdpr: after; VEX files 1; CVEs 1; rated twice 0; PASS",
                      "before, comp_gdpr: before; VEX files 1; CVEs 1; rated twice 0; PASS",
                      f"{javacheck.CONTROL}: refused; VEX files 1; CVEs 1; rated twice 0; PASS",
                      "Check4: every label passes"]

    def unexpected(self, lines):
        s.write(self.out, "".join(line + "\n" for line in lines))
        expect = javacheck.Expect()
        javacheck.check_vexes(self.jdk, "jar", "classes", self.groups, expect)
        return [what for what, _, _ in expect.unexpected()]

    def test_the_whole_output(self):
        self.assertEqual(self.unexpected(self.lines), [])

    def test_no_output(self):
        bad = self.unexpected([])
        self.assertIn("Check4: labels", bad)
        self.assertIn("Check4: last line", bad)
        self.assertIn("Check4, after, comp_gdpr: verdict lines", bad)

    def test_a_label_missing(self):
        self.assertIn("Check4: labels", self.unexpected([self.lines[0], self.lines[2], self.lines[3]]))

    def test_a_label_twice(self):
        bad = self.unexpected([self.lines[0]] + self.lines)
        self.assertIn("Check4, after, comp_gdpr: verdict lines", bad)

    def test_a_vex_count_off(self):
        lines = [self.lines[0].replace("VEX files 1", "VEX files 2")] + self.lines[1:]
        self.assertEqual(self.unexpected(lines), ["Check4, after, comp_gdpr: kind and VEX files"])

    def test_no_last_line(self):
        self.assertEqual(self.unexpected(self.lines[:3]), ["Check4: last line"])

    def test_cases_with_no_output(self):
        s.write(self.out, "")
        expect = javacheck.Expect()
        cases = javacheck.failure_cases(cdx.vex_rows(AFTER)[0], cdx.vex_rows(BEFORE)[0])
        javacheck.run_cases(self.jdk, "jar", "classes", "stub", cases, expect)
        bad = [what for what, _, _ in expect.unexpected()]
        for case in cases:
            self.assertIn(f"{case.name}, case: verdict lines", bad)
            self.assertIn(f"{case.name}: last line", bad)


class TestBeforeReport(unittest.TestCase):
    def test_ratings_not_read_are_listed_not_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            vector = "SL:3/M:3/O:3/S:3/ED:4/EE:4/A:4/ID:4/LC:2/LI:2/LAV:2/LAC:2/FD:3/RD:3/NC:3/PV:3"
            vex = s.write(os.path.join(tmp, "vex.cdx.json"),
                          s.vex([("CVE-2099-0001", vector, "low", 8.75), ("CVE-2099-0002", "SL:9", "low", 1.0)]))
            lines, off = javarun.before_report([("before, x", "before", [(vex, REPORT)]),
                                                ("after, x", "after", [(AFTER, REPORT)])])
        self.assertEqual(off, [])
        self.assertEqual(lines, ["  before, x: 1 ratings read, off main's score or severity 0; not read 1",
                                 "    not read: CVE-2099-0002: vector 'SL:9': 1 factors, not 16"])

    def test_a_rating_off_main_rule_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            vector = "SL:3/M:3/O:3/S:3/ED:4/EE:4/A:4/ID:4/LC:2/LI:2/LAV:2/LAC:2/FD:3/RD:3/NC:3/PV:3"
            vex = s.write(os.path.join(tmp, "vex.cdx.json"), s.vex([("CVE-2099-0001", vector, "low", 9.0)]))
            _, off = javarun.before_report([("before, x", "before", [(vex, REPORT)])])
        self.assertEqual(off, ["CVE-2099-0001: score 9.0, main's rule gives 8.75"])


class TestJavaCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jdk, cls.jar = javacheck.jdk_bin(), s.env("VB_JAR")
        if cls.jdk is None or cls.jar is None:
            raise unittest.SkipTest("set VB_JAR and VB_JDK (or JAVA_HOME) to run the Java check "
                                    "(python3 -m chain.javacheck fetch-jar DIR fetches the JAR)")
        javacheck.verify_jar(cls.jar)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.classes, cls.stub = javacheck.compile_check(cls.jdk, cls.jar, cls.tmp.name)
        (cls.after_row,) = cdx.vex_rows(AFTER)
        (cls.before_row,) = cdx.vex_rows(BEFORE)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def cases(self):
        return javacheck.failure_cases(self.after_row, self.before_row)

    def test_every_failure_path_on_its_own_input(self):
        expect = javacheck.Expect()
        results = javacheck.run_cases(self.jdk, self.jar, self.classes, self.stub, self.cases(), expect)
        self.assertEqual(expect.unexpected(), [])
        got = {case.name: (rc, verdict) for case, rc, verdict in results}
        self.assertEqual(len(got), 15)
        self.assertEqual(sum(1 for rc, _ in got.values() if rc == 1), 13)
        self.assertEqual(got["an after rating through the stub calculator"],
                         (1, "FAIL: sub-scores off the level sums"))
        self.assertEqual(got["before, the report's CVE replaced by another one"],
                         (1, f"FAIL: {javacheck.ABSENT}, {javacheck.EXTRA}"))
        self.assertEqual(got["the before rating as published, refused"], (0, "PASS"))
        self.assertEqual(got["a control given the after's legal vector"], (1, "FAIL: a control vector accepted"))

    def test_the_driver_fails_on_an_exit_it_does_not_expect(self):
        expect = javacheck.Expect()
        javacheck.run_cases(self.jdk, self.jar, self.classes, self.stub, self.cases(), expect, want_rc=0)
        bad = expect.unexpected()
        self.assertEqual(len(bad), 13)
        self.assertTrue(all(what.endswith(": exit") and got == 1 for what, got, _ in bad))
        self.assertIn("unexpected 13", expect.report()[0])

    def test_the_driver_fails_on_a_verdict_it_does_not_expect(self):
        expect = javacheck.Expect()
        wrong = [javacheck.Case(c.name, c.kind, c.expected, c.rows, c.stub, c.rc, ("another reason",))
                 for c in self.cases() if c.reasons]
        javacheck.run_cases(self.jdk, self.jar, self.classes, self.stub, wrong, expect)
        self.assertEqual(len(expect.unexpected()), 13)

    def test_every_label_passes(self):
        expect = javacheck.Expect()
        res = javacheck.check_vexes(self.jdk, self.jar, self.classes,
                                    [("after, comp_gdpr", "after", [(AFTER, REPORT)]),
                                     ("before, comp_gdpr", "before", [(BEFORE, REPORT)])], expect)
        self.assertEqual((res.rc, expect.unexpected()), (0, []))
        verdicts = res.verdicts()
        self.assertEqual(set(verdicts.values()), {"PASS"})
        self.assertEqual(len(verdicts), 3)
        before = next(line for line in res.lines if line.startswith("before, comp_gdpr"))
        self.assertIn("refused by fromVector() or calculateScore() 1", before)

    def test_the_jar_sha256(self):
        self.assertEqual(javacheck.verify_jar(self.jar), self.jar)


class TestFetchJar(unittest.TestCase):
    """The JAR's sha256 check, with no download: a file already in place is checked, not replaced."""

    def test_a_jar_of_other_bytes_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            s.write(os.path.join(tmp, javacheck.JAR_NAME), b"not the jar")
            with self.assertRaises(javacheck.JarError):
                javacheck.fetch_jar(tmp)
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(javacheck.main(["fetch-jar", tmp]), 1)
            self.assertIn("sha256", err.getvalue())

    def test_usage(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(javacheck.main([]), 2)


if __name__ == "__main__":
    unittest.main()
