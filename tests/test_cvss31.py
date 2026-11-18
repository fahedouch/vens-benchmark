"""The CVSS v3.1 base score the generator writes in each report's prose and as Trivy's V3Score."""
import itertools
import unittest

import make_scenarios as ms

# NVD's own v3.1 vectors and base scores (nvd@nist.gov's Primary cvssMetricV31), from its CVE API 2.0 on 2026-11-18.
NVD = {
    "CVE-2014-0160": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "CVE-2014-3566": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N", 3.4),
    "CVE-2014-6271": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "CVE-2016-5195": ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.0),
    "CVE-2017-0144": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    "CVE-2017-1000251": ("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.0),
    "CVE-2017-5753": ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N", 5.6),
    "CVE-2018-3639": ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    "CVE-2019-0708": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "CVE-2020-0601": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", 8.1),
    "CVE-2020-11022": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "CVE-2021-3156": ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    "CVE-2021-44228": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "CVE-2021-45046": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0),
    "CVE-2021-45105": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9),
    "CVE-2022-0847": ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    "CVE-2023-45857": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 6.5),
    "CVE-2023-4863": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
}
VALUES = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "HLN", "I": "HLN", "A": "HLN"}


def every_vector():
    for combo in itertools.product(*VALUES.values()):
        yield "CVSS:3.1/" + "/".join(f"{m}:{v}" for m, v in zip(VALUES, combo))


class TestBaseScore(unittest.TestCase):
    def test_nvd_published_scores(self):
        for cve, (vector, score) in NVD.items():
            self.assertEqual(ms.cvss31_score(vector), score, cve)

    def test_the_showcases_vectors_are_nvds(self):
        for key, cve in (("log4shell", "CVE-2021-44228"), ("axios", "CVE-2023-45857")):
            self.assertEqual((ms.REAL[key]["id"], ms.REAL[key]["vector"]), (cve, NVD[cve][0]))

    def test_no_impact_scores_zero(self):
        self.assertEqual(ms.cvss31_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N"), 0.0)
        self.assertEqual(ms.cvss31_rating(0.0), "NONE")

    def test_roundup(self):
        # Appendix A: the smallest number of one decimal at or above the input, noise below 1e-5 ignored.
        self.assertEqual(ms.cvss31_roundup(4.02), 4.1)
        self.assertEqual(ms.cvss31_roundup(4.0), 4.0)
        self.assertEqual(ms.cvss31_roundup(4.000000000000001), 4.0)
        self.assertEqual(ms.cvss31_roundup(0.1 + 0.2), 0.3)
        self.assertEqual(ms.cvss31_roundup(0.30001), 0.4)

    def test_ratings(self):
        cases = {0.1: "LOW", 3.9: "LOW", 4.0: "MEDIUM", 6.9: "MEDIUM", 7.0: "HIGH", 8.9: "HIGH", 9.0: "CRITICAL",
                 10.0: "CRITICAL"}
        for score, rating in cases.items():
            self.assertEqual(ms.cvss31_rating(score), rating, score)

    def test_other_strings_refused(self):
        for bad in ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:X",
                    "CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P"):
            with self.assertRaises(ValueError, msg=bad):
                ms.cvss31_score(bad)

    def test_agrees_with_the_cvss_package_on_every_base_vector(self):
        try:
            from cvss import CVSS3
        except ImportError:
            self.skipTest("the cvss package (requirements.txt) is not installed")
        vectors = list(every_vector())
        self.assertEqual(len(vectors), 2592)
        for vector in vectors:
            self.assertEqual(ms.cvss31_score(vector), float(CVSS3(vector).base_score), vector)


if __name__ == "__main__":
    unittest.main()
