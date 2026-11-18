"""The runs the analysis reads and step 5's statistics on them, on synthetic records with known values."""
import math
import unittest
from fractions import Fraction

from chain import demo, stats
from chain import cells as cellmod
from tests import records as r
from tests import support as s

CTX = "internal"
MODEL = f"openai/{s.MODEL}"


def cell_of(cells, arm="after", unit=CTX, model=s.MODEL, batch=1):
    return cells[(cellmod.DEMO, arm, "openai", model, unit, batch)]


def before_run(replicate, aggregates):
    """A before run whose CVE i has all four aggregates aggregates[i], so its score is that aggregate squared."""
    return r.record("before", CTX, replicate, {f"CVE-2099-{i:04d}": r.rating(r.group_vector(v, v, v, v), "before")
                                               for i, v in enumerate(aggregates)})


class TestRuns(unittest.TestCase):
    def test_a_replicates_run_is_its_first_complete_attempt(self):
        recs = [r.record("after", CTX, 1, None, attempt=1, outcome="failed"),
                r.record("after", CTX, 1, r.scored([1, 2]), attempt=2),
                r.record("after", CTX, 2, r.scored([3, 4]), attempt=1),
                r.record("after", CTX, 2, r.scored([5, 6]), attempt=2)]
        c = cell_of(cellmod.group(recs))
        self.assertEqual(sorted(c["runs"]), [1, 2])
        self.assertIs(c["runs"][1], recs[1])
        self.assertIs(c["runs"][2], recs[2])
        self.assertEqual(c["problems"], ["replicate 2: 2 complete attempts, the first one read (run 1000 a1 r2)"])
        self.assertEqual(len(c["attempts"]), 4)

    def test_a_stray_run_and_an_unknown_replicate_are_never_runs(self):
        recs = [r.record("after", CTX, 1, r.scored([1, 2]), excluded="a stray run"),
                r.record("after", CTX, None, r.scored([1, 2]))]
        c = cell_of(cellmod.group(recs))
        self.assertEqual((c["runs"], len(c["attempts"])), ({}, 2))

    def test_a_complete_run_not_usable_says_why_and_still_counts_in_the_targets(self):
        rec = r.record("after", CTX, 1, r.scored([1, 2]), usable=False)
        rec["incomplete"] = ["a complete run's VEX without its answers.json"]
        c = cell_of(cellmod.group([rec]))
        self.assertEqual(c["runs"], {})
        self.assertEqual(c["unusable"][1][1], "a complete run's VEX without its answers.json")
        self.assertEqual(cellmod.complete_runs(c), {1: rec})

    def test_batch_sizes_are_never_one_cell(self):
        cells = cellmod.group([r.record("before", CTX, 1, r.scored([1])),
                               r.record("before", CTX, 1, r.scored([2]), batch=10)])
        self.assertEqual(len(cells), 2)
        self.assertEqual(cellmod.label(next(k for k in cells if k[5] == 10)), f"before · {MODEL} batch 10 · internal")

    def test_two_commits_in_one_replicate_are_flagged(self):
        cells = cellmod.group([r.record("after", CTX, 1, r.scored([1]), commit="a" * 40),
                               r.record("after", CTX, 1, r.scored([1]), commit="b" * 40, attempt=2)])
        self.assertIn("replicate 1: complete attempts at 2 vens commits", cell_of(cells)["problems"])

    def test_sources_name_each_attempt(self):
        recs = {1: r.record("after", CTX, 1, {}, run_id=7), 2: r.record("after", CTX, 2, {}, run_id=7),
                3: r.record("after", CTX, 3, {}, run_id=7, attempt=2)}
        self.assertEqual(cellmod.sources(recs), "run 7 a1 r1-r2; run 7 a2 r3")


class TestTargets(unittest.TestCase):
    def test_own_rule(self):
        # L 58/8, T 34/4, B 16/4: 7.25 x 8.5
        self.assertEqual(demo.own_rule(r.rating(s.VECTOR), "after"), (Fraction(493, 8), "critical"))
        before = r.rating(r.group_vector(3, 4, 2, 3), "before")
        # ((3 + 4) / 2) x ((2 + 3) / 2) = 8.75, main's thresholds: low
        self.assertEqual(demo.own_rule(before, "before"), (Fraction(35, 4), "low"))
        # rescored: L 3.5 x max(2, 3)
        self.assertEqual(demo.rescored(before), 10.5)

    def test_shares_over_the_report(self):
        ratings = {"CVE-A": r.rating(s.VECTOR), "CVE-B": r.rating(s.VECTOR, score=61.0, severity="low")}
        rec = r.record("after", CTX, 1, ratings)
        got = demo.run_targets(rec, "after", {"CVE-A", "CVE-B", "CVE-C"}, {"CVE-A": True, "CVE-B": False})
        self.assertEqual(got, {"cves": 3, "over": "the report's CVEs", "legal": 1, "recomputable": 1,
                               "severity_ok": 1})

    def test_without_the_report_over_the_rated_cves(self):
        rec = r.record("before", CTX, 1, {"CVE-A": r.rating(r.group_vector(3, 4, 2, 3), "before")})
        got = demo.run_targets(rec, "before", None)
        self.assertEqual((got["cves"], got["legal"], got["recomputable"], got["severity_ok"]), (1, None, 1, 1))
        self.assertIn("no report given", got["over"])

    def test_targets_read_every_complete_run(self):
        good = r.record("after", CTX, 1, {"CVE-A": r.rating(s.VECTOR)})
        unusable = r.record("after", CTX, 2, {"CVE-A": r.rating(s.VECTOR, score=1.0)}, usable=False)
        per = next(iter(demo.targets(cellmod.group([good, unusable]), lambda rec: {"CVE-A"}).values()))
        self.assertEqual({rep: t["recomputable"] for rep, t in per.items()}, {1: 1, 2: 0})


class TestSpreads(unittest.TestCase):
    def test_w_h_and_the_bound(self):
        recs = [r.record("after", CTX, 1, r.scored([0, 2, 4])), r.record("after", CTX, 2, r.scored([0, 4, 8])),
                before_run(1, (1, 2, 3)), before_run(2, (1, 3, 5))]
        row = demo.spreads(cellmod.group(recs))[(MODEL, CTX)]
        self.assertEqual(row["after"]["W"], [2.0, 4.0])
        # the before's scores are the aggregates squared: 1, 4, 9 (mean 14/3) and 1, 9, 25
        want = math.sqrt(((1 - 14 / 3) ** 2 + (4 - 14 / 3) ** 2 + (9 - 14 / 3) ** 2) / 2)
        self.assertAlmostEqual(row["before"]["W"][0], want)
        self.assertEqual(row["after / before"]["W"], stats.noninferiority([2.0, 4.0], row["before"]["W"]))
        # rescored under L x max(T, B) on the same levels: the same squares here
        self.assertEqual(row["before rescored"]["W"], row["before"]["W"])
        self.assertAlmostEqual(row["after"]["H"][0], math.log2(3))


class TestCrossModel(unittest.TestCase):
    def test_delta_gap_and_bands(self):
        recs = [r.record("after", CTX, 1, r.scored([0], ["low"])), r.record("after", CTX, 2, r.scored([2], ["low"])),
                r.record("after", CTX, 1, r.scored([4], ["low"]), model="m2"),
                r.record("after", CTX, 2, r.scored([6], ["high"]), model="m2")]
        (k, got), = demo.cross_model(cellmod.group(recs)).items()
        self.assertEqual(k, (CTX, "after", MODEL, "openai/m2"))
        self.assertEqual((got["cross"], got["delta"], got["p"], got["mpd"]), (4.0, 2.0, 2 / 6, (2.0, 2.0)))
        # cross pairs low-low, low-high, low-low, low-high; within the first model 1, the second 0
        self.assertEqual((got["bands"], got["bands_within"]), (0.5, (1.0, 0.0)))

    def test_models_are_paired_at_one_batch_size(self):
        recs = [r.record("after", CTX, 1, r.scored([0])), r.record("after", CTX, 1, r.scored([0]), model="m2"),
                r.record("after", CTX, 1, r.scored([0]), model="m2", batch=10)]
        self.assertEqual([k[1] for k in sorted(demo.cross_model(cellmod.group(recs)))], ["after, batch 1"])


class TestImpacts(unittest.TestCase):
    def test_340_by_hand(self):
        # (T, B): B > T twice, both B >= 6 with T < 6, the collapse; T > B once; B = T once
        impacts = [(2, 7), (7, 7), (6, 3), (5, 6)]
        rec = r.record("after", CTX, 1, r.scored([1, 2, 3, 4], ["low", "high", "low", "medium"], impacts))
        self.assertEqual(demo.impact_report(rec),
                         {"cves": 4, "distinct_T": 4, "distinct_B": 3, "distinct_max": 2, "B>T": 0.5, "T>B": 0.25,
                          "B=T": 0.25, "low": 0.5, "collapse": 0.5})


class TestFloorAndOpportunity(unittest.TestCase):
    def test_floor_per_model_context_and_arm(self):
        recs = [r.record("before", CTX, i + 1, r.scored(x)) for i, x in enumerate(([0, 0], [1, 3], [2, 2]))]
        got = demo.floors(cellmod.group(recs))[(MODEL, CTX, "before")]
        self.assertAlmostEqual(got["mpd"], 5 / 3)
        self.assertEqual((got["tri_mean"], got["spread"], got["replicates"]), (2.5, 2.5, [1, 2, 3]))

    def test_opportunity_in_and_out_of_the_list(self):
        def answers(o, level):
            fs = r.factors(s.VECTOR)
            fs["O"] = {**fs["O"], "answer": o, "level": level}
            return fs

        ratings = {v: r.rating(s.VECTOR) for v in ("CVE-A", "CVE-B", "CVE-C")}
        rec = r.record("after", CTX, 1, ratings, answers={"CVE-A": answers("no_access_or_resources_required", 9),
                                                          "CVE-B": answers("special_access_or_resources_required", 4),
                                                          "CVE-C": answers(None, 9)})
        got = demo.opportunity(cellmod.group([rec]), {"CVE-A"})[(MODEL, CTX)]
        self.assertEqual(got["in the list"], {"cves": 1, "answers": {"no_access_or_resources_required": 1},
                                              "mean_level": 9.0})
        self.assertEqual(got["outside it"], {"cves": 1, "answers": {"special_access_or_resources_required": 1},
                                             "mean_level": 4.0})


if __name__ == "__main__":
    unittest.main()
