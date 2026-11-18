"""The runs the analysis reads and step 5's statistics on them, on synthetic records with known values."""
import math
import unittest
from fractions import Fraction

from chain import cdx, demo
from chain import cells as cellmod
from tests import records as r
from tests import support as s

CTX = "internal"
MODEL = f"openai/{s.MODEL}"


def cell_of(cells, arm="after", unit=CTX, model=s.MODEL, batch=1, campaign=None):
    commit = s.AFTER_SHA if arm == "after" else s.BEFORE_SHA
    return cells[cellmod.Cell(cellmod.DEMO, campaign, arm, "openai", model, unit, batch, commit)]


def before_run(replicate, aggregates, ids=None):
    """A before run whose CVE i has all four aggregates aggregates[i], so its score is that aggregate squared."""
    ids = ids or [f"CVE-2099-{i:04d}" for i in range(len(aggregates))]
    return r.record("before", CTX, replicate, {vid: r.rating(r.group_vector(v, v, v, v), "before")
                                               for vid, v in zip(ids, aggregates)})


def after_run(replicate, scores, ids):
    return r.record("after", CTX, replicate, dict(zip(ids, r.scored(scores).values())))


class TestRuns(unittest.TestCase):
    def test_a_replicates_run_is_its_first_complete_attempt(self):
        recs = [r.record("after", CTX, 1, None, attempt=1, outcome="failed"),
                r.record("after", CTX, 1, r.scored([1, 2]), attempt=2),
                r.record("after", CTX, 2, r.scored([3, 4]), attempt=1),
                r.record("after", CTX, 2, r.scored([5, 6]), attempt=2)]
        c = cell_of(cellmod.group(recs))
        self.assertIs(c["runs"][1], recs[1])
        self.assertIs(c["runs"][2], recs[2])
        self.assertEqual(c["problems"], ["replicate 2: 2 complete attempts, the first one read (run 1000 a1 r2)"])
        self.assertEqual(len(c["attempts"]), 4)

    def test_the_first_by_workflow_run_then_attempt(self):
        late, early = (r.record("after", CTX, 1, r.scored([1]), run_id=9, attempt=1),
                       r.record("after", CTX, 1, r.scored([2]), run_id=8, attempt=2))
        self.assertIs(cell_of(cellmod.group([late, early]))["runs"][1], early)

    def test_a_stray_run_and_an_unknown_replicate_are_never_runs(self):
        recs = [r.record("after", CTX, 1, r.scored([1, 2]), excluded="a stray run"),
                r.record("after", CTX, None, r.scored([1, 2]))]
        c = cell_of(cellmod.group(recs))
        self.assertEqual((c["runs"], len(c["attempts"])), ({}, 2))

    def test_an_unknown_arm_is_never_a_run_and_is_reported(self):
        rec = r.record(None, CTX, 1, r.scored([1, 2]))
        (k, c), = cellmod.group([rec]).items()
        self.assertEqual((k.arm, c["runs"], c["unusable"]), (None, {}, {}))
        self.assertEqual(c["problems"], ["1 attempt(s) whose arm is unknown: never a run"])
        self.assertEqual(demo.targets({k: c}, lambda rec: {"CVE-2099-0000"}), {})

    def test_campaigns_and_commits_are_never_pooled(self):
        recs = [r.record("after", CTX, 1, r.scored([1, 2])), r.record("after", CTX, 1, r.scored([3, 4]))]
        cells = cellmod.group(recs, campaign_of=lambda rec: "c1" if rec is recs[0] else "c2")
        self.assertEqual(sorted(k.campaign for k in cells), ["c1", "c2"])
        self.assertTrue(all(len(c["runs"]) == 1 for c in cells.values()))
        clash = cellmod.group([r.record("after", CTX, 1, r.scored([1])),
                               r.record("after", CTX, 2, r.scored([1]), commit="c" * 40)])
        self.assertEqual(list(cellmod.conflicts(clash).values()), [sorted([s.AFTER_SHA, "c" * 40])])
        self.assertEqual(demo.by_model(clash), {})

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
        self.assertEqual(cellmod.label(next(k for k in cells if k.batch == 10)),
                         f"None · before · {MODEL} batch 10 · internal")

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

    def test_the_bands_edges(self):
        lik = lambda v: {f: v for f in cdx.FACTORS[:8]}
        # L 3.0 is MEDIUM, its impact max(11/4, 2) LOW: low; L 6.0 and impact 6.0 are HIGH: critical
        at_3 = r.rating(r.vector(**lik(3), LC=2, LI=3, LAV=3, LAC=3, FD=2, RD=2, NC=2, PV=2))
        at_6 = r.rating(r.vector(**lik(6), **{f: 6 for f in cdx.FACTORS[8:]}))
        self.assertEqual(demo.own_rule(at_3, "after"), (Fraction(33, 4), "low"))
        self.assertEqual(demo.own_rule(at_6, "after"), (Fraction(36), "critical"))
        self.assertEqual((demo.band(2.999), demo.band(3.0), demo.band(5.999), demo.band(6.0)), (0, 1, 1, 2))

    def test_shares_over_the_report_its_unrated_cves_failing(self):
        ratings = {"CVE-A": r.rating(s.VECTOR), "CVE-B": r.rating(s.VECTOR, score=s.SCORE + 0.001)}
        rec = r.record("after", CTX, 1, ratings)
        got = demo.run_targets(rec, "after", {"CVE-A", "CVE-B", "CVE-C"}, {"CVE-A": True, "CVE-B": True})
        # CVE-B's score off by 0.001 is not recomputable; CVE-C, which the VEX does not rate, fails both
        self.assertEqual(got, {"cves": 3, "vex": True, "legal": 2, "recomputable": 1, "severity_ok": 2})

    def test_a_complete_run_without_a_vex_fails_every_cve(self):
        rec = r.record("after", CTX, 1, None, usable=False)
        rec["incomplete"] = ["a complete attempt without a VEX"]
        per = next(iter(demo.targets(cellmod.group([rec]), lambda x: {"CVE-A", "CVE-B"}, lambda x: {}).values()))
        self.assertEqual(per, {1: {"cves": 2, "vex": False, "legal": 0, "recomputable": 0, "severity_ok": 0}})

    def test_without_the_report_the_targets_are_unavailable(self):
        rec = r.record("before", CTX, 1, {"CVE-A": r.rating(r.group_vector(3, 4, 2, 3), "before")})
        per = next(iter(demo.targets(cellmod.group([rec]), lambda x: None).values()))
        self.assertEqual(per, {1: {"unavailable": demo.NO_REPORT}})


class TestSpreads(unittest.TestCase):
    def test_w_and_h_per_run_over_its_own_cves_and_the_cohorts(self):
        # the before's scores are the aggregates squared: 0, 0, 100
        recs = [after_run(1, [0, 10], ["A", "B"]), before_run(1, (0, 0, 10), ["A", "B", "C"])]
        row = demo.spreads(cellmod.group(recs))[(None, MODEL, CTX)]
        self.assertAlmostEqual(row["after"]["W"][0], math.sqrt(50))
        self.assertAlmostEqual(row["after"]["H"][0], 1.0)
        self.assertAlmostEqual(row["before"]["W"][0], 57.735026918962575)
        self.assertAlmostEqual(row["before"]["H"][0], 0.9182958340544896)
        self.assertEqual((row["after"]["cves"], row["before"]["cves"]), ([2], [3]))
        self.assertEqual(row["cohort"], {"only": {"after": [], "before": ["C"]}, "uneven": {"after": 0, "before": 0}})

    def test_the_case_of_the_review(self):
        # before A=0, B=0, C=10 over its own three CVEs: W 5.774, H 0.918; C at (2 + 2) / 2 x (5 + 5) / 2
        groups = ((0, 0, 0, 0), (0, 0, 0, 0), (2, 2, 5, 5))
        rec = r.record("before", CTX, 1, {vid: r.rating(r.group_vector(*g), "before") for vid, g in zip("ABC", groups)})
        row = demo.spreads(cellmod.group([rec, after_run(1, [0, 10], ["A", "B"])]))[(None, MODEL, CTX)]
        self.assertEqual((round(row["before"]["W"][0], 3), round(row["before"]["H"][0], 3)), (5.774, 0.918))

    def test_the_bound_by_hand(self):
        recs = [r.record("after", CTX, 1, r.scored([0, 2, 4])), r.record("after", CTX, 2, r.scored([0, 4, 8])),
                before_run(1, (1, 2, 3)), before_run(2, (1, 3, 5))]
        row = demo.spreads(cellmod.group(recs))[(None, MODEL, CTX)]
        # W after 2 and 4; before sd(1, 4, 9) 4.0415 and sd(1, 9, 25) 12.2202: the ratio 3 / 8.1308, the bound by the
        # two-cell delete-one jackknife on the log ratio, worked out apart
        ratio, bound, _ = row["after / before"]["W"]
        self.assertAlmostEqual(ratio, 0.36896616400999366)
        self.assertAlmostEqual(bound, 0.126076606177605)
        self.assertEqual(row["before rescored"]["W"], row["before"]["W"])
        self.assertAlmostEqual(row["after"]["H"][0], math.log2(3))


class TestCrossModel(unittest.TestCase):
    def test_delta_gap_and_bands(self):
        recs = [r.record("after", CTX, 1, r.scored([0], ["low"])), r.record("after", CTX, 2, r.scored([2], ["low"])),
                r.record("after", CTX, 1, r.scored([4], ["low"]), model="m2"),
                r.record("after", CTX, 2, r.scored([6], ["high"]), model="m2")]
        (k, got), = demo.cross_model(cellmod.group(recs)).items()
        self.assertEqual(k, (None, CTX, "after", MODEL, "openai/m2"))
        self.assertEqual((got["cross"], got["delta"], got["p"], got["mpd"]), (4.0, 2.0, 2 / 6, (2.0, 2.0)))
        # cross pairs low-low, low-high, low-low, low-high; within the first model 1, the second 0
        self.assertEqual((got["bands"], got["bands_within"]), (0.5, (1.0, 0.0)))

    def test_models_are_paired_at_one_batch_size(self):
        recs = [r.record("after", CTX, 1, r.scored([0])), r.record("after", CTX, 1, r.scored([0]), model="m2"),
                r.record("after", CTX, 1, r.scored([0]), model="m2", batch=10)]
        self.assertEqual([k[2] for k in sorted(demo.cross_model(cellmod.group(recs)), key=str)], ["after, batch 1"])


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
        got = demo.floors(cellmod.group(recs))[(None, MODEL, CTX, "before")]
        self.assertAlmostEqual(got["mpd"], 5 / 3)
        self.assertEqual((got["tri_mean"], got["spread"], got["replicates"]), (2.5, 2.5, [1, 2, 3]))

    def test_opportunity_every_cve_of_each_side(self):
        def answers(o, level):
            fs = r.factors(s.VECTOR)
            fs["O"] = {**fs["O"], "answer": o, "level": level}
            return fs

        ratings = {v: r.rating(s.VECTOR) for v in ("CVE-A", "CVE-B", "CVE-C")}
        rec = r.record("after", CTX, 1, ratings, answers={"CVE-A": answers("no_access_or_resources_required", 9),
                                                          "CVE-B": answers("special_access_or_resources_required", 4),
                                                          "CVE-C": answers(None, 9)})
        report = {"CVE-A", "CVE-B", "CVE-C", "CVE-D"}
        got = demo.opportunity(cellmod.group([rec]), {"CVE-A"}, lambda x: report)[(None, MODEL, CTX)]
        self.assertEqual(got["in the list"], {"cves": 1, "answered": 1, "dropped": 0,
                                              "answers": {"no_access_or_resources_required": 1}, "mean_level": 9.0})
        # outside: B answered; C not asked; D, the report's, not rated
        self.assertEqual(got["outside it"], {"cves": 3, "answered": 1, "dropped": 2,
                                             "answers": {"special_access_or_resources_required": 1},
                                             "mean_level": 4.0})


if __name__ == "__main__":
    unittest.main()
