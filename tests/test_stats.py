"""The statistics on synthetic cells whose values are worked out by hand, ties included."""
import math
import unittest

from chain import stats


class TestPerRun(unittest.TestCase):
    def test_w_is_the_sd_n_minus_1(self):
        # mean 2.5; squares 2.25 + 0.25 + 0.25 + 2.25 = 5, over 3
        self.assertAlmostEqual(stats.run_spread([[1, 2, 3, 4]])[0], math.sqrt(5 / 3), places=12)

    def test_w_of_one_cve_is_none(self):
        self.assertTrue(math.isnan(stats.run_spread([[7]])[0]))

    def test_h_counts_equal_rounded_scores_as_one_value(self):
        # 1.004 and 1.001 round to 1.0, so two values of two each: 1 bit
        self.assertAlmostEqual(stats.run_entropy([[1.004, 1.001, 2.0, 2.0]])[0], 1.0, places=12)

    def test_h_bounds(self):
        self.assertEqual(stats.run_entropy([[3.5, 3.5, 3.5]])[0], 0.0)
        self.assertAlmostEqual(stats.run_entropy([[1, 2, 3, 4]])[0], 2.0, places=12)

    def test_h_with_an_uneven_tie(self):
        # 2 of 4, 1, 1: -(0.5 log 0.5 + 2 x 0.25 log 0.25) = 0.5 + 1 = 1.5 bits
        self.assertAlmostEqual(stats.run_entropy([[9, 9, 1, 4]])[0], 1.5, places=12)


class TestPairs(unittest.TestCase):
    def test_mpd(self):
        # pairs: (0, 1) mean(1, 3) = 2; (0, 2) mean(2, 2) = 2; (1, 2) mean(1, 1) = 1
        self.assertAlmostEqual(stats.mpd([[0, 0], [1, 3], [2, 2]]), 5 / 3, places=12)
        self.assertIsNone(stats.mpd([[0, 0]]))

    def test_cross_mpd_and_delta(self):
        a, b = [[0], [2]], [[4], [6]]
        # cross: |0-4| 4, |0-6| 6, |2-4| 2, |2-6| 4, mean 4; within each 2; Delta 4 - 2
        self.assertAlmostEqual(stats.cross_mpd(a, b), 4.0)
        self.assertAlmostEqual(stats.delta(a, b), 2.0)

    def test_delta_is_a_u_statistic(self):
        # the same two runs for both models: cross pairs 0, 1, 1, 0 (mean 0.5), each within pair 1; Delta -0.5,
        # its expectation 0 when the models are identically distributed, not each draw
        a = [[1, 5], [3, 5]]
        self.assertAlmostEqual(stats.delta(a, a), -0.5)

    def test_delta_needs_two_runs_per_model(self):
        self.assertIsNone(stats.delta([[0]], [[4], [6]]))
        self.assertEqual(stats.gap_test([[0]], [[4], [6]], stats.rng_for("x")), (None, None))

    def test_gap_test_enumerated(self):
        # 6 relabellings of {0, 2} | {4, 6}: Delta 2 for the observed and its mirror, -1 for the four mixed ones
        d, p = stats.gap_test([[0], [2]], [[4], [6]], stats.rng_for("gap|test"))
        self.assertAlmostEqual(d, 2.0)
        self.assertAlmostEqual(p, 2 / 6)

    def test_gap_test_drawn_is_seeded(self):
        a = [[i, i + 1] for i in range(10)]
        b = [[i + 3, i] for i in range(10)]
        first = stats.gap_test(a, b, stats.rng_for("gap|seeded"), n_perm=500)
        self.assertEqual(first, stats.gap_test(a, b, stats.rng_for("gap|seeded"), n_perm=500))
        self.assertTrue(1 / 501 <= first[1] <= 1)

    def test_agreement(self):
        a = [["low", "high"], ["low", "low"]]
        b = [["low", "high"]]
        # (a1, b1): 2 of 2; (a2, b1): 1 of 2
        self.assertAlmostEqual(stats.agreement(a, b), 0.75)
        self.assertAlmostEqual(stats.within_agreement(a), 0.5)
        self.assertIsNone(stats.within_agreement(b))


class TestNonInferiority(unittest.TestCase):
    def test_bound_by_hand(self):
        # ratio 3 / 2; leave-one-out log ratios log 2 and 0 for the arm, constant for the control:
        # var = 1/2 x 2 x (log 2 / 2)^2, se = log 2 / 2
        ratio, bound, verdict = stats.noninferiority([2, 4], [2, 2])
        self.assertAlmostEqual(ratio, 1.5)
        self.assertAlmostEqual(bound, math.exp(math.log(1.5) - stats.Z * math.log(2) / 2), places=12)
        self.assertEqual(verdict, "fail")

    def test_bound_with_both_cells_varying(self):
        # ratio 3 / (9.5 / 3); each cell's leave-one-out log ratios vary, both enter the variance
        ratio, bound, _ = stats.noninferiority([2, 4, 3], [3, 3, 3.5])
        self.assertAlmostEqual(ratio, 0.9473684210526316)
        self.assertAlmostEqual(bound, 0.6799092334100059)

    def test_zeros(self):
        self.assertEqual(stats.noninferiority([1, 2], [0, 0]), (None, None, "pass"))
        self.assertEqual(stats.noninferiority([0, 0], [1, 2]), (0.0, 0.0, "fail"))
        self.assertEqual(stats.noninferiority([2, 2], [0, 4])[1:], (0.0, "fail"))

    def test_one_run_gives_the_ratio_alone(self):
        self.assertEqual(stats.noninferiority([3], [2]), (1.5, None, None))


class TestFloor(unittest.TestCase):
    def test_by_hand(self):
        f = stats.floor([[0, 0], [1, 3], [2, 2]])
        # one triple: max - min 2 and 3 over the two CVEs, mean 2.5; the N-run spread the same
        self.assertAlmostEqual(f["mpd"], 5 / 3)
        self.assertEqual((f["tri_mean"], f["tri_min"], f["tri_max"], f["spread"]), (2.5, 2.5, 2.5, 2.5))
        self.assertEqual((f["runs"], f["cves"]), (3, 2))

    def test_below_three_and_two_runs(self):
        f = stats.floor([[0, 0], [1, 3]])
        self.assertEqual((f["tri_mean"], f["spread"]), (None, 2.0))
        f = stats.floor([[0, 0]])
        self.assertEqual((f["mpd"], f["spread"]), (None, None))


if __name__ == "__main__":
    unittest.main()
