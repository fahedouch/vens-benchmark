"""The KPI measures on synthetic runs whose values are worked out by hand."""
import math
import unittest

from chain import cdx, kpi
from chain import cells as cellmod
from tests import records as r
from tests import support as s

MODEL = f"openai/{s.MODEL}"
FIRST = {f: int(v.split(":")[1]) for f, v in zip(cdx.FACTORS, s.VECTOR.split("/"))}
MOTIVE_4 = r.vector(**{**FIRST, "M": 4})  # L 61/8, still critical
OTHER = r.vector(M=4)


def after_run(replicate, ratings, answers, **kw):
    return r.record("after", "internal", replicate, ratings, answers=answers, **kw)


class TestStability(unittest.TestCase):
    def test_agreement_and_unchanged_severities(self):
        one = {"CVE-A": r.rating(s.VECTOR), "CVE-B": r.rating(OTHER)}
        two = {"CVE-A": r.rating(MOTIVE_4), "CVE-B": r.rating(OTHER, severity="low")}
        recs = [after_run(1, one, {v: r.factors(x["vector"]) for v, x in one.items()}),
                after_run(2, two, {v: r.factors(x["vector"]) for v, x in two.items()})]
        got = kpi.stability(cellmod.group(recs))[(None, MODEL, "internal", "after")]
        # Motive differs on CVE-A alone: half; every other factor agrees
        self.assertEqual(got["factor"]["M"], 0.5)
        self.assertEqual({f for f, v in got["factor"].items() if v != 1.0}, {"M"})
        self.assertEqual((got["vector"], got["severity_unchanged"], got["answers"]["M"]), (0.5, 0.5, 0.5))

    def test_one_run_says_nothing_of_stability(self):
        got = kpi.stability(cellmod.group([after_run(1, {"CVE-A": r.rating(s.VECTOR)}, None)]))
        row = got[(None, MODEL, "internal", "after")]
        self.assertEqual((row["vector"], row["severity_unchanged"]), (None, None))


class TestSensitivity(unittest.TestCase):
    def test_model_sensitivity(self):
        recs = [r.record("before", "internal", 1, r.scored([1, 2])),
                r.record("before", "internal", 2, r.scored([3, 6])),
                r.record("before", "internal", 1, r.scored([5, 4]), model="m2"),
                r.record("before", "internal", 2, r.scored([7, 4]), model="m2")]
        (got,) = kpi.model_sensitivity(cellmod.group(recs)).values()
        # CVE 0: means 2 and 6, ranges 1-3 and 5-7 apart; CVE 1: means 4 and 4, overlapping
        self.assertEqual(got, {"cves": 2, "gap": 2.0, "apart": 1, "replicates": ([1, 2], [1, 2])})

    def test_context_sensitivity_and_discrimination(self):
        ls = {"internal": [1, 2], "internal-api": [2, 1], "internet-facing": [3, 3]}
        cells = cellmod.group([r.record("after", ctx, rep, r.scored(x)) for ctx, x in ls.items() for rep in (1, 2)])
        got = kpi.context_sensitivity(cells)[(None, MODEL, "after")]
        # CVE 0 rises 1, 2, 3; CVE 1 falls from 2 to 1
        self.assertEqual((got["cves"], got["in_order"]), (2, 0.5))
        self.assertEqual(got["pairs"][("internal", "internal-api")], {"gap": 1.0, "noise": 0.0, "answers": {}})
        # the per-CVE means 1, 2, 2, 1, 3, 3: mean 2, squares 1, 0, 0, 1, 1, 1 over 5
        d = kpi.discrimination(cells)[(None, MODEL, "after")]
        self.assertAlmostEqual(d["sd"], math.sqrt(4 / 5))
        self.assertEqual(d["values"], 6)


    def test_the_noise_floor_needs_both_contexts_mpd(self):
        # internal holds one run, no MPD; internal-api's MPD (0 + 2) / 2, internet-facing's (0 + 1) / 2
        ls = {"internal": [[1, 2]], "internal-api": [[2, 1], [2, 3]], "internet-facing": [[3, 3], [3, 4]]}
        cells = cellmod.group([r.record("after", ctx, rep, r.scored(x)) for ctx, xs in ls.items()
                               for rep, x in enumerate(xs, 1)])
        pairs = kpi.context_sensitivity(cells)[(None, MODEL, "after")]["pairs"]
        self.assertEqual([pairs[p]["noise"] for p in (("internal", "internal-api"), ("internal", "internet-facing"),
                                                     ("internal-api", "internet-facing"))], [None, None, 0.75])


class TestFailuresAndCost(unittest.TestCase):
    def test_cannot_tell_apart_from_failures(self):
        vec = s.VECTOR
        recs = [after_run(1, {"CVE-A": r.rating(vec)}, {"CVE-A": r.factors(vec, EE=("cannot_tell", "answer"))},
                          summary={"defects": {"reply_unreadable": 2}}),
                after_run(2, {"CVE-A": r.rating(vec)}, {"CVE-A": r.factors(vec)}),
                after_run(3, None, None, outcome="failed", failure={"kind": "scoring", "cause": "stopped"})]
        (got,) = kpi.failures(cellmod.group(recs)).values()
        self.assertEqual(got["cannot_tell"]["questions"]["EE"], {"rate": 0.5, "asked": 2, "agreement": 0.0})
        self.assertEqual(got["cannot_tell"]["cves_affected"], 0.5)
        self.assertEqual((got["defects"], got["failed"], got["without_complete"]),
                         ({"reply_unreadable": 2}, {"scoring: stopped": 1}, [3]))

    def test_every_complete_attempt_without_its_record_counts(self):
        vec = s.VECTOR
        again = after_run(1, {"CVE-A": r.rating(vec)}, None, attempt=2, usable=False)
        again["incomplete"] = ["a complete run's VEX without its answers.json"]
        cells = cellmod.group([after_run(1, {"CVE-A": r.rating(vec)}, {"CVE-A": r.factors(vec)}), again])
        (c,) = cells.values()
        (got,) = kpi.failures(cells).values()
        # the replicate's run is its first attempt, usable; the second, complete, lacks answers.json
        self.assertEqual((list(c["runs"]), c["unusable"], got["incomplete"]), ([1], {}, 1))

    def test_cost_per_run(self):
        steps = lambda end: {"generate": {"started_at": "2026-11-20T10:00:00Z", "ended_at": end}}
        recs = [r.record("after", "internal", 1, r.scored([1, 2]), recovery={"llm_calls": 10, "recovery_calls": 0},
                         cost={"total": 0.1}, steps=steps("2026-11-20T10:01:00Z")),
                r.record("after", "internal", 2, r.scored([1, 2]), recovery={"llm_calls": 12, "recovery_calls": 2},
                         cost={"total": 0.3}, steps=steps("2026-11-20T10:02:00Z"))]
        (got,) = kpi.cost(cellmod.group(recs)).values()
        self.assertEqual({k: v if k == "replicates" else round(v, 6) for k, v in got.items()},
                         {"runs": 2, "replicates": [1, 2], "calls_per_run": 11.0, "calls_per_cve": 5.5,
                          "recovery_per_run": 1.0, "wall_seconds": 90.0, "usd_per_run": 0.2, "usd_per_cve": 0.1})


if __name__ == "__main__":
    unittest.main()
