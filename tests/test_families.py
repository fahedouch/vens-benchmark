"""The scenarios' families on synthetic runs: for each family a check's pass, its fail and a replicate missing; a
move that is all Go's reported as such; the diagnostics that read no contrast."""
import math
import unittest
from fractions import Fraction

from chain import diagnostics, families, report_scen, verdicts
from chain import cells as cellmod
from tests import records as r
from tests import support as s

MODEL = f"openai/{s.MODEL}"
# the after's severity from its likelihood and impact bands, every likelihood factor at the first level, every
# impact factor at the second; the before's from one aggregate in every group, its score that aggregate squared
SEVERITY_LEVELS = {"info": (1, 1), "low": (4, 2), "medium": (4, 4), "high": (9, 4), "critical": (9, 9)}
BEFORE_SEVERITY = {"info": 1, "low": 3, "medium": 5, "high": 7, "critical": 9}
NULL = {"threat_agent": 8, "vulnerability": 7, "technical_impact": 7, "business_impact": 5}
PAIR_VALUES = {"le": ((3, 5), (5, 3)), "lt": ((3, 5), (5, 5)), "eq": ((5, 5), (3, 5)), "gap": ((3, 5), (5, 5))}


def made(quantity, value, arm):
    """(vector, given factors) whose quantity is value in the arm."""
    if quantity.startswith("answer "):
        return r.vector(), {quantity.split()[1]: (value, "answer")}
    if quantity == "severity" and arm == "after":
        lik, imp = SEVERITY_LEVELS[value]
        return r.vector(**{f: lik for f in families.GROUPS["L"]},
                        **{f: imp for f in families.GROUPS["T"] + families.GROUPS["B"]}), {}
    if arm == "before":
        v = BEFORE_SEVERITY[value] if quantity == "severity" else value
        if quantity in ("severity", "score"):
            return r.group_vector(v, v, v, v), {}
        names = families.GROUPS.get(quantity, (quantity,))
        return r.group_vector(*[v if set(families.GROUPS[g]) & set(names) else 5 for g in ("TA", "VU", "T", "B")]), {}
    return r.vector(**{f: value for f in families.GROUPS.get(quantity, (quantity,))}), {}


def run(arm, sid, value, quantity, replicate=1, outcome="complete"):
    vec, given = made(quantity, value, arm)
    vid = "CVE-2099-0001"
    answers = {vid: r.factors(vec, **given)} if arm == "after" else None
    return r.record(arm, sid, replicate, {vid: r.rating(vec, arm)}, scenario=True, outcome=outcome, answers=answers)


def pair_runs(check, arm, values, missing=False):
    a, b = check.scenarios[0]
    return [run(arm, a, values[0], check.quantity),
            run(arm, b, values[1], check.quantity, outcome="failed" if missing else "complete")]


def single_values(check, arm):
    if check.test == "in":
        target = dict(check.target)[arm]
        return target[0], "critical" if "low" in target else "low"
    if check.test == "is":
        return dict(check.target)[arm][0], "identified"
    return {"below_null": (3, 9), "above_null": (9, 3), "any": (5, None)}[check.test]


def evaluate(check, recs, arm):
    scen = {sid: {"null": NULL} for item in check.scenarios
            for sid in (item if isinstance(item, tuple) else (item,))}
    rows = [x for x in families.evaluate(cellmod.group(recs), scen, (check,)) if x["arm"] == arm]
    return rows[0]["row"]


class TestEachFamily(unittest.TestCase):
    def test_pass_fail_and_missing(self):
        seen = set()
        for check in verdicts.CHECKS:
            seen.add(check.family)
            for arm, _ in check.kinds:
                with self.subTest(family=check.family, check=check.label, arm=arm):
                    self._one(check, arm)
        self.assertEqual(len(seen), 13)  # the eleven families, the showcases and reachability

    def _one(self, check, arm):
        if check.pairs():
            good, bad = PAIR_VALUES[check.test]
            if check.quantity.startswith("answer "):
                good, bad = ("x", "x"), ("x", "y")
            self.assertEqual([p["ok"] for p in evaluate(check, pair_runs(check, arm, good), arm)["per"]], [True])
            self.assertEqual([p["ok"] for p in evaluate(check, pair_runs(check, arm, bad), arm)["per"]], [False])
            got = evaluate(check, pair_runs(check, arm, good, missing=True), arm)
        else:
            sid = check.scenarios[0]
            good, bad = single_values(check, arm)
            self.assertEqual([p["ok"] for p in evaluate(check, [run(arm, sid, good, check.quantity)], arm)["per"]],
                             [True])
            if bad is not None:
                got = evaluate(check, [run(arm, sid, bad, check.quantity)], arm)
                self.assertEqual([p["ok"] for p in got["per"]], [False])
            got = evaluate(check, [run(arm, sid, good, check.quantity, outcome="failed")], arm)
        self.assertEqual((got["per"], got["missing"], got["median"][-1]), ([], [1], None))


class TestTheVerdictOnTheMedians(unittest.TestCase):
    def test_over_replicates(self):
        check = next(c for c in verdicts.CHECKS if c.label == "VU, ctrl_on at most ctrl_off")
        recs = [run("after", "ctrl_on", 3, "VU", 1), run("after", "ctrl_off", 5, "VU", 1),
                run("after", "ctrl_on", 6, "VU", 2), run("after", "ctrl_off", 5, "VU", 2),
                run("after", "ctrl_on", 4, "VU", 3), run("after", "ctrl_off", 7, "VU", 3)]
        got = evaluate(check, recs, "after")
        self.assertEqual([p["ok"] for p in got["per"]], [True, False, True])
        # medians: ctrl_on 4, ctrl_off 5
        self.assertEqual(got["median"], (4, 5, True))

    def test_the_kind_decides_the_wording(self):
        rows = families.evaluate(cellmod.group([run("after", "ctrl_on", 3, "VU"), run("after", "ctrl_off", 5, "VU"),
                                                run("before", "ctrl_on", 3, "VU"), run("before", "ctrl_off", 5, "VU")]),
                                 {}, [c for c in verdicts.CHECKS if c.family == "8 Relevant against irrelevant control"])
        text = "\n".join(report_scen.families_section({"rows": rows, "moves": {}}))
        self.assertIn("| VU, ctrl_on below ctrl_off | after | diagnostic |", text)
        self.assertIn("judged by nothing", text)
        self.assertNotIn("| VU, ctrl_on below ctrl_off | after | diagnostic | " + MODEL + " | ctrl_on / ctrl_off | "
                         "b - a: 2.000 x1 | 3.000 -> 5.000 | pass", text)


def sens_run(sid, lc_level, lc_answer, lc_source="answer"):
    vec = r.vector(LC=lc_level)
    vid = "CVE-2099-0007"
    return r.record("after", sid, 1, {vid: r.rating(vec)}, scenario=True,
                    answers={vid: r.factors(vec, LC=(lc_answer, lc_source))})


class TestMoves(unittest.TestCase):
    def rows(self, recs):
        return families.evaluate(cellmod.group(recs), {},
                                 [c for c in verdicts.CHECKS if c.family == "3 Data sensitivity"])

    def test_a_move_that_is_all_gos(self):
        # Loss of confidentiality's extent answered the same, crossed with data sensitivity's column: 2, then 6
        rows = self.rows([sens_run("sens_low", 2, "minimal"), sens_run("sens_high", 6, "minimal")])
        moves = families.family_moves(rows)
        # T's move is Go's; LI's, the other pair the after reads on a level, is none
        self.assertEqual(dict(moves[("3 Data sensitivity", MODEL)]), {families.GO: 1, families.NONE: 1})
        self.assertTrue(families.all_gos(moves[("3 Data sensitivity", MODEL)]))
        t = next(x for x in rows if x["check"].quantity == "T" and x["arm"] == "after")
        self.assertEqual(t["row"]["per"][0]["moved"], [("LC", 2, 6, "answer", "answer", True)])
        text = "\n".join(report_scen.families_section({"rows": rows, "moves": moves}))
        self.assertIn("all Go's: the after's move here is Go's, not the model's reading", text)

    def test_a_move_of_the_model_and_of_go_by_source(self):
        model = families.move(sens_run("a", 2, "minimal"), sens_run("b", 6, "extensive"), "T")
        go = families.move(sens_run("a", 2, None, "floor"), sens_run("b", 6, None, "config"), "T")
        none = families.move(sens_run("a", 2, "minimal"), sens_run("b", 2, "minimal"), "T")
        self.assertEqual((model, go, none), (families.MODEL, families.GO, families.NONE))
        counter = families.family_moves(self.rows([sens_run("sens_low", 2, "minimal"),
                                                   sens_run("sens_high", 6, "extensive")]))
        self.assertFalse(families.all_gos(counter[("3 Data sensitivity", MODEL)]))

    def test_the_before_is_not_attributed(self):
        rows = [x for x in self.rows([run("before", "sens_low", 3, "T"), run("before", "sens_high", 5, "T")])
                if x["arm"] == "before"]
        self.assertEqual([p["move"] for x in rows for p in x["row"]["per"]], [None])


class TestDiagnostics(unittest.TestCase):
    def test_null_under_each_arms_rule(self):
        # likelihood (8 + 7) / 2; the before x (7 + 5) / 2 = 45, high; the after x max(7, 5) = 52.5, critical
        self.assertEqual(diagnostics.null_rules(NULL),
                         {"before": (Fraction(45), "high"), "after": (Fraction(105, 2), "critical")})

    def test_consistency(self):
        recs = [run("after", "expo_internal", 3, "score", 1), run("after", "expo_internal", 5, "score", 2)]
        got = diagnostics.consistency(cellmod.group(recs))
        # scores 9 and 25: SD sqrt(128)
        self.assertAlmostEqual(got["per"][(MODEL, "expo_internal", "after")], math.sqrt(128))
        self.assertEqual(got["score_sd"][(MODEL, "after")][1], 1)
        # every answer is a<level>, every level 3 then 5: no question agrees
        self.assertEqual(got["answers"][(MODEL, "PV")], (0.0, 1))

    def test_the_table_with_the_fallback(self):
        recs = [run("after", "wrong_yaml", 3, "score"), run("before", "wrong_yaml", 5, "score")]
        fallback = [run("after", "wrong_yaml", 9, "score"), run("before", "wrong_yaml", 1, "score")]
        (row,) = diagnostics.null_table(cellmod.group(recs), {"wrong_yaml": {"null": NULL}},
                                        diagnostics.fallback_cells(fallback))
        self.assertEqual(row["arms"], {(MODEL, "after"): (9.0, "medium", 1), (MODEL, "before"): (25.0, "medium", 1)})
        self.assertEqual(row["fallback"], (81.0, "critical", 1))
        self.assertEqual([x[:3] for x in diagnostics.wrong_yaml(cellmod.group(recs))[(MODEL, "after")]],
                         [(1, 9.0, "medium")])


if __name__ == "__main__":
    unittest.main()
