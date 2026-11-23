"""C1 + C2's implementation gate without a reachability relay (plan Z0d), on synthetic inputs (no vens): a scenario's
one CVE taken over all its rows, every after run recomputed from its frozen inputs and its own answers, any VEX
status or declared block failing, each after cell binding on every expected replicate, and the pinned contract.
tests/test_c1c2_mock.py runs the gate on vens's mock."""
import json
import os
import shutil
import tempfile
import unittest

import ctx_analyze
from chain import cdx, conform, contract, report_scen, verdicts
from chain import cells as cellmod
from tests import records as r
from tests import support as s

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS = os.path.join(ROOT, "scenarios")
A = "CVE-2099-0001"
GIVEN = {"M": "possible_reward", "O": "some_access_or_resources_required", "EE": "difficult", "LAC": "unidentified",
         "FD": "bankruptcy", "RD": "minimal_damage", "PV": "hundreds"}
STATUS = {"state": "not_affected", "justification": "code_not_reachable", "detail": "compiled out"}


def corpus_copy(tmp, changes):
    """scenarios/ copied under tmp, each of changes {sid: function(report) -> report} applied to its report."""
    root = os.path.join(tmp, "scenarios")
    shutil.copytree(SCENARIOS, root)
    for sid, change in changes.items():
        path = os.path.join(root, sid, "report.json")
        with open(path, encoding="utf-8") as fh:
            doc = change(json.load(fh))
        s.write(path, doc)
    return root


def another_row(pkg, cia):
    """A report change adding a row of its one CVE in package pkg, its vector giving cia."""
    def change(doc):
        f = dict(doc["Results"][0]["Vulnerabilities"][0], PkgName=pkg,
                 CVSS={"redhat": {"V3Vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/{cia}"}})
        doc["Results"][0]["Vulnerabilities"].append(f)
        return doc
    return change


class TestTheScenariosCVE(unittest.TestCase):
    """verdicts.load takes a scenario's one CVE over all its rows."""

    def test_the_worst_value_over_every_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            scen = verdicts.load(corpus_copy(tmp, {"sens_low": another_row("libother", "C:H/I:N/A:H")}), contract.C1C2)
        sc = scen["sens_low"]
        self.assertEqual((sc["vuln_id"], len(sc["findings"])), ("CVE-2099-0002", 2))
        self.assertEqual(sc["impact"].values, {"C": "H", "I": "N", "A": "H"})
        # b7c0435's floors over both rows too: integrity N in each
        self.assertEqual(sc["floors"], frozenset("I"))
        self.assertNotIn("status", sc)

    def test_one_cve_per_scenario(self):
        def two(doc):
            f = dict(doc["Results"][0]["Vulnerabilities"][0], VulnerabilityID="CVE-2099-0999")
            doc["Results"][0]["Vulnerabilities"].append(f)
            return doc
        with tempfile.TemporaryDirectory() as tmp:
            root = corpus_copy(tmp, {"reach_yes": two})
            with self.assertRaisesRegex(ValueError, "reach_yes: 2 CVEs in its report, a scenario holds one"):
                verdicts.load(root)


def published(sid, scen, replicate=1, change=None, status=None, declared=None):
    """One after run of a scenario as vens publishes it on GIVEN's answers; change(rating) alters what it publishes."""
    sc = scen[sid]
    levels = {f: lv for f, (lv, _) in contract.c1c2_levels(sc["dep"], sc["impact"], sc["described"], GIVEN).items()}
    vec = "/".join(f"{f}:{levels[f]}" for f in cdx.FACTORS)
    rating = dict(r.rating(vec), analysis=status)
    rating = change(rating) if change else rating
    given = {f: (GIVEN.get(f), "answer") for f in cdx.FACTORS}
    rec = r.record("after", sid, replicate, {sc["vuln_id"]: rating}, scenario=True,
                   answers={sc["vuln_id"]: r.factors(vec, **given)}, commit=s.C1C2_SHA)
    if declared is not None:
        rec["answers"]["per_cve"][sc["vuln_id"]]["declared"] = declared
    return rec


class TestTheRecomputation(unittest.TestCase):
    """chain/conform.py: every CVE of every after run against its frozen inputs and its own answers."""

    @classmethod
    def setUpClass(cls):
        cls.scen = verdicts.load(SCENARIOS, contract.C1C2)

    def problems(self, rec, sid):
        sc = self.scen[sid]
        return conform.run_problems(rec, sc["config"], {sc["vuln_id"]: sc["findings"]})

    def test_the_rating_the_levels_give(self):
        levels = {f: 5 for f in cdx.FACTORS}
        self.assertEqual(conform.rating(levels), (r.vector(), "medium", 25.0))
        low = dict(levels, SL=1, M=1, O=0, S=1, ED=1, EE=1, A=1, ID=1)
        self.assertEqual(conform.rating(low)[1:], ("low", 4.375))

    def test_runs_as_vens_publishes_them(self):
        for sid in ("reach_no", "reach_yes", "showcase_high_to_low", "disc_dos_novec"):
            self.assertEqual(self.problems(published(sid, self.scen), sid), [], sid)

    def test_every_difference(self):
        cases = (
            (published("reach_no", self.scen, status=STATUS), [f"{A}: the VEX publishes a status, not_affected"]),
            (published("reach_no", self.scen, declared={}), [f"{A}: answers.json holds a declared block"]),
            (published("reach_no", self.scen, change=lambda x: dict(x, score=1.0)), [f"{A}: score 1.0 not 55.3125"]),
            (published("reach_no", self.scen, change=lambda x: dict(x, severity="low")),
             [f"{A}: severity 'low' not 'critical'"]))
        for rec, want in cases:
            self.assertEqual(self.problems(rec, "reach_no"), want)
        off = published("reach_no", self.scen, change=lambda x: dict(
            x, levels={**x["levels"], "LC": 2, "O": 0}, vector=x["vector"].replace("LC:7", "LC:2")))
        (got,) = self.problems(off, "reach_no")
        self.assertTrue(got.startswith(f"{A}: O 0 not 7, LC 2 not 7, vector "), got)
        unrated = published("reach_yes", self.scen)
        unrated["answers"]["per_cve"][A]["unrated"] = True
        self.assertEqual(self.problems(unrated, "reach_yes"), [f"{A}: no rated answers.json entry"])


def cells_of(recs):
    return cellmod.group(recs)


class TestTheGate(unittest.TestCase):
    """Each after cell an implementation item, binding on every expected replicate; BD1 on every after run."""

    @classmethod
    def setUpClass(cls):
        cls.scen = verdicts.load(SCENARIOS, contract.C1C2)

    def read(self, recs, demo_root=None):
        return conform.read(cells_of(recs), self.scen, demo_root)

    def test_pass_fail_inconclusive(self):
        got = self.read([published("reach_no", self.scen, rep) for rep in (1, 2)]
                        + [published("reach_yes", self.scen, 1), published("reach_yes", self.scen, 2, status=STATUS)]
                        + [published("showcase_high_to_low", self.scen, 1),
                           r.record("after", "showcase_high_to_low", 2, {}, scenario=True, outcome="failed",
                                    commit=s.C1C2_SHA)])
        verdict = {k.unit: (c["verdict"], c["replicates"]) for k, c in got.items()}
        self.assertEqual(verdict, {"reach_no": ("pass", [1, 2]), "reach_yes": ("fail", [1, 2]),
                                   "showcase_high_to_low": ("inconclusive", [1, 2])})
        fails = conform.failures(got)
        self.assertEqual(len(fails), 2)
        self.assertIn("reach_yes: fail: r2 CVE-2099-0001: the VEX publishes a status, not_affected; r2 CVE-2099-0001 "
                      "holds a VEX status or a declared block", fails[0])
        self.assertIn("showcase_high_to_low: inconclusive: r2 without a complete run", fails[1])

    def test_a_run_the_reader_refused_fails(self):
        refused = published("reach_no", self.scen, status=STATUS)
        refused["scores_usable"] = False
        refused["answers"]["problems"] = [f"{A}: the VEX publishes a status, not_affected"]
        (c,) = self.read([refused]).values()
        self.assertEqual((c["verdict"], c["runs"]), ("fail", 0))
        self.assertIn("r1 refused by the reader", c["problems"][0])
        self.assertEqual(c["statuses"], [f"r1 {A}"])

    def test_a_scenario_outside_the_corpus_copy(self):
        (c,) = conform.read(cells_of([published("reach_no", self.scen)]), {}, None).values()
        self.assertEqual((c["verdict"], c["unread"]), ("inconclusive", "reach_no is not in the corpus copy"))

    def test_the_demo_scan_holds_no_status(self):
        recs = [r.record("after", "internal", rep, {A: dict(r.rating(s.VECTOR), analysis=STATUS if rep == 2 else None)},
                         answers={A: r.factors(s.VECTOR)}, commit=s.C1C2_SHA) for rep in (1, 2)]
        got = conform.read(cells_of(recs), None, None)
        (c,) = got.values()
        self.assertEqual((c["verdict"], c["runs"], c["cves"], c["statuses"]), ("fail", 2, 2, [f"r2 {A}"]))
        self.assertEqual(c["unread"], "the demo scan or its context not found: give --demo")
        (line,) = conform.failures(got)
        self.assertIn(f"r2 {A} holds a VEX status or a declared block; not recomputed, the demo scan", line)
        text = "\n".join(report_scen.c2_reads({"implementation": got, "gate": [line], "rules": contract.C1C2}))
        self.assertIn(": fail; 2 run(s) of 2 replicate(s), 2 CVE(s), 0 off their recomputation, 1 CVE(s) holding a "
                      "status or a declared block; not recomputed", text)
        self.assertIn("C1 + C2's implementation gate: 1 failure(s), no go.", text)

    def test_the_binding_line_before_the_families(self):
        got = self.read([published("reach_no", self.scen), published("reach_yes", self.scen, status=STATUS)])
        text = "\n".join(report_scen.families_section({"rows": [], "moves": {}, "rules": contract.C1C2,
                                                        "implementation": got}))
        self.assertIn("Implementation checks (plan Z0, every replicate; binding): 1 pass, 1 fail, 0 inconclusive",
                      text)
        self.assertIn("reach_yes: fail: r1 CVE-2099-0001: the VEX publishes a status, not_affected", text)


class TestThePinnedRules(unittest.TestCase):
    """ctx_analyze's --rules, never read off the runs; N's commit a parameter until it is known."""

    def rules(self, *argv):
        return ctx_analyze.pinned_rules(ctx_analyze.parse(list(argv) + ["dir"]))

    def test_from_the_option_or_the_commit(self):
        self.assertIsNone(self.rules())
        self.assertEqual(self.rules("--rules", "c1c2"), contract.C1C2)
        self.assertEqual(self.rules("--commit", f"after={s.REACH_SHA}"), contract.REACH_RULES)
        self.assertIsNone(self.rules("--commit", f"after={s.C1C2_SHA}"))
        self.assertEqual(self.rules("--rules", "c1c2", "--commit", f"after={'e' * 40}"), contract.C1C2)
        with self.assertRaisesRegex(ctx_analyze.InputError, "--rules c1c2, but --commit after= pins b7c0435"):
            self.rules("--rules", "c1c2", "--commit", f"after={s.AFTER_SHA}")


if __name__ == "__main__":
    unittest.main()
