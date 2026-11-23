"""C1 + C2's implementation gate and the review's fixes to the chain mirror, on synthetic inputs (no vens): Go's case
folding, a scenario's CVE taken over all its rows, a detail citing its entries in order, the executable witnesses,
showcase_med_to_high's severity a diagnostic, every run recomputed from its frozen inputs (chain/conform.py), the
demo scan holding no status, and the every-replicate reading that binds beside read5's eligibility rule.
tests/test_c1c2_mock.py runs the gate on vens 2de5d34's mock."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

import ctx_analyze
from chain import answers, cdx, conform, contract, families, report_scen, verdicts
from chain import cells as cellmod
from tests import records as r
from tests import support as s

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS = os.path.join(ROOT, "scenarios")
A = "CVE-2099-0001"
MODEL = f"c1 · openai/{s.MODEL}"
GIVEN = {"M": "possible_reward", "O": "some_access_or_resources_required", "EE": "difficult", "LAC": "unidentified",
         "FD": "bankruptcy", "RD": "minimal_damage", "PV": "hundreds"}
MED = "showcase_med_to_high publishes no not_affected"


class TestGoFolding(unittest.TestCase):
    """contract.fold_equal against Go's strings.EqualFold, through unicode.SimpleFold's orbits (chain/gofold.txt)."""

    def test_the_orbits_go_compares_by(self):
        cases = (("I", "ı", False), ("İ", "i", False), ("i", "I", True), ("k", "K", True), ("ſ", "S", True),
                 ("ß", "ẞ", True), ("Σ", "ς", True), ("libwidget", "LIBWIDGET", True), ("ab", "a", False))
        for a, b, equal in cases:
            self.assertEqual(contract.fold_equal(a, b), equal, (a, b))
        self.assertFalse(contract.hits({"cve": "", "component": "LIBWIDGET", "reachable": False}, A, ["libwıdget"]))

    def test_the_table_is_go_1_27s(self):
        with open(os.path.join(ROOT, "chain", "gofold.txt"), encoding="ascii") as fh:
            header, *orbits = fh.read().splitlines()
        self.assertEqual(header, "# unicode.SimpleFold orbits, go1.27.0, Unicode 17.0.0")
        self.assertEqual((len(orbits), len(contract.GO_ORBITS)), (1482, 2994))

    def test_go_writes_the_same_table(self):
        go = s.env("VB_GO")
        if go is None:
            self.skipTest("set VB_GO to the go binary vens 2de5d34 builds with (go1.27.0) to write the table again")
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "GOPROXY": "off", "GOTOOLCHAIN": "local", "GOCACHE": tmp, "GOFLAGS": ""}
            got = subprocess.run([go, "run", os.path.join(ROOT, "go", "gofold.go")], capture_output=True, check=True,
                                 env=env, cwd=tmp).stdout
        with open(os.path.join(ROOT, "chain", "gofold.txt"), "rb") as fh:
            self.assertEqual(got, fh.read())


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


def another_row(pkg, cia=None):
    """A report change adding a row of its one CVE in package pkg, its vector giving cia when given."""
    def change(doc):
        f = dict(doc["Results"][0]["Vulnerabilities"][0], PkgName=pkg)
        if cia:
            f["CVSS"] = {"redhat": {"V3Vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/{cia}"}}
        doc["Results"][0]["Vulnerabilities"].append(f)
        return doc
    return change


class TestTheScenariosCVE(unittest.TestCase):
    """verdicts.load takes a scenario's one CVE over all its rows."""

    def test_every_row_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            scen = verdicts.load(corpus_copy(tmp, {"showcase_high_to_low": another_row("log4j-api"),
                                                   "sens_low": another_row("libother", "C:H/I:N/A:H")}),
                                 contract.C1C2)
        sc = scen["showcase_high_to_low"]
        self.assertEqual((sc["vuln_id"], sc["packages"], len(sc["findings"])),
                         ("CVE-2021-44228", ["org.apache.logging.log4j:log4j-core", "log4j-api"], 2))
        # the component entry no longer covers every occurrence: nothing published
        self.assertEqual(sc["status"], ())
        self.assertEqual(scen["sens_low"]["impact"].values, {"C": "H", "I": "N", "A": "H"})
        # b7c0435's floors over both rows too: integrity N in each
        self.assertEqual(scen["sens_low"]["floors"], frozenset("I"))

    def test_one_cve_per_scenario(self):
        def two(doc):
            f = dict(doc["Results"][0]["Vulnerabilities"][0], VulnerabilityID="CVE-2099-0999")
            doc["Results"][0]["Vulnerabilities"].append(f)
            return doc
        with tempfile.TemporaryDirectory() as tmp:
            root = corpus_copy(tmp, {"reach_yes": two})
            with self.assertRaisesRegex(ValueError, "reach_yes: 2 CVEs in its report, a scenario holds one"):
                verdicts.load(root)


def cite(i, selector, provenance):
    return f"Declared not reachable by config.yaml reachability[{i}] ({selector}). Provenance: {provenance}"


class TestTheDetail(unittest.TestCase):
    """answers._declared_problems reads the detail's citations in order, a provenance holding line breaks."""

    def test_citations_in_order_whatever_the_lines(self):
        detail = cite(0, f"cve: {A}", "first\nsecond line") + "\n" + cite(2, "component: x", "third")
        ok = {"state": "not_affected", "justification": "code_not_reachable", "detail": detail}
        self.assertEqual(answers._declared_problems(A, {"unreachable": [0, 2], "analysis": ok}), [])
        backwards = dict(ok, detail=cite(2, "component: x", "third") + "\n" + cite(0, f"cve: {A}", "first"))
        self.assertEqual(answers._declared_problems(A, {"unreachable": [0, 2], "analysis": backwards}),
                         [f"{A}: a declared status that is not not_affected, code_not_reachable, citing each entry"])
        inline = dict(ok, detail=cite(0, f"cve: {A}", "p") + " " + cite(2, "component: x", "q"))
        self.assertTrue(answers._declared_problems(A, {"unreachable": [0, 2], "analysis": inline}))


class TestTheWitnesses(unittest.TestCase):
    """Executable witnesses: a frozen list, none by default, vetoing a declaration where they were run."""

    def test_the_list(self):
        self.assertEqual(contract.witnesses([]), [])
        got = contract.witnesses([{"where": "reach_no", "cve": f" {A} "}, {"where": "internal", "component": "x"}])
        self.assertEqual(got, [{"where": "reach_no", "cve": A}, {"where": "internal", "component": "x"}])
        self.assertEqual(contract.witnessed(got, "reach_no"), [{"where": "reach_no", "cve": A}])
        for bad in ({}, [{"cve": A}], [{"where": "x"}], [{"where": "x", "cve": A, "component": "y"}],
                    [{"where": "x", "cve": ""}], [{"where": "x", "cve": A, "reachable": True}], ["x"]):
            with self.assertRaises(ValueError, msg=bad):
                contract.witnesses(bad)

    def test_a_witness_vetoes_where_it_was_run(self):
        log4j = "org.apache.logging.log4j:log4j-core"
        mine = contract.witnesses([{"where": "reach_no", "cve": A},
                                   {"where": "showcase_high_to_low", "component": log4j}])
        scen = verdicts.load(SCENARIOS, contract.C1C2, mine)
        self.assertEqual((scen["reach_no"]["status"], scen["showcase_high_to_low"]["status"]), ((), ()))
        self.assertTrue(scen["reach2_no"]["status"])
        elsewhere = contract.witnesses([{"where": "reach2_no", "cve": A}])
        self.assertTrue(verdicts.load(SCENARIOS, contract.C1C2, elsewhere)["reach_no"]["status"])


class TestTheShowcase(unittest.TestCase):
    def test_med_to_high_severity_is_a_diagnostic_under_c1c2(self):
        (c1c2,) = [c for c in verdicts.CHECKS_C1C2 if c.label == "showcase_med_to_high high or critical"]
        (old,) = [c for c in verdicts.CHECKS if c.label == "showcase_med_to_high high or critical"]
        self.assertEqual((c1c2.kinds, old.kinds), (verdicts.BOTH(verdicts.DIAGNOSTIC), verdicts.BOTH(verdicts.CARRIED)))
        self.assertEqual((c1c2.target, c1c2.test), (old.target, old.test))


def published(sid, scen, status=None, change=None):
    """One after run of a scenario as vens 2de5d34 would publish it on GIVEN's answers, then change(levels)."""
    sc = scen[sid]
    levels = {f: lv for f, (lv, _) in contract.c1c2_levels(sc["dep"], sc["impact"], sc["described"], GIVEN).items()}
    if change:
        levels = change(levels)
    vec = "/".join(f"{f}:{levels[f]}" for f in cdx.FACTORS)
    given = {f: (GIVEN.get(f), "answer") for f in cdx.FACTORS}
    rec = r.record("after", sid, 1, {sc["vuln_id"]: dict(r.rating(vec), analysis=status)}, scenario=True,
                   answers={sc["vuln_id"]: r.factors(vec, **given)}, commit=s.C1C2_SHA)
    if status is not None:
        rec["answers"]["per_cve"][sc["vuln_id"]]["declared"] = {"unreachable": [0], "analysis": status}
    return rec


def status_of(scen, sid):
    return dict(zip(("state", "justification", "detail"), scen[sid]["status"]))


NONE_HIT = {"unreachable": [], "reachable": [], "unresolved": []}


class TestTheRecomputation(unittest.TestCase):
    """chain/conform.py: every CVE of every after run against its frozen inputs and its own answers."""

    @classmethod
    def setUpClass(cls):
        cls.scen = verdicts.load(SCENARIOS, contract.C1C2)

    def problems(self, rec, sid, witnesses=()):
        sc = self.scen[sid]
        return conform.run_problems(rec, sc["config"], {sc["vuln_id"]: sc["findings"]}, witnesses)

    def test_runs_as_vens_publishes_them(self):
        rec = published("reach_no", self.scen, status_of(self.scen, "reach_no"))
        self.assertEqual(self.problems(rec, "reach_no"), [])
        self.assertEqual(self.problems(published("reach_yes", self.scen), "reach_yes"), [])

    def test_every_difference(self):
        declared = status_of(self.scen, "reach_no")
        hit = dict(NONE_HIT, unreachable=[0])
        cases = (
            (published("reach_yes", self.scen, declared), "reach_yes",
             [f"{A}: VEX status not_affected, the config declares none",
              f"{A}: declared entries {hit}, the config's hit {NONE_HIT}"]),
            (published("reach_no", self.scen), "reach_no",
             [f"{A}: VEX status none, the config declares not_affected",
              f"{A}: declared entries {NONE_HIT}, the config's hit {hit}"]),
            (published("reach_no", self.scen, dict(declared, detail=declared["detail"] + " (edited)")), "reach_no",
             [f"{A}: VEX status not_affected, the config declares not_affected, its detail off the entries"]),
            (published("reach_no", self.scen, declared, lambda lv: dict(lv, LC=2, O=0)), "reach_no",
             [f"{A}: O 0 not 7, LC 2 not 7"]))
        for rec, sid, want in cases:
            self.assertEqual(self.problems(rec, sid), want, sid)
        unrated = published("reach_yes", self.scen)
        unrated["answers"]["per_cve"][A]["unrated"] = True
        self.assertEqual(self.problems(unrated, "reach_yes"), [f"{A}: no rated answers.json entry"])

    def test_a_witness_turns_a_publication_into_a_failure(self):
        rec = published("reach_no", self.scen, status_of(self.scen, "reach_no"))
        self.assertEqual(self.problems(rec, "reach_no", [{"where": "reach_no", "cve": A}]),
                         [f"{A}: VEX status not_affected, the config declares none"])

    def test_every_scenario_run_read(self):
        recs = [published("reach_no", self.scen, status_of(self.scen, "reach_no")), published("reach_yes", self.scen)]
        got = conform.read(cellmod.group(recs), self.scen, None)
        self.assertEqual(sorted((k.unit, c["runs"], c["problems"], c["unread"]) for k, c in got.items()),
                         [("reach_no", 1, [], None), ("reach_yes", 1, [], None)])
        self.assertEqual(conform.read(cellmod.group(recs), {}, None)[next(iter(cellmod.group(recs)))]["unread"],
                         "reach_no is not in the corpus copy")

    def test_the_demo_scan_holds_no_status(self):
        st = {"state": "not_affected", "justification": "code_not_reachable", "detail": "x"}
        recs = [r.record("after", "internal", rep, {A: dict(r.rating(s.VECTOR), analysis=st if rep == 2 else None)},
                         answers={A: r.factors(s.VECTOR)}, commit=s.C1C2_SHA) for rep in (1, 2)]
        got = conform.read(cellmod.group(recs), None, None)
        (c,) = got.values()
        self.assertEqual((c["runs"], c["cves"], c["statuses"]), (2, 2, [f"r2 {A}"]))
        self.assertEqual(c["unread"], "the demo scan or its context not found: give --demo")
        fails = conform.failures([], got)
        self.assertEqual(len(fails), 2)
        self.assertIn(f"r2 {A} holds a VEX status or a declared block on the demo scan", fails[0])
        self.assertIn("not recomputed, the demo scan or its context not found: give --demo", fails[1])
        text = "\n".join(report_scen.c2_reads({"implementation": got, "gate": fails, "rules": contract.C1C2}))
        self.assertIn("2 run(s), 2 CVE(s), 0 off their recomputation; 1 CVE(s) holding a status; not recomputed", text)
        self.assertIn("C1 + C2's implementation gate: 2 failure(s), no go.", text)


def impl_row(label, item, oks, missing=(), model=MODEL, arm="after"):
    c = next(c for c in verdicts.CHECKS_C1C2 if c.label == label)
    per = [{"replicate": i + 1, "ok": ok, "a": (), "b": (), "value": ()} for i, ok in enumerate(oks)]
    return {"check": c, "arm": arm, "kind": c.kind(arm), "model": model, "rules": contract.C1C2, "certified": True,
            "vectorless": False, "row": {"item": item, "per": per, "missing": list(missing), "median": (None, None)}}


class TestTheBinding(unittest.TestCase):
    """Plan Z0's every-replicate reading binds every implementation check, read5's eligibility printed beside."""

    def rows(self):
        return [impl_row(verdicts.REACH_STATUS, ("reach_no", "reach_yes"), [True, False, True]),
                impl_row(verdicts.REACH_STATUS, ("reach2_no", "reach2_yes"), [True, True], missing=[3]),
                impl_row(MED, "showcase_med_to_high", [True] * 3),
                impl_row(MED, "showcase_med_to_high", [True] * 3, arm="before")]

    def test_fail_inconclusive_and_missing_stop_a_go(self):
        fails = conform.failures(self.rows(), {})
        self.assertIn(f"{verdicts.REACH_STATUS} · reach_no / reach_yes · {MODEL}: fail", fails)
        self.assertIn(f"{verdicts.REACH_STATUS} · reach2_no / reach2_yes · {MODEL}: inconclusive", fails)
        self.assertIn(f"{verdicts.REACH_STATUS} · reach3_no / reach3_yes · {MODEL}: missing", fails)
        self.assertIn(f"{verdicts.SHOWCASE_STATUS[0].label} · showcase_high_to_low · {MODEL}: missing", fails)
        self.assertEqual(len(fails), 5)
        self.assertEqual(conform.failures([], {}), [])

    def test_the_report_prints_the_binding_reading(self):
        text = "\n".join(report_scen.families_section({"rows": self.rows(), "moves": {}}))
        self.assertIn("Implementation checks (plan Z0, every replicate; binding): 1 pass, 1 fail, 1 inconclusive",
                      text)
        self.assertIn(f"- {verdicts.REACH_STATUS} · reach_no / reach_yes · {MODEL}: fail", text)
        self.assertIn(f"- {verdicts.REACH_STATUS} · reach3_no / reach3_yes · {MODEL}: missing", text)
        self.assertIn(f"{MED} · showcase_med_to_high · {MODEL}: the before passes 1.00, the after fails 0.00: pass; "
                      f"read5's eligibility, printed beside; the every-replicate reading binds: pass.", text)

    def test_one_failing_replicate_read5_calls_weakened_binds_as_fail(self):
        rows = [impl_row(MED, "showcase_med_to_high", [True, True, False]),
                impl_row(MED, "showcase_med_to_high", [True] * 3, arm="before")]
        self.assertEqual(families.gates(rows)[("showcases", MED, "showcase_med_to_high", MODEL)][2], "weakened")
        self.assertIn(f"{MED} · showcase_med_to_high · {MODEL}: fail", conform.failures(rows, {}))


class TestThePinnedRules(unittest.TestCase):
    """ctx_analyze's --rules, never read off the runs."""

    def rules(self, *argv):
        return ctx_analyze.pinned_rules(ctx_analyze.parse(list(argv) + ["dir"]))

    def test_from_the_option_or_the_commit(self):
        self.assertEqual(self.rules(), contract.B7C0435)
        self.assertEqual(self.rules("--rules", "c1c2"), contract.C1C2)
        self.assertEqual(self.rules("--commit", f"after={s.C1C2_SHA}"), contract.C1C2)
        self.assertEqual(self.rules("--commit", f"after={s.REACH_SHA}"), contract.REACH_RULES)
        self.assertEqual(self.rules("--rules", "c1c2", "--commit", f"after={'e' * 40}"), contract.C1C2)
        with self.assertRaisesRegex(ctx_analyze.InputError, "--rules c1c2, but --commit after= pins b7c0435"):
            self.rules("--rules", "c1c2", "--commit", f"after={s.AFTER_SHA}")


if __name__ == "__main__":
    unittest.main()
