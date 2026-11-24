"""c1c2b, the rating-policy fix (decisions.md 24/11/2026) as the chain mirrors vens 310-policy at the policy commit
(contract.POLICY_COMMIT): C1 + C2''s levels and marker, Skill level from source worst_case, the severity and score read
on one impact, the business impact when the config declares data_subjects, the technical impact otherwise, published
as vens:impact-basis. On synthetic inputs: the pin, the basis rule, chain/conform.py's recomputation on the published
basis and its refusals, answers.json read under c1c2b, and the readers a c1c2b record passes through (cdx, demo,
diagnostics). c1c2 and c1c2p read as before.

With VB_VENS_POLICY, a vens binary built at the policy commit, vens's own mock on every scenario, as written and with
data_subjects taken out of its config: every run recomputed by conform under c1c2b, business on the corpus as written,
technical without data_subjects; with VB_VENS_MARKER beside it, the marker commit's runs give the same vectors, answers
and marker, Skill level's source aside, and the policy commit's rating is the marker commit's levels read on the impact
the basis names."""
import os
import shutil
import tempfile
import unittest
from fractions import Fraction

import yaml

from chain import answers, attempt, cdx, conform, contract, demo, diagnostics, runvens, verdicts
from chain import cells as cellmod
from tests import records as r
from tests import support as s
from tests.test_c1c2 import DEP, SCENARIOS, c1c2_entry, doc, load
from tests.test_c1c2_gate import GIVEN

POLICY, MARKER = contract.POLICY_COMMIT, contract.MARKER_COMMIT
BASIS, PROVENANCE, CVSS_V3 = "vens:impact-basis", "vens:impact-provenance", "cvss-v3"
IDS = sorted(d for d in os.listdir(SCENARIOS) if os.path.isdir(os.path.join(SCENARIOS, d)))
BANDS = ("none", "one_individual", "hundreds", "thousands", "millions")
# OWASP's worked example's averages, likelihood 4.375, technical 7.25, business 2.25, on calculator levels.
EXAMPLE = "SL:5/M:1/O:7/S:2/ED:3/EE:5/A:9/ID:3/LC:6/LI:7/LAV:7/LAC:9/FD:1/RD:1/NC:2/PV:5"


def published(sid, scen, basis=("business",), commit=POLICY, provenance=(CVSS_V3,), rate_on="business"):
    """One after run of a scenario as the policy commit publishes it on GIVEN's answers: the rating on rate_on's impact
    (None: max(T, B)), at commit, its VEX carrying the basis and provenance values given."""
    sc = scen[sid]
    got = contract.c1c2_levels(sc["dep"], sc["impact"], sc["described"], GIVEN, rules=contract.C1C2B)
    vec = "/".join(f"{f}:{got[f][0]}" for f in cdx.FACTORS)
    _, severity, score = conform.rating(cdx.levels(vec), rate_on)
    rating = dict(r.rating(vec, score=score, severity=severity), provenance=list(provenance), basis=list(basis))
    given = {f: (GIVEN.get(f), "answer") for f in cdx.FACTORS}
    rec = r.record("after", sid, 1, {sc["vuln_id"]: rating}, scenario=True,
                   answers={sc["vuln_id"]: r.factors(vec, **given)}, commit=commit)
    rec["answers"]["per_cve"][sc["vuln_id"]]["counters"] = contract.c1c2_counters(sc["dep"], sc["impact"],
                                                                                    contract.C1C2B)
    return rec


def without_subjects(root, sids):
    """The scenarios under root with data_subjects taken out of each sid's config."""
    for sid in sids:
        path = os.path.join(root, sid, "config.yaml")
        with open(path, encoding="utf-8") as fh:
            config = yaml.safe_load(fh)
        config["context"].pop("data_subjects", None)
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(config, fh, sort_keys=False)
    return root


class TestThePin(unittest.TestCase):
    """The policy commit pins c1c2b, whose levels are C1 + C2''s and whose records show what C1 + C2''s show."""

    def test_the_contract(self):
        self.assertEqual((len(POLICY), contract.CONTRACTS[POLICY]), (40, contract.C1C2B))
        self.assertEqual(attempt.pinned_contract({"arm": "after", "vens_commit": POLICY}), contract.C1C2B)
        self.assertIn(contract.C1C2B, contract.C1C2_RULES)
        self.assertEqual(contract.C2P_RULES, (contract.C1C2P, contract.C1C2B, contract.C1C2R))
        self.assertEqual(contract.accepted(contract.C1C2B), {contract.C1C2, contract.C1C2P})
        self.assertEqual(contract.accepted(contract.C1C2P), {contract.C1C2, contract.C1C2P})
        self.assertEqual(contract.accepted(contract.C1C2), {contract.C1C2})
        # the marker commit and its ancestors keep c1c2p; the policy commit alone writes the basis
        self.assertEqual(contract.CONTRACTS[MARKER], contract.C1C2P)
        self.assertEqual([contract.basis_commit(x) for x in (POLICY, MARKER, contract.C2P_COMMIT, None)],
                         [True, False, False, False])
        self.assertEqual([contract.marker_commit(x) for x in (POLICY, MARKER, contract.C2P_COMMIT)], [True, True, False])

    def test_the_levels_are_c2ps_skill_level_worst_case(self):
        scen = verdicts.load(SCENARIOS, contract.C1C2B)
        for sid, sc in scen.items():
            b = contract.c1c2_levels(sc["dep"], sc["impact"], sc["described"], GIVEN, rules=contract.C1C2B)
            p = contract.c1c2_levels(sc["dep"], sc["impact"], sc["described"], GIVEN, rules=contract.C1C2P)
            self.assertEqual((b["SL"], p["SL"]), ((9, "worst_case"), (9, "constant")), sid)
            self.assertEqual({f: x for f, x in b.items() if f != "SL"}, {f: x for f, x in p.items() if f != "SL"}, sid)
            self.assertEqual(contract.c1c2_counters(sc["dep"], sc["impact"], contract.C1C2B),
                             contract.c1c2_counters(sc["dep"], sc["impact"], contract.C1C2P), sid)
        low = dict(DEP, availability_requirement="low")
        vectored = contract.impact([("nvd", "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L")])
        self.assertEqual([contract.impact_level("LAV", low, vectored, x) for x in contract.C1C2_RULES], [5, 1, 1, 1])
        self.assertEqual(contract.impact_level("LAV", DEP, contract.NO_IMPACT_READ, contract.C1C2B), 9)
        self.assertEqual(contract.c1c2_source("SL", DEP, vectored), "constant")


class TestTheBasisRule(unittest.TestCase):
    """Business iff the config declares data_subjects, any band, none included; technical otherwise."""

    def test_by_data_subjects(self):
        for band in BANDS:
            self.assertEqual(contract.impact_basis(dict(DEP, data_subjects=band)), "business", band)
        self.assertEqual(contract.impact_basis(dict(DEP, data_subjects=None)), "technical")
        self.assertEqual(contract.impact_basis({k: v for k, v in DEP.items() if k != "data_subjects"}), "technical")

    def test_from_the_config(self):
        ctx = {"exposure": "internet", "data_sensitivity": "low", "business_criticality": "low"}
        self.assertEqual(contract.impact_basis(contract.deployment({"context": ctx})), "technical")
        for value, want in (("none", "business"), ("millions", "business"), (None, "technical")):
            got = contract.deployment({"context": dict(ctx, data_subjects=value)})
            self.assertEqual(contract.impact_basis(got), want, value)
        # a declared framework list, empty or not, does not set it
        for frameworks in ([], ["gdpr"]):
            got = contract.deployment({"context": dict(ctx, compliance_requirements=frameworks)})
            self.assertEqual(contract.impact_basis(got), "technical", frameworks)


class TestTheRating(unittest.TestCase):
    """conform.rating on one impact: OWASP's worked example, the impact edges, max(T, B) where no basis is given."""

    def test_each_impact(self):
        lv = cdx.levels(EXAMPLE)
        self.assertEqual(conform.rating(lv, "business")[1:], ("low", 9.84375))
        self.assertEqual(conform.rating(lv, "technical")[1:], ("high", 31.71875))
        self.assertEqual(conform.rating(lv)[1:], ("high", 31.71875))
        # B above T: max(T, B) reads B
        lv = cdx.levels("SL:9/M:1/O:0/S:4/ED:9/EE:1/A:9/ID:1/LC:2/LI:1/LAV:1/LAC:1/FD:9/RD:9/NC:7/PV:9")
        self.assertEqual(conform.rating(lv, "technical")[1:], ("low", float(Fraction(34, 8) * Fraction(5, 4))))
        self.assertEqual(conform.rating(lv, "business")[1:], ("high", float(Fraction(34, 8) * Fraction(34, 4))))
        self.assertEqual(conform.rating(lv), conform.rating(lv, "business"))
        with self.assertRaises(KeyError):
            conform.rating(lv, "both")

    def test_the_impact_edges(self):
        # L 6.0, HIGH; B 2.75, 3.0, 5.75, 6.0
        for b, band in (((1, 1, 2, 7), "medium"), ((3, 4, 2, 3), "high"), ((7, 4, 5, 7), "high"),
                        ((7, 5, 5, 7), "critical")):
            vec = "SL:9/M:1/O:7/S:9/ED:9/EE:3/A:9/ID:1/LC:2/LI:1/LAV:1/LAC:1/" + "/".join(
                f"{f}:{x}" for f, x in zip(("FD", "RD", "NC", "PV"), b))
            _, severity, score = conform.rating(cdx.levels(vec), "business")
            self.assertEqual((severity, score), (band, float(Fraction(48, 8) * Fraction(sum(b), 4))), b)


class TestTheGate(unittest.TestCase):
    """chain/conform.py under c1c2b: the rating recomputed on the published basis, the basis the config's, one per
    CVE, the marker required as at the marker commit; any other commit writes no basis."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = os.path.join(cls.tmp.name, "scenarios")
        shutil.copytree(SCENARIOS, root)
        without_subjects(root, ("reach_no",))
        cls.scen = verdicts.load(root, contract.C1C2B)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def problems(self, rec, sid, rules=contract.C1C2B):
        sc = self.scen[sid]
        return conform.run_problems(rec, sc["config"], {sc["vuln_id"]: sc["findings"]}, rules)

    def test_a_run_on_its_basis_passes(self):
        self.assertEqual(contract.impact_basis(self.scen["reach_yes"]["dep"]), "business")
        self.assertEqual(contract.impact_basis(self.scen["reach_no"]["dep"]), "technical")
        self.assertEqual(self.problems(published("reach_yes", self.scen), "reach_yes"), [])
        rec = published("reach_no", self.scen, basis=("technical",), rate_on="technical")
        self.assertEqual(self.problems(rec, "reach_no"), [])
        cells = conform.read(cellmod.group([published("reach_yes", self.scen)]), self.scen, None, contract.C1C2B)
        self.assertEqual([c["verdict"] for c in cells.values()], ["pass"])

    def test_the_rating_on_another_impact_fails(self):
        sc = self.scen["reach_yes"]
        vid = sc["vuln_id"]
        got = contract.c1c2_levels(sc["dep"], sc["impact"], sc["described"], GIVEN, rules=contract.C1C2B)
        lv = {f: x[0] for f, x in got.items()}
        _, t_sev, t_score = conform.rating(lv, "technical")
        _, b_sev, b_score = conform.rating(lv, "business")
        self.assertNotEqual((t_sev, t_score), (b_sev, b_score))
        rec = published("reach_yes", self.scen, rate_on="technical")
        self.assertEqual(self.problems(rec, "reach_yes"),
                         [f"{vid}: severity {t_sev!r} not {b_sev!r}, score {t_score!r} not {b_score!r}"])
        # max(T, B), the marker commit's rating, fails where it is not B
        self.assertEqual(len(self.problems(published("reach_yes", self.scen, rate_on=None), "reach_yes")), 1)

    def test_the_basis_refusals(self):
        vid = self.scen["reach_yes"]["vuln_id"]
        cases = (((), f"{vid}: 0 {BASIS} properties, not one"),
                 (("business", "business"), f"{vid}: 2 {BASIS} properties, not one"),
                 (("both",), f"{vid}: {BASIS} 'both' is not technical or business"))
        for basis, want in cases:
            self.assertEqual(self.problems(published("reach_yes", self.scen, basis=basis), "reach_yes"), [want],
                             basis)
        # on the record's own basis the rating recomputes; the basis off its config refuses it
        rec = published("reach_yes", self.scen, basis=("technical",), rate_on="technical")
        self.assertEqual(self.problems(rec, "reach_yes"), [f"{vid}: {BASIS} 'technical', its config gives 'business'"])
        nvid = self.scen["reach_no"]["vuln_id"]
        rec = published("reach_no", self.scen, basis=("business",), rate_on="business")
        self.assertEqual(self.problems(rec, "reach_no"), [f"{nvid}: {BASIS} 'business', its config gives 'technical'"])

    def test_the_marker_is_required(self):
        vid = self.scen["reach_yes"]["vuln_id"]
        rec = published("reach_yes", self.scen, provenance=())
        self.assertEqual(self.problems(rec, "reach_yes"), [f"{vid}: 0 {PROVENANCE} properties, not one"])

    def test_other_commits_write_no_basis(self):
        vid = self.scen["reach_yes"]["vuln_id"]
        rec = published("reach_yes", self.scen, commit=MARKER, rate_on=None)
        self.assertEqual(self.problems(rec, "reach_yes", contract.C1C2P),
                         [f"{vid}: {BASIS} published, vens {MARKER[:12]} writes no basis"])
        # c1c2p reads as before: max(T, B), no basis
        rec = published("reach_yes", self.scen, commit=MARKER, rate_on=None, basis=())
        self.assertEqual(self.problems(rec, "reach_yes", contract.C1C2P), [])
        rec = published("reach_yes", self.scen, commit=MARKER, rate_on="business", basis=())
        self.assertEqual(len(self.problems(rec, "reach_yes", contract.C1C2P)), 1)


class TestTheAnswers(unittest.TestCase):
    """answers.json pinned to c1c2b: what C1 + C2' and C1 + C2 show is accepted, C2''s column and counter read."""

    def test_validate(self):
        shown_c2p = doc(c1c2_entry(counters=("availability_requirement_missing",)))
        shown_c2 = doc(c1c2_entry())
        for d in (shown_c2p, shown_c2):
            self.assertEqual(answers.validate(load(d), contract.C1C2B), [])
        self.assertEqual(answers.validate(load(shown_c2p), contract.C1C2),
                         ["answers.json follows c1c2p, not the pinned c1c2"])


class TestTheReaders(unittest.TestCase):
    """cdx reads the property; demo's own rule and the null model's after read the published or configured basis."""

    def test_cdx_reads_the_basis(self):
        a, b = "CVE-2099-0001", "CVE-2099-0002"
        vex = s.vex([(a, s.VECTOR, s.SEVERITY, s.SCORE), (b, s.VECTOR, s.SEVERITY, s.SCORE)])
        vex["vulnerabilities"][0]["properties"] = [{"name": PROVENANCE, "value": CVSS_V3},
                                                   {"name": BASIS, "value": "business"}]
        with tempfile.TemporaryDirectory() as tmp:
            got, problems = cdx.ratings(s.write(os.path.join(tmp, "vex.json"), vex))
        self.assertEqual(problems, [])
        self.assertEqual({vid: (x["provenance"], x["basis"]) for vid, x in got.items()},
                         {a: ([CVSS_V3], ["business"]), b: ([], [])})

    def test_own_rule(self):
        rating = r.rating(EXAMPLE)
        lik = Fraction(35, 8)
        self.assertEqual(demo.own_rule(rating, "after"), (lik * Fraction(29, 4), "high"))
        self.assertEqual(demo.own_rule(dict(rating, basis=["business"]), "after"), (lik * Fraction(9, 4), "low"))
        self.assertEqual(demo.own_rule(dict(rating, basis=["technical"]), "after"), (lik * Fraction(29, 4), "high"))
        # two values, or another, read as no basis: max(T, B)
        for basis in (["business", "business"], ["both"], []):
            self.assertEqual(demo.own_rule(dict(rating, basis=basis), "after")[1], "high", basis)

    def test_the_null_model(self):
        null = {"threat_agent": 4, "vulnerability": 5, "technical_impact": 7, "business_impact": 2}
        self.assertEqual(diagnostics.null_rules(null)["after"], (Fraction(9, 2) * 7, "high"))
        self.assertEqual(diagnostics.null_rules(null, "technical")["after"], (Fraction(9, 2) * 7, "high"))
        self.assertEqual(diagnostics.null_rules(null, "business")["after"], (Fraction(9, 2) * 2, "low"))
        self.assertEqual(diagnostics.null_rules(null, "business")["before"], diagnostics.null_rules(null)["before"])
        scen = {"a": {"null": null, "dep": dict(DEP)}, "b": {"null": null, "dep": dict(DEP, data_subjects=None)}}
        for rules, want in ((contract.C1C2B, {"a": "low", "b": "high"}), (contract.C1C2P, {"a": "high", "b": "high"})):
            got = {row["scenario"]: row["rules"]["after"][1] for row in diagnostics.null_table({}, scen, None, rules)}
            self.assertEqual(got, want, rules)


class TestTheMock(unittest.TestCase):
    """vens's mock at the policy commit (VB_VENS_POLICY) on every scenario, as written (business) and without
    data_subjects (technical): every run passes conform under c1c2b keyed on the policy commit, and fails it keyed on
    the marker commit; beside the marker commit's binary (VB_VENS_MARKER): the same vectors and markers, answers.json
    the same but Skill level's source, and the rating the marker commit's levels give on the basis's impact."""

    @classmethod
    def setUpClass(cls):
        cls.binary = s.env("VB_VENS_POLICY")
        if cls.binary is None:
            raise unittest.SkipTest("set VB_VENS_POLICY to a vens binary built from 310-policy at the policy commit")
        cls.marker = s.env("VB_VENS_MARKER")
        cls.tmp = tempfile.TemporaryDirectory()
        plain = shutil.copytree(SCENARIOS, os.path.join(cls.tmp.name, "plain"))
        technical = without_subjects(shutil.copytree(SCENARIOS, os.path.join(cls.tmp.name, "technical")), IDS)
        cls.runs = {}
        for tag, root, binary in (("business", plain, cls.binary), ("technical", technical, cls.binary),
                                  ("marker", plain, cls.marker)):
            for sid in IDS if binary else ():
                folder = os.path.join(cls.tmp.name, "runs", tag, sid)
                rec = runvens.generate(binary, os.path.join(root, sid, "config.yaml"),
                                       os.path.join(root, sid, "report.json"), folder, record={"arm": "after"})
                cls.runs[(tag, sid)] = (folder, rec["generate"]["exit_status"])
        cls.scen = {"business": verdicts.load(plain, contract.C1C2B),
                    "technical": verdicts.load(technical, contract.C1C2B)}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def record(self, tag, sid, commit=POLICY, rules=contract.C1C2B):
        folder, code = self.runs[(tag, sid)]
        self.assertEqual(code, 0, (tag, sid))
        rec = attempt.read_attempt(folder, rules=rules)
        self.assertEqual((rec["scores_usable"], rec["problems"], rec["answers"]["problems"]), (True, [], []), sid)
        return {**rec, "what": {**rec["what"], "vens_commit": commit}}

    def test_every_run_recomputes_on_its_basis(self):
        for tag in ("business", "technical"):
            for sid in IDS:
                sc = self.scen[tag][sid]
                cves = {sc["vuln_id"]: sc["findings"]}
                rec = self.record(tag, sid)
                (rating,) = rec["ratings"].values()
                self.assertEqual(rating["basis"], [tag], (tag, sid))
                self.assertEqual(conform.run_problems(rec, sc["config"], cves, contract.C1C2B), [], (tag, sid))
                off = conform.run_problems({**rec, "what": {**rec["what"], "vens_commit": MARKER}}, sc["config"], cves,
                                           contract.C1C2B)
                self.assertIn(f"{sc['vuln_id']}: {BASIS} published, vens {MARKER[:12]} writes no basis", off)
                self.assertEqual(rec["answers"]["per_cve"][sc["vuln_id"]]["factors"]["SL"]["source"], "worst_case",
                                 (tag, sid))

    def test_beside_the_marker_commit(self):
        if self.marker is None:
            self.skipTest("set VB_VENS_MARKER to compare with the marker commit's mock")
        strip = lambda fs: {f: {k: v for k, v in x.items() if not (f == "SL" and k == "source")} for f, x in fs.items()}
        for sid in IDS:
            ours, theirs = self.record("business", sid), self.record("marker", sid, MARKER, contract.C1C2P)
            (vid, o), (_, t) = next(iter(ours["ratings"].items())), next(iter(theirs["ratings"].items()))
            self.assertEqual((o["vector"], o["provenance"], t["basis"]), (t["vector"], t["provenance"], []), sid)
            self.assertEqual((o["severity"], o["score"]), conform.rating(t["levels"], "business")[1:], sid)
            self.assertEqual((t["severity"], t["score"]), conform.rating(t["levels"])[1:], sid)
            self.assertEqual(strip(ours["answers"]["per_cve"][vid]["factors"]),
                             strip(theirs["answers"]["per_cve"][vid]["factors"]), sid)


if __name__ == "__main__":
    unittest.main()
