"""c1c2r, the repair (decisions.md 24/11/2026, Financial damage and Reputation damage set by Go from the declared
business criticality) as the chain mirrors vens 310-policy at the repair commit (contract.REPAIR_COMMIT): c1c2b's rules,
but Financial damage and Reputation damage are no longer asked: each is the config's business_criticality's declaration
at t, OWASP's band of max(LC, LI, LAV), on the decided table, source criticality; the VEX metadata carries one
vens:rating-policy, 2. On synthetic inputs: the pin, the table over its 1,792 cells against one re-typed here, the
levels, chain/conform.py's recomputation and its refusals (the review's M1 under c1c2b and c1c2r), answers.json read
under c1c2r, cdx's rating policy, the null model. c1c2, c1c2p and c1c2b read as before.

With VB_VENS_REPAIR, a vens binary built at the repair commit, vens's own mock on every scenario, as written and with
data_subjects taken out of its config: every run recomputed by conform under c1c2r, Financial and Reputation damage the
table's, the rating policy 2; read under c1c2b the same runs fail where the table sets a level below cannot_tell's 9;
with VB_VENS_POLICY beside it, the policy commit's runs give the same levels but those two, and no rating policy."""
import itertools
import os
import shutil
import tempfile
import unittest
from fractions import Fraction

from chain import answers, attempt, cdx, conform, contract, diagnostics, runvens, verdicts
from chain import cells as cellmod
from tests import records as r
from tests import support as s
from tests.test_c1c2 import DEP, SCENARIOS, c1c2_entry, doc, v31
from tests.test_c1c2_gate import GIVEN
from tests.test_c1c2b import without_subjects

REPAIR, POLICY, MARKER = contract.REPAIR_COMMIT, contract.POLICY_COMMIT, contract.MARKER_COMMIT
BASIS, PROVENANCE, RATING_POLICY, CVSS_V3 = "vens:impact-basis", "vens:impact-provenance", "vens:rating-policy", \
    "cvss-v3"
IDS = sorted(d for d in os.listdir(SCENARIOS) if os.path.isdir(os.path.join(SCENARIOS, d)))
FOUR = ("low", "medium", "high", "critical")
# The decided table, re-typed from decisions.md 24/11/2026: (FD, RD), each at t low, medium and high.
TABLE = {"low": ((1, 1, 1), (1, 1, 1)), "medium": ((1, 1, 3), (1, 1, 4)), "high": ((1, 3, 7), (1, 4, 5)),
         "critical": ((3, 7, 9), (4, 5, 9))}
# C2' re-typed: LC by C on non-sensitive then critical data, LI by I, LAV by A on secondary then primary services.
LC, LI, LAV = {"N": (2, 2), "L": (2, 6), "H": (6, 7)}, {"N": 1, "L": 3, "H": 7}, {"N": (1, 1), "L": (1, 5), "H": (5, 7)}
CIAS = [None] + ["".join(x) for x in itertools.product("NLH", repeat=3)]
CELLS = list(itertools.product(FOUR, FOUR, FOUR, CIAS))


def cell(crit, sens, avail, cia):
    """(dep, impact) of one cell, cia None for no usable v3 vector."""
    dep = dict(DEP, business_criticality=crit, data_sensitivity=sens, availability_requirement=avail)
    imp = contract.NO_IMPACT_READ if cia is None else contract.impact([v31(f"C:{cia[0]}/I:{cia[1]}/A:{cia[2]}")])
    return dep, imp


def want(crit, sens, avail, cia):
    """(FD, RD) the re-typed tables give a cell: t high without a vector, whose three impacts are 9."""
    if cia is None:
        t = 2
    else:
        worst = max(LC[cia[0]][sens in ("high", "critical")], LI[cia[1]], LAV[cia[2]][avail in ("high", "critical")])
        t = 0 if worst < 3 else 1 if worst < 6 else 2
    return TABLE[crit][0][t], TABLE[crit][1][t]


def published(sid, scen, basis=("business",), commit=REPAIR, provenance=(CVSS_V3,), rate_on="business",
              policy=("2",), levels=None):
    """One after run of a scenario as the repair commit publishes it on GIVEN's answers (Financial and Reputation
    damage not asked): the rating on rate_on's impact, at commit, its VEX carrying the basis, provenance and rating
    policy given (None: metadata unread); levels, {factor: level} in place of the rules' where given."""
    sc = scen[sid]
    got = contract.c1c2_levels(sc["dep"], sc["impact"], sc["described"], GIVEN, rules=contract.C1C2R)
    lv = {f: x[0] for f, x in got.items()}
    lv.update(levels or {})
    vec = "/".join(f"{f}:{lv[f]}" for f in cdx.FACTORS)
    _, severity, score = conform.rating(cdx.levels(vec), rate_on)
    rating = dict(r.rating(vec, score=score, severity=severity), provenance=list(provenance), basis=list(basis),
                  policy=None if policy is None else list(policy))
    given = {f: (GIVEN.get(f), "answer") for f in cdx.FACTORS}
    given.update({f: (None, contract.CRITICALITY_SOURCE) for f in contract.DECLARED})
    rec = r.record("after", sid, 1, {sc["vuln_id"]: rating}, scenario=True,
                   answers={sc["vuln_id"]: r.factors(vec, **given)}, commit=commit)
    rec["answers"]["per_cve"][sc["vuln_id"]]["counters"] = contract.c1c2_counters(sc["dep"], sc["impact"],
                                                                                    contract.C1C2R)
    return rec


class TestThePin(unittest.TestCase):
    """The repair commit pins c1c2r; the policy commit keeps c1c2b; both write the basis and the marker."""

    def test_the_contract(self):
        self.assertEqual((len(REPAIR), contract.CONTRACTS[REPAIR]), (40, contract.C1C2R))
        self.assertEqual(attempt.pinned_contract({"arm": "after", "vens_commit": REPAIR}), contract.C1C2R)
        self.assertEqual(contract.CONTRACTS[POLICY], contract.C1C2B)
        self.assertEqual(contract.C1C2_RULES, (contract.C1C2, contract.C1C2P, contract.C1C2B, contract.C1C2R))
        self.assertEqual(contract.C2P_RULES, (contract.C1C2P, contract.C1C2B, contract.C1C2R))
        self.assertEqual(contract.BASIS_RULES, (contract.C1C2B, contract.C1C2R))
        self.assertEqual(contract.accepted(contract.C1C2R), {contract.C1C2, contract.C1C2P})
        self.assertIn(contract.C1C2R, contract.NAMES)
        self.assertEqual([contract.basis_commit(x) for x in (REPAIR, POLICY, MARKER, None)], [True, True, False, False])
        self.assertEqual([contract.marker_commit(x) for x in (REPAIR, POLICY, MARKER, contract.C2P_COMMIT)],
                         [True, True, True, False])

    def test_the_docs_commit_and_ed1ed1c(self):
        # a475b2a, review B's docs and comments over ed1ed1c, is the repair commit; ed1ed1c is still read as one
        (first,) = contract.EARLIER_REPAIRS
        self.assertEqual((REPAIR, first), ("a475b2a5d3499e86680ba366b505da770b6fbb96",
                                           "ed1ed1c6eac749976e8d3be16aa409fa8870ede3"))
        self.assertEqual(sorted(x for x, rules in contract.CONTRACTS.items() if rules == contract.C1C2R),
                         sorted((REPAIR, first)))
        for commit in (REPAIR, first):
            self.assertEqual(attempt.pinned_contract({"arm": "after", "vens_commit": commit}), contract.C1C2R)
            self.assertEqual((contract.basis_commit(commit), contract.marker_commit(commit)), (True, True))


class TestTheTable(unittest.TestCase):
    """contract.damage over 4 criticalities x 4 sensitivities x 4 availability requirements x (27 C/I/A + none)."""

    def test_the_decided_table(self):
        self.assertEqual(contract.DAMAGE, TABLE)
        self.assertEqual(contract.DECLARED, ("FD", "RD"))

    def test_every_cell(self):
        self.assertEqual(len(CELLS), 1792)
        for c in CELLS:
            fd, rd = contract.damage(*cell(*c))
            self.assertEqual((fd, rd), want(*c), c)
            self.assertIn(fd, (1, 3, 7, 9), c)
            self.assertIn(rd, (1, 4, 5, 9), c)

    def test_never_falls_as_an_input_rises(self):
        got = {c: contract.damage(*cell(*c)) for c in CELLS}
        bad = []
        for (crit, sens, avail, cia), (fd, rd) in got.items():
            raised = [(FOUR[FOUR.index(crit) + 1], sens, avail, cia)] if crit != "critical" else []
            raised += [(crit, FOUR[FOUR.index(sens) + 1], avail, cia)] if sens != "critical" else []
            raised += [(crit, sens, FOUR[FOUR.index(avail) + 1], cia)] if avail != "critical" else []
            if cia is not None:
                raised += [(crit, sens, avail, cia[:i] + "NLH"["NLH".index(x) + 1] + cia[i + 1:])
                           for i, x in enumerate(cia) if x != "H"]
                raised.append((crit, sens, avail, None))
            bad += [(c, (fd, rd), got[c]) for c in raised if got[c][0] < fd or got[c][1] < rd]
        self.assertEqual(bad, [])

    def test_the_band_without_a_vector_is_high(self):
        dep, imp = cell("medium", "low", "low", None)
        self.assertEqual((contract.technical_band(dep, imp), contract.damage(dep, imp)), (2, (3, 4)))

    def test_criticality_as_vens_loads_it(self):
        ctx = {"exposure": "internal", "data_sensitivity": "low", "business_criticality": " Critical "}
        dep = contract.deployment({"context": ctx})
        self.assertEqual(dep["business_criticality"], "critical")
        for bad in (None, "", "vital"):
            with self.assertRaisesRegex(ValueError, "is not low, medium, high or critical"):
                contract.damage(dict(dep, business_criticality=bad), contract.NO_IMPACT_READ)

    def test_the_disclosures(self):
        band = lambda x: 0 if x < 3 else 1 if x < 6 else 2
        top = {}
        for crit in FOUR:
            for t in range(3):
                fd, rd = TABLE[crit][0][t], TABLE[crit][1][t]
                for nc, pv in itertools.product((2, 5, 7), (3, 5, 7, 9)):
                    top[(crit, t, nc)] = max(top.get((crit, t, nc), 0), Fraction(fd + rd + nc + pv, 4))
        # without a framework (NC 2) a HIGH business impact needs critical at t high and PV 5 or more
        self.assertEqual({k for k, v in top.items() if k[2] == 2 and band(v) == 2}, {("critical", 2, 2)})
        self.assertEqual(Fraction(9 + 9 + 2 + 5, 4), Fraction(25, 4))
        self.assertEqual(top[("high", 2, 2)], Fraction(23, 4))
        self.assertFalse(any(band(v) == 2 for k, v in top.items() if k[0] == "low"))
        # a C:H CVE on public data in a critical service: LC 6, t high, FD 9 and RD 9
        self.assertEqual(contract.damage(*cell("critical", "low", "low", "HNN")), (9, 9))


class TestTheLevels(unittest.TestCase):
    """Under c1c2r the levels are c1c2b's but Financial and Reputation damage, not asked, from the table."""

    def test_on_the_corpus(self):
        scen = verdicts.load(SCENARIOS, contract.C1C2R)
        for sid, sc in scen.items():
            args = (sc["dep"], sc["impact"], sc["described"])
            rr = contract.c1c2_levels(*args, GIVEN, rules=contract.C1C2R)
            bb = contract.c1c2_levels(*args, GIVEN, rules=contract.C1C2B)
            self.assertEqual({f: x for f, x in rr.items() if f not in ("FD", "RD")},
                             {f: x for f, x in bb.items() if f not in ("FD", "RD")}, sid)
            fd, rd = contract.damage(sc["dep"], sc["impact"])
            self.assertEqual((rr["FD"], rr["RD"]), ((fd, "criticality"), (rd, "criticality")), sid)
            self.assertEqual((rr["SL"], bb["FD"][1]), ((9, "worst_case"), "answer"), sid)
            self.assertEqual([contract.c1c2_asked(f, *args, rules=contract.C1C2R) for f in ("FD", "RD")],
                             [False, False], sid)
            self.assertEqual([contract.c1c2_asked(f, *args, rules=contract.C1C2B) for f in ("FD", "RD")],
                             [True, True], sid)
            self.assertEqual(contract.c1c2_questions(*args, rules=contract.C1C2R),
                             [q for q in contract.c1c2_questions(*args) if q not in ("FD", "RD")], sid)


class TestTheGate(unittest.TestCase):
    """chain/conform.py under c1c2r: Financial and Reputation damage recomputed from the table, the rating on the
    published basis, the rating policy required; the review's M1: under c1c2b and c1c2r no basis refuses whatever the
    commit."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = os.path.join(cls.tmp.name, "scenarios")
        shutil.copytree(SCENARIOS, root)
        without_subjects(root, ("reach_no",))
        cls.scen = verdicts.load(root, contract.C1C2R)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def problems(self, rec, sid, rules=contract.C1C2R):
        sc = self.scen[sid]
        return conform.run_problems(rec, sc["config"], {sc["vuln_id"]: sc["findings"]}, rules)

    def test_a_run_on_the_table_passes(self):
        self.assertEqual(self.problems(published("reach_yes", self.scen), "reach_yes"), [])
        for commit in contract.EARLIER_REPAIRS:
            self.assertEqual(self.problems(published("reach_yes", self.scen, commit=commit), "reach_yes"), [], commit)
        rec = published("reach_no", self.scen, basis=("technical",), rate_on="technical")
        self.assertEqual(self.problems(rec, "reach_no"), [])
        cells = conform.read(cellmod.group([published("reach_yes", self.scen)]), self.scen, None, contract.C1C2R)
        self.assertEqual([c["verdict"] for c in cells.values()], ["pass"])

    def test_damage_off_the_table_fails(self):
        sc = self.scen["reach_yes"]
        fd, rd = contract.damage(sc["dep"], sc["impact"])
        other = next(x for x in (1, 3, 7, 9) if x != fd)
        rec = published("reach_yes", self.scen, levels={"FD": other})
        got = self.problems(rec, "reach_yes")
        self.assertEqual(len(got), 1)
        self.assertTrue(got[0].startswith(f"{sc['vuln_id']}: FD {other} not {fd}"), got)
        rec = published("reach_yes", self.scen, levels={"RD": 9 if rd != 9 else 1})
        self.assertTrue(self.problems(rec, "reach_yes")[0].startswith(f"{sc['vuln_id']}: RD "))

    def test_the_rating_policy(self):
        for policy, shown in (((), "[]"), (("1",), "['1']"), (("2", "2"), "['2', '2']"), (None, "metadata unread")):
            rec = published("reach_yes", self.scen, policy=policy)
            self.assertEqual(self.problems(rec, "reach_yes"), [f"{RATING_POLICY} {shown}, not one '2'"], policy)
        # required whatever the commit; c1c2b reads none
        rec = published("reach_yes", self.scen, commit=POLICY, policy=())
        self.assertEqual(self.problems(rec, "reach_yes"), [f"{RATING_POLICY} [], not one '2'"])
        self.assertFalse(any(RATING_POLICY in p for p in self.problems(rec, "reach_yes", contract.C1C2B)))

    def test_no_basis_refuses_whatever_the_commit(self):
        vid = self.scen["reach_yes"]["vuln_id"]
        for rules in contract.BASIS_RULES:
            for commit in (REPAIR, POLICY, None, "0" * 40):
                rec = published("reach_yes", self.scen, basis=(), commit=commit)
                self.assertIn(f"{vid}: 0 {BASIS} properties, not one", self.problems(rec, "reach_yes", rules),
                              (rules, commit))
        # a known commit that writes no basis, with one, is refused as before
        rec = published("reach_yes", self.scen, commit=MARKER)
        self.assertIn(f"{vid}: {BASIS} published, vens {MARKER[:12]} writes no basis",
                      self.problems(rec, "reach_yes", contract.C1C2B))

    def test_c1c2p_reads_as_before(self):
        sc = self.scen["reach_yes"]
        vid = sc["vuln_id"]
        got = contract.c1c2_levels(sc["dep"], sc["impact"], sc["described"], GIVEN, rules=contract.C1C2P)
        rec = published("reach_yes", self.scen, commit=MARKER, basis=(), rate_on=None, policy=(),
                        levels={f: x for f, (x, _) in got.items()})
        vec = next(iter(rec["ratings"].values()))["vector"]
        rec["answers"]["per_cve"][vid]["factors"] = r.factors(vec, **{f: (GIVEN.get(f), "answer") for f in cdx.FACTORS})
        self.assertEqual(self.problems(rec, "reach_yes", contract.C1C2P), [])
        # with no commit, as the M1 probe: c1c2p does not require a basis
        self.assertEqual(self.problems({**rec, "what": {**rec["what"], "vens_commit": None}}, "reach_yes",
                                       contract.C1C2P), [f"{vid}: {PROVENANCE} published, vens None writes no marker"])

    def test_the_basis_off_its_config(self):
        nvid = self.scen["reach_no"]["vuln_id"]
        rec = published("reach_no", self.scen, basis=("business",), rate_on="business")
        self.assertEqual(self.problems(rec, "reach_no"), [f"{nvid}: {BASIS} 'business', its config gives 'technical'"])


class TestTheAnswers(unittest.TestCase):
    """answers.json pinned to c1c2r: c1c2b's reading, plus Skill level from worst_case and Financial and Reputation
    damage from criticality, never answered."""

    def entry(self, sl="worst_case", fd=None):
        e = c1c2_entry()
        for x in e["factors"]:
            if x["factor"] == "SL":
                x["source"] = sl
            if x["factor"] in ("FD", "RD"):
                x.update(source="criticality", level=9)
        if fd is not None:
            next(x for x in e["factors"] if x["factor"] == "FD").update(fd)
        return e

    def test_the_counter_totals(self):
        ar, vm = "availability_requirement_missing", "cvss_v3_missing"
        vectorless = self.entry()
        vectorless["counters"] = [vm]
        for x in vectorless["factors"]:
            if x["factor"] in ("LC", "LI", "LAV"):
                x.update(level=9)
                x.pop("cvss", None)
        self.assertEqual(answers.validate(doc(vectorless), contract.C1C2R), [])
        self.assertEqual(answers.validate(doc(vectorless, counters={}), contract.C1C2R),
                         [f"{vm} totals 0, its entries count 1"])
        unrated = {"vulnId": "CVE-2099-0002", "unrated": True, "adjustment": "not_asked",
                   "factors": [{"factor": "M", "answer": "a", "reading": "answered"}], "counters": [ar]}
        self.assertEqual(answers.validate(doc(self.entry(), unrated), contract.C1C2R),
                         [f"CVE-2099-0002: an unrated entry counting {ar}"])

    def test_validate(self):
        self.assertEqual(answers.validate(doc(self.entry()), contract.C1C2R), [])
        self.assertEqual(answers.validate(doc(self.entry(sl="constant")), contract.C1C2R),
                         ["CVE-2099-0001: SL not from worst_case"])
        for fd in ({"answer": "bankruptcy", "reading": "answered"}, {"source": "answer"}):
            self.assertEqual(answers.validate(doc(self.entry(fd=fd)), contract.C1C2R),
                             ["CVE-2099-0001: FD not from criticality alone"], fd)
        # c1c2b reads these entries as before
        self.assertEqual(answers.validate(doc(self.entry(sl="constant")), contract.C1C2B), [])


class TestTheReaders(unittest.TestCase):
    """cdx carries the VEX metadata's rating policy on each rating; the null model's after reads the configured
    basis under c1c2r as under c1c2b."""

    def test_cdx_reads_the_rating_policy(self):
        vex = s.vex([("CVE-2099-0001", s.VECTOR, s.SEVERITY, s.SCORE)])
        cases = ((None, []), ({"properties": [{"name": RATING_POLICY, "value": "2"}, {"name": "x", "value": "y"}]},
                              ["2"]), ({}, []), ("metadata", None))
        for meta, policy in cases:
            v = dict(vex, **({} if meta is None else {"metadata": meta}))
            with tempfile.TemporaryDirectory() as tmp:
                got, problems = cdx.ratings(s.write(os.path.join(tmp, "vex.json"), v))
            self.assertEqual((got["CVE-2099-0001"]["policy"], problems), (policy, []), meta)

    def test_the_null_model(self):
        null = {"threat_agent": 4, "vulnerability": 5, "technical_impact": 7, "business_impact": 2}
        scen = {"a": {"null": null, "dep": dict(DEP)}, "b": {"null": null, "dep": dict(DEP, data_subjects=None)}}
        got = {row["scenario"]: row["rules"]["after"][1] for row in diagnostics.null_table({}, scen, None,
                                                                                           contract.C1C2R)}
        self.assertEqual(got, {"a": "low", "b": "high"})


class TestTheMock(unittest.TestCase):
    """vens's mock at the repair commit (VB_VENS_REPAIR) on every scenario, as written (business) and without
    data_subjects (technical): every run passes conform under c1c2r, FD and RD the table's from source criticality, the
    rating policy 2; read under c1c2b, a run whose table sets FD or RD below 9 fails; beside the policy commit's binary
    (VB_VENS_POLICY): the same levels but FD and RD, the policy commit writing no rating policy."""

    @classmethod
    def setUpClass(cls):
        cls.binary = s.env("VB_VENS_REPAIR")
        if cls.binary is None:
            raise unittest.SkipTest("set VB_VENS_REPAIR to a vens binary built from 310-policy at the repair commit")
        cls.policy = s.env("VB_VENS_POLICY")
        cls.tmp = tempfile.TemporaryDirectory()
        plain = shutil.copytree(SCENARIOS, os.path.join(cls.tmp.name, "plain"))
        technical = without_subjects(shutil.copytree(SCENARIOS, os.path.join(cls.tmp.name, "technical")), IDS)
        cls.runs = {}
        for tag, root, binary in (("business", plain, cls.binary), ("technical", technical, cls.binary),
                                  ("policy", plain, cls.policy)):
            for sid in IDS if binary else ():
                folder = os.path.join(cls.tmp.name, "runs", tag, sid)
                rec = runvens.generate(binary, os.path.join(root, sid, "config.yaml"),
                                       os.path.join(root, sid, "report.json"), folder, record={"arm": "after"})
                cls.runs[(tag, sid)] = (folder, rec["generate"]["exit_status"])
        cls.scen = {"business": verdicts.load(plain, contract.C1C2R),
                    "technical": verdicts.load(technical, contract.C1C2R)}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def record(self, tag, sid, commit=REPAIR, rules=contract.C1C2R):
        folder, code = self.runs[(tag, sid)]
        self.assertEqual(code, 0, (tag, sid))
        rec = attempt.read_attempt(folder, rules=rules)
        self.assertEqual((rec["scores_usable"], rec["problems"], rec["answers"]["problems"]), (True, [], []), sid)
        return {**rec, "what": {**rec["what"], "vens_commit": commit}}

    def test_every_run_recomputes(self):
        below = 0
        for tag in ("business", "technical"):
            for sid in IDS:
                sc = self.scen[tag][sid]
                cves = {sc["vuln_id"]: sc["findings"]}
                rec = self.record(tag, sid)
                (rating,) = rec["ratings"].values()
                self.assertEqual((rating["basis"], rating["policy"]), ([tag], ["2"]), (tag, sid))
                self.assertEqual(conform.run_problems(rec, sc["config"], cves, contract.C1C2R), [], (tag, sid))
                fs = rec["answers"]["per_cve"][sc["vuln_id"]]["factors"]
                fd, rd = contract.damage(sc["dep"], sc["impact"])
                self.assertEqual([(fs[f]["level"], fs[f]["source"], fs[f]["answer"]) for f in ("FD", "RD")],
                                 [(fd, "criticality", None), (rd, "criticality", None)], (tag, sid))
                if min(fd, rd) < 9:
                    below += 1
                    off = conform.run_problems(rec, sc["config"], cves, contract.C1C2B)
                    self.assertTrue(any(" not " in p for p in off), (tag, sid, off))
        self.assertGreater(below, 0)

    def test_beside_the_policy_commit(self):
        if self.policy is None:
            self.skipTest("set VB_VENS_POLICY to compare with the policy commit's mock")
        for sid in IDS:
            ours, theirs = self.record("business", sid), self.record("policy", sid, POLICY, contract.C1C2B)
            (vid, o), (_, t) = next(iter(ours["ratings"].items())), next(iter(theirs["ratings"].items()))
            self.assertEqual({f: x for f, x in o["levels"].items() if f not in ("FD", "RD")},
                             {f: x for f, x in t["levels"].items() if f not in ("FD", "RD")}, sid)
            self.assertEqual((o["provenance"], o["basis"], t["policy"]), (t["provenance"], t["basis"], []), sid)
            self.assertEqual((o["severity"], o["score"]), conform.rating(o["levels"], "business")[1:], sid)


if __name__ == "__main__":
    unittest.main()
