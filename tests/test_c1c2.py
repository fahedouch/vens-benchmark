"""C1 + C2 without a reachability relay (venslabs/vens#310 plans Z0 and Z0d) as the chain mirrors them, on synthetic
inputs: the usable v3 vector rule, C2's table, the nine questions, Privacy violation's floor and the adjustment,
answers.json's C1 + C2 record against the pinned contract, no declared block and no VEX status, the families under the
no-relay checks with read5's eligibility rule, and step 5's corpus. No vens is run: tests/test_c1c2_mock.py runs the
rules against N's mock, tests/test_c1c2_gate.py the implementation gate, tests/test_c1c2p.py C1 + C2'."""
import os
import tempfile
import unittest

import yaml

from chain import answers, attempt, campaign, cdx, contract, families, report_scen, verdicts
from chain import cells as cellmod
from tests import records as r
from tests import support as s

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS = os.path.join(ROOT, "scenarios")
IDS = sorted(d for d in os.listdir(SCENARIOS) if os.path.isdir(os.path.join(SCENARIOS, d)))
A, B = "CVE-2099-0001", "CVE-2099-0002"
DEP = {"exposure": "internet", "data_sensitivity": "high", "frameworks": ("gdpr",),
       "detection": {"network": "logged", "host": "not_logged", "application": "active_in_application"},
       "traceability": "per_individual", "data_subjects": "millions"}
BODY = "AV:N/AC:L/PR:N/UI:N/S:U/"


def v31(cia, source="nvd"):
    return source, "3.1", f"CVSS:3.1/{BODY}{cia}"


def finding(cvss, pkg="libwidget", description="d"):
    return {"VulnerabilityID": A, "PkgName": pkg, "Description": description, "CVSS": cvss}


def impact_of(*cias):
    return contract.impact([v31(c) for c in cias])


class TestTheVectors(unittest.TestCase):
    """pkg/cvss's ImpactOf and the Trivy scanner's vector listing, case by case as vens's own tests take them."""

    def test_the_trivy_listing(self):
        f = finding({"redhat": {"V3Vector": "cvss:3.0/" + BODY + "C:L/I:L/A:L"},
                     "nvd": {"V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "V3Vector": BODY + "C:H/I:N/A:N",
                             "V40Vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
                     "ghsa": {"V3Vector": " CVSS:3.2/" + BODY + "C:H/I:H/A:H", "V2Vector": ""}})
        self.assertEqual([(src, version) for src, version, _ in contract.trivy_vectors(f)],
                         [("ghsa", "3.2"), ("nvd", "2.0"), ("nvd", "3"), ("nvd", "4.0"), ("redhat", "3.0")])

    def test_the_worst_value_per_axis(self):
        cases = (([v31("C:H/I:L/A:N")], {"C": "H", "I": "L", "A": "N"}, 1),
                 ([v31("C:L/I:N/A:H"), v31("C:H/I:L/A:N", "redhat")], {"C": "H", "I": "L", "A": "H"}, 2),
                 ([("nvd", "3.0", "CVSS:3.0/" + BODY + "C:N/I:H/A:N"), v31("C:L/I:N/A:N", "redhat")],
                  {"C": "L", "I": "H", "A": "N"}, 2),
                 ([("nvd", "3", BODY + "C:N/I:N/A:L")], {"C": "N", "I": "N", "A": "L"}, 1),
                 ([("nvd", "3.1", "cvss:3.1/" + BODY + "C:L/I:L/A:L")], {"C": "L", "I": "L", "A": "L"}, 1),
                 ([v31("C:H/I:H/A:H"), ("redhat", "3.1", "  CVSS:3.1/" + BODY + "C:H/I:H/A:H\n")],
                  {"C": "H", "I": "H", "A": "H"}, 1),
                 ([v31("C:H/I:H/A:H/C:L"), v31("C:N/I:L/A:N", "redhat")], {"C": "N", "I": "L", "A": "N"}, 1))
        for vectors, values, usable in cases:
            got = contract.impact(vectors)
            self.assertEqual((got.values, got.usable), (values, usable), vectors)

    def test_a_vector_refused_whole(self):
        cases = ((v31("garbage"), "not a metric:value pair"),
                 (("nvd", "3.1", "CVSS:3.1/" + BODY + "C:H/I:H/A:H/"), "not a metric:value pair"),
                 (v31("C:H/I:H/A:H/A:L"), "given twice"),
                 (v31("I:H/A:H"), "C is absent"),
                 (v31("C:H/I:X/A:H"), "I is absent or off"),
                 (v31("C:H/I:H/A:h"), "A is absent or off"),
                 (("nvd", "3.1", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"), "states neither 3.0 nor 3.1"),
                 (("nvd", "3", "CVSS:3/" + BODY + "C:H/I:H/A:H"), "states neither 3.0 nor 3.1"),
                 (("nvd", "3.1", "CVSS:3.1"), "not a metric:value pair"),
                 (("nvd", "3.2", "CVSS:3.2/" + BODY + "C:H/I:H/A:H"), "CVSS version '3.2' is neither 3.0 nor 3.1"),
                 (("ghsa", "3.9", BODY + "C:H/I:H/A:H"), "CVSS version '3.9' is neither 3.0 nor 3.1"))
        for vector, why in cases:
            got = contract.impact([vector])
            self.assertEqual((got.usable, got.values, len(got.rejected)), (0, {}, 1), vector)
            self.assertIn(why, got.rejected[0][1], vector)

    def test_v3_alone_is_read(self):
        v4 = ("nvd", "4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
        v2 = ("nvd", "2.0", "AV:N/AC:L/Au:N/C:C/I:C/A:C")
        self.assertEqual(contract.impact([]), contract.NO_IMPACT_READ)
        self.assertEqual(contract.impact([v2]), contract.NO_IMPACT_READ)
        self.assertEqual(contract.impact([v4, v4]), contract.Impact({}, 0, (), 1))
        self.assertEqual(contract.impact([("nvd", "5.0", "CVSS:5.0/AV:N"), ("nvd", "", "AV:N")]),
                         contract.NO_IMPACT_READ)
        self.assertEqual(contract.impact([v2, v31("C:N/I:N/A:L"), v4]),
                         contract.Impact({"C": "N", "I": "N", "A": "L"}, 1, (), 1))

    def test_gos_trim_keeps_what_str_strip_would_take(self):
        # \x1c before the prefix: no prefix for Go, so a V3Vector of version 3 whose first metric is "\x1cCVSS"
        f = finding({"nvd": {"V3Vector": "\x1cCVSS:3.2/" + BODY + "C:H/I:H/A:H"}})
        self.assertEqual(contract.trivy_vectors(f)[0][1], "3")
        self.assertEqual(contract.cve_impact([f]).usable, 1)
        self.assertEqual(contract.prefix_version("\u2003cvss:3.1/AV:N"), "3.1")

    def test_another_3x_version_is_counted_once_and_leaves_a_usable_one(self):
        v32 = ("nvd", "3.2", "CVSS:3.2/" + BODY + "C:H/I:H/A:H")
        again = ("redhat", "3.2", " CVSS:3.2/" + BODY + "C:H/I:H/A:H ")
        got = contract.impact([v32, again])
        self.assertEqual((got.usable, len(got.rejected)), (0, 1))
        got = contract.impact([v32, v31("C:L/I:N/A:N")])
        self.assertEqual((got.values, got.usable, len(got.rejected)), ({"C": "L", "I": "N", "A": "N"}, 1, 1))

    def test_the_counts_and_the_disagreeing_axes(self):
        cves = {A: [finding({"nvd": {"V3Vector": f"CVSS:3.1/{BODY}C:H/I:L/A:N"}}),
                    finding({"redhat": {"V3Vector": f"CVSS:3.1/{BODY}C:L/I:L/A:H"}}, pkg="other")],
                B: [finding({"nvd": {"V3Vector": "CVSS:3.2/" + BODY + "C:N/I:N/A:N",
                                     "V40Vector": "CVSS:4.0/AV:N"}})]}
        self.assertEqual(contract.disagreeing_axes([v for f in cves[A] for v in contract.trivy_vectors(f)]),
                         ["C", "A"])
        self.assertEqual(contract.impact_counts(cves), {"cves": 2, "vectorless": 1, "rejected": 1, "disagree": 1,
                                                        "disagree_axes": 2, "v4": 1, "pv_floor": 0})


class TestTheRules(unittest.TestCase):
    """C2's table, the nine questions, Privacy violation's floor and cap, and the adjustment."""

    def test_c2s_table(self):
        for ds, column in (("low", 0), ("medium", 0), ("high", 1), ("critical", 1)):
            dep = dict(DEP, data_sensitivity=ds)
            for value, lc, li, lav in (("N", (2, 2), 1, 1), ("L", (2, 6), 3, 5), ("H", (6, 7), 7, 7)):
                imp = impact_of(f"C:{value}/I:{value}/A:{value}")
                got = {f: contract.c1c2_options(f, dep, imp) for f in contract.AXIS}
                self.assertEqual(got, {"LC": {None: lc[column]}, "LI": {None: li}, "LAV": {None: lav}}, (ds, value))
                self.assertEqual({contract.c1c2_source(f, dep, imp) for f in contract.AXIS}, {"cvss"})
        # no usable vector: each at 9, whatever the column; a level 9 never comes from a vector
        self.assertEqual({contract.impact_level(f, DEP, contract.NO_IMPACT_READ) for f in contract.AXIS}, {9})
        self.assertNotIn(9, {lv for t in (contract.C2_LI, contract.C2_LAV) for lv in t.values()}
                         | {lv for pair in contract.C2_LC.values() for lv in pair})

    def test_at_most_nine_questions_never_an_impact_nor_r(self):
        unfloored = impact_of("C:H/I:H/A:H")
        self.assertEqual(contract.c1c2_questions(DEP, unfloored), list(contract.C1C2_QUESTIONS))
        self.assertEqual(contract.c1c2_questions(DEP, contract.NO_IMPACT_READ), list(contract.C1C2_QUESTIONS))
        self.assertEqual(contract.c1c2_questions(DEP, unfloored, described=False),
                         ["ID", "LAC", "FD", "RD", "NC", "PV"])
        self.assertFalse(set(contract.C1C2_QUESTIONS) & {"R", "LC", "LI", "LAV"})

    def test_privacy_violations_floor_on_usable_vectors_giving_c_n(self):
        cases = ((impact_of("C:N/I:H/A:H"), True), (impact_of("C:N/I:H/A:H", "C:L/I:N/A:N"), False),
                 (contract.NO_IMPACT_READ, False),
                 (contract.impact([("nvd", "3.2", "CVSS:3.2/" + BODY + "C:N/I:N/A:N")]), False))
        for imp, floored in cases:
            self.assertEqual(contract.privacy_floored(imp), floored, imp)
            self.assertEqual(contract.c1c2_asked("PV", DEP, imp), not floored, imp)
            self.assertEqual(contract.c1c2_source("PV", DEP, imp, "millions"), "floor" if floored else "answer")
            if floored:
                self.assertEqual(contract.c1c2_options("PV", DEP, imp), {None: 3})
        # data_subjects at the floor's band caps it there, not asked, from config
        dep, unfloored = dict(DEP, data_subjects="one_individual"), impact_of("C:H/I:H/A:H")
        self.assertEqual((contract.c1c2_asked("PV", dep, unfloored), contract.c1c2_source("PV", dep, unfloored)),
                         (False, "config"))

    def test_the_levels_from_the_answers(self):
        imp = impact_of("C:H/I:L/A:N")
        given = {"M": "possible_reward", "O": "some_access_or_resources_required", "EE": "difficult",
                 "ID": ["network", "application"], "LAC": "defeats_attribution", "FD": "bankruptcy",
                 "RD": "loss_of_goodwill", "NC": "clear_violation", "PV": "thousands"}
        got = contract.c1c2_levels(DEP, imp, True, given)
        self.assertEqual({f: lv for f, (lv, _) in got.items()},
                         {"SL": 9, "M": 4, "O": 7, "S": 9, "ED": 9, "EE": 3, "A": 9, "ID": 1, "LC": 7, "LI": 3,
                          "LAV": 1, "LAC": 9, "FD": 9, "RD": 5, "NC": 5, "PV": 7})
        self.assertEqual({f for f, (_, src) in got.items() if src == "cvss"}, {"LC", "LI", "LAV"})
        # an answer off the list, an empty set or one holding cannot_tell take the worst case
        worst = contract.c1c2_levels(DEP, imp, True, {"M": "nope", "ID": [], "PV": 3})
        self.assertEqual((worst["M"][0], worst["ID"][0], worst["PV"][0]), (9, 9, 9))
        self.assertEqual(contract.c1c2_levels(DEP, imp, True, {"ID": ["application", "cannot_tell"]})["ID"][0], 9)
        # without a description Motive, Opportunity and Ease of exploit are at cannot_tell's level, from answer
        bare = contract.c1c2_levels(DEP, imp, False, {})
        self.assertEqual({f: bare[f] for f in ("M", "O", "EE")}, {"M": (9, "answer"), "O": (9, "answer"),
                                                                  "EE": (9, "answer")})

    def test_the_adjustment_lowers_opportunity_and_privacy_violation_alone(self):
        imp, given = impact_of("C:H/I:H/A:H"), {"O": "no_access_or_resources_required", "PV": "millions"}
        base = contract.c1c2_levels(DEP, imp, True, given)
        low = contract.c1c2_levels(DEP, imp, True, given, {"O": "special_access_or_resources_required",
                                                           "PV": "not_affected"})
        self.assertEqual((low["O"], low["PV"]), ((4, "adjustment"), (3, "adjustment")))
        self.assertEqual({f: low[f] for f in contract.AXIS}, {f: base[f] for f in contract.AXIS})
        for adjusted in ({"O": "keep", "PV": "affected"}, {"O": "cannot_tell", "PV": "cannot_tell"}):
            self.assertEqual(contract.c1c2_levels(DEP, imp, True, given, adjusted), base, adjusted)
        # never raised; Opportunity's adjustment needs a description, Privacy violation's its question
        high = contract.c1c2_levels(DEP, imp, True, {"O": "full_access_or_expensive_resources_required"},
                                    {"O": "no_access_or_resources_required"})
        self.assertEqual(high["O"], (0, "answer"))
        undescribed = contract.c1c2_levels(DEP, imp, False, {}, {"O": "full_access_or_expensive_resources_required"})
        self.assertEqual(undescribed["O"], (9, "answer"))
        floored = impact_of("C:N/I:H/A:H")
        self.assertEqual(contract.c1c2_levels(DEP, floored, True, {}, {"PV": "not_affected"})["PV"], (3, "floor"))

    def test_the_adjustments_fields(self):
        floored, unfloored = impact_of("C:N/I:H/A:H"), impact_of("C:H/I:H/A:H")
        self.assertEqual(contract.adjustment_fields(DEP, unfloored), ["opportunity", "confidentiality"])
        self.assertEqual(contract.adjustment_fields(DEP, unfloored, False), ["confidentiality"])
        self.assertEqual(contract.adjustment_fields(DEP, floored), ["opportunity"])
        self.assertEqual(contract.adjustment_fields(DEP, floored, False), [])


def c1c2_entry(vid=A, cvss="H", counters=(), pv=None):
    """A rated answers.json entry under C1 + C2, every impact from cvss (None: no usable vector)."""
    levels = {"LC": contract.C2_LC.get(cvss, (9, 9))[1], "LI": contract.C2_LI.get(cvss, 9),
              "LAV": contract.C2_LAV.get(cvss, 9)}
    factors = []
    for f in cdx.FACTORS:
        if f in contract.AXIS:
            factors.append({"factor": f, "level": levels[f], "source": "cvss", **({"cvss": cvss} if cvss else {})})
        elif f == "PV":
            factors.append(pv or ({"factor": "PV", "level": 3, "source": "floor", "cvss": "N"} if cvss == "N" else
                                  {"factor": "PV", "answer": "a", "reading": "answered", "level": 5,
                                   "source": "answer"}))
        else:
            factors.append({"factor": f, "level": 5, "source": "constant"})
    return {"vulnId": vid, "adjustment": "not_asked", "factors": factors, "counters": list(counters)}


def load(d):
    with tempfile.TemporaryDirectory() as tmp:
        return answers.load(s.write(os.path.join(tmp, "answers.json"), d))


def doc(*vulns):
    return load({"vulnerabilities": list(vulns), "counters": {}, "defects": {}})


STATUS = {"state": "not_affected", "justification": "code_not_reachable", "detail": "compiled out"}


class TestTheRecord(unittest.TestCase):
    """answers.json under C1 + C2 as the reader checks it: no relay, so no declared block and no VEX status."""

    def test_the_contract_shown_and_the_one_pinned(self):
        raw = s.answers_doc([(A, s.VECTOR)])
        old, new = load(raw), doc(c1c2_entry())
        reach = doc({**raw["vulnerabilities"][0], "reachability": {"factor": "R", "answer": "reachable"}})
        mixed = doc(reach["vulnerabilities"][0], c1c2_entry(B))
        unrated = doc({"vulnId": B, "unrated": True, "adjustment": "not_asked",
                       "factors": [{"factor": "M", "answer": "a", "reading": "answered"}]})
        bare = c1c2_entry()
        bare["factors"] = [f for f in bare["factors"] if f["factor"] not in contract.AXIS]
        self.assertEqual([answers.marks(d) for d in (old, new, reach, unrated, doc(bare))],
                         [{contract.B7C0435}, {contract.C1C2}, {contract.REACH_RULES}, set(), set()])
        self.assertEqual((answers.rules_of(old), answers.rules_of(new), answers.rules_of(mixed)),
                         (contract.B7C0435, contract.C1C2, None))
        # the pinned contract is validated, never downgraded: a record off it, mixed or unknown fails
        self.assertEqual([answers.validate(d, contract.C1C2) for d in (new, unrated)], [[], []])
        self.assertEqual(answers.validate(old, contract.C1C2), ["answers.json follows b7c0435, not the pinned c1c2"])
        self.assertEqual(answers.validate(new, contract.B7C0435), ["answers.json follows c1c2, not the pinned b7c0435"])
        self.assertEqual(answers.validate(mixed, contract.C1C2), ["answers.json mixes contracts: 5f797bf, c1c2"])
        self.assertEqual(answers.validate(doc(bare), contract.C1C2)[0], f"{A}: LC not from cvss alone")
        self.assertEqual(answers.validate(doc(bare), None), [])
        self.assertEqual((answers.validate(old, None), answers.validate(old, contract.B7C0435)), ([], []))
        self.assertEqual(answers.c1c2(reach)[:4], [f"{A}: a reachability record under C1 + C2"] + [
            f"{A}: {f} not from cvss alone" for f in ("LC", "LI", "LAV")])

    def test_the_contract_a_commit_or_the_reading_pins(self):
        self.assertEqual([attempt.pinned_contract({"arm": "after", "vens_commit": sha}) for sha in (
            s.AFTER_SHA, s.REACH_SHA, s.C1C2_SHA, s.RELAY_SHA, "e" * 40)],
            [contract.B7C0435, contract.REACH_RULES, contract.C1C2, None, None])
        self.assertEqual(attempt.pinned_contract({"arm": "after", "vens_commit": s.RELAY_SHA}, contract.C1C2),
                         contract.C1C2)
        self.assertEqual(attempt.pinned_contract({"arm": "after", "vens_commit": s.AFTER_SHA}, contract.C1C2),
                         contract.C1C2)
        self.assertIsNone(attempt.pinned_contract({"arm": "before", "vens_commit": s.AFTER_SHA}, contract.C1C2))
        # N, the no-relay commit, pins C1 + C2; 2de5d34, which relayed, nothing
        self.assertEqual([sha for sha, rules in contract.CONTRACTS.items() if rules == contract.C1C2], [s.C1C2_SHA])

    def test_a_record_that_follows_c1_c2(self):
        good = doc(c1c2_entry(A, "H"), c1c2_entry(B, None, counters=["cvss_v3_missing"]),
                   c1c2_entry("CVE-2099-0003", "N"))
        self.assertEqual(answers.validate(good, contract.C1C2), [])
        self.assertEqual(answers.per_cve(good["vulnerabilities"][0])["factors"]["LC"]["cvss"], "H")

    def test_the_impacts_off_c2(self):
        lc_answered = c1c2_entry()
        lc_answered["factors"][8].update(answer="extensive", reading="answered")
        li_off = c1c2_entry()
        li_off["factors"][9]["level"] = 5
        mixed = c1c2_entry()
        del mixed["factors"][10]["cvss"]
        mixed["factors"][10]["level"] = 9
        cases = ((lc_answered, "LC not from cvss alone"), (li_off, "LI at 5 from cvss 'H'"),
                 (c1c2_entry(cvss=None), "cvss_v3_missing counted against"),
                 (c1c2_entry(counters=["cvss_v3_missing"]), "cvss_v3_missing counted against"),
                 (mixed, "a usable vector for some technical impacts and not for others"),
                 (c1c2_entry(cvss="N", pv={"factor": "PV", "answer": "a", "level": 5, "source": "answer"}),
                  "Privacy violation's floor off"),
                 (c1c2_entry(cvss="H", pv={"factor": "PV", "level": 3, "source": "floor", "cvss": "N"}),
                  "Privacy violation's floor off"))
        for e, why in cases:
            got = answers.c1c2(doc(e))
            self.assertEqual(len(got), 1, (why, got))
            self.assertIn(why, got[0])

    def test_a_declared_block_fails_under_any_contract(self):
        relayed = dict(c1c2_entry(), declared={"unreachable": [0], "analysis": STATUS})
        want = f"{A}: a declared block, no contract relaying reachability"
        for pinned in (contract.C1C2, contract.B7C0435, None):
            self.assertIn(want, answers.validate(doc(relayed), pinned), pinned)
        old = s.answers_doc([(A, s.VECTOR)])
        old["vulnerabilities"][0]["declared"] = {}
        self.assertEqual(answers.validate(load(old), None), [want])

    def test_an_unrated_entry_answers_no_impact(self):
        unrated = {"vulnId": B, "unrated": True, "adjustment": "not_asked",
                   "factors": [{"factor": "LC", "answer": "a", "reading": "answered"}]}
        self.assertEqual(answers.c1c2(doc(c1c2_entry(), unrated)),
                         [f"{B}: an unrated entry answering a technical impact"])

    def test_a_vex_status_fails_the_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            vex = s.vex([(A, s.VECTOR, s.SEVERITY, s.SCORE)])
            plain, _ = cdx.ratings(s.write(os.path.join(tmp, "plain.json"), vex))
            vex["vulnerabilities"][0]["analysis"] = STATUS
            published, problems = cdx.ratings(s.write(os.path.join(tmp, "status.json"), vex))
            vex["vulnerabilities"][0]["analysis"] = "not_affected"
            _, bad = cdx.ratings(s.write(os.path.join(tmp, "bad.json"), vex))
        self.assertEqual((plain[A]["analysis"], published[A]["analysis"], problems), (None, STATUS, []))
        self.assertEqual(bad, [f"{A}: analysis 'not_affected' is not an object"])
        rated = load(s.answers_doc([(A, s.VECTOR)]))
        self.assertEqual(answers.check(rated, plain), [])
        self.assertEqual(answers.check(rated, published), [f"{A}: the VEX publishes a status, not_affected"])


MODEL = f"c1 · openai/{s.MODEL}"
# reach_no's CVE (C:H/I:H/A:H, data critical) on GIVEN's answers.
VEC = "SL:9/M:4/O:7/S:9/ED:9/EE:3/A:9/ID:9/LC:7/LI:7/LAV:7/LAC:9/FD:9/RD:1/NC:2/PV:5"
GIVEN = {"M": "possible_reward", "O": "some_access_or_resources_required", "EE": "difficult", "LAC": "unidentified",
         "FD": "bankruptcy", "RD": "minimal_damage", "PV": "hundreds"}
NOTES = verdicts.NOTES


def scen_run(arm, sid, replicate, vec=VEC, c1c2=True):
    """A run of one scenario and, for the after, answers.json under C1 + C2 (impacts from cvss) or b7c0435."""
    answers_ = None
    if arm == "after":
        given = {f: (GIVEN[f], "answer") for f in GIVEN}
        if c1c2:
            given.update({f: (None, "cvss") for f in contract.AXIS})
        answers_ = {A: r.factors(vec, **given)}
    return r.record(arm, sid, replicate, {A: r.rating(vec, arm)}, scenario=True, answers=answers_)


class TestTheFamilies(unittest.TestCase):
    """The checks under the pinned contract: what the notes alone may move as diagnostics, showcase_med_to_high's
    high or critical carried under read5's eligibility rule, the rows certified against the pinned contract."""

    SIDS = ("reach_no", "reach_yes", "showcase_high_to_low", "showcase_med_to_high")

    @classmethod
    def setUpClass(cls):
        cls.scen = verdicts.load(SCENARIOS)

    def runs(self, c1c2=True, replicates=(1, 2)):
        return [scen_run(arm, sid, rep, c1c2=c1c2) for rep in replicates for sid in self.SIDS
                for arm in ("before", "after")]

    def rows(self, recs, rules=contract.C1C2):
        return families.evaluate(cellmod.group(recs), self.scen, rules=rules)

    def test_the_notes_alone_and_the_carried_showcase(self):
        rows = self.rows(self.runs())
        self.assertEqual({x["rules"] for x in rows}, {contract.C1C2})
        self.assertTrue(all(x["certified"] for x in rows))
        kinds = {(x["check"].label, x["arm"]): x["kind"] for x in rows if x["check"].family in ("showcases",
                                                                                                "reachability")}
        self.assertEqual(kinds[("showcase_high_to_low low" + NOTES, "after")], verdicts.DIAGNOSTIC)
        self.assertEqual(kinds[("the score above the unreachable one's by more than 0.5" + NOTES, "after")],
                         verdicts.DIAGNOSTIC)
        self.assertEqual((kinds[("showcase_med_to_high high or critical", "before")],
                          kinds[("showcase_med_to_high high or critical", "after")]), (verdicts.CARRIED,) * 2)
        self.assertNotIn("showcase_high_to_low low", {x["check"].label for x in rows})

    def test_read5s_rule_reads_the_carried_showcase(self):
        rows = self.rows(self.runs())
        g = families.gates(rows)
        self.assertEqual(g[("showcases", "showcase_med_to_high high or critical", "showcase_med_to_high", MODEL)],
                         (1.0, 0.0, "pass"))
        self.assertFalse([k for k in g if k[0] == "reachability"])
        text = "\n".join(report_scen.families_section({"rows": rows, "moves": {}, "rules": contract.C1C2,
                                                        "implementation": {}}))
        self.assertIn("- showcase_med_to_high high or critical · showcase_med_to_high · " + MODEL
                      + ": the before passes 1.00, the after fails 0.00: pass.", text)
        self.assertEqual(text.count("Withdrawn, not met (plan Z0d): #333's expected low for showcase_high_to_low; "
                                    "step 1's reachability contract"), 2)
        self.assertIn("Implementation checks (plan Z0, every replicate; binding): 0 pass, 0 fail, 0 inconclusive",
                      text)

    def test_historical_runs_keep_their_rules(self):
        rows = self.rows(self.runs(c1c2=False), contract.B7C0435)
        self.assertEqual({x["rules"] for x in rows}, {contract.B7C0435})
        self.assertTrue(all(x["certified"] for x in rows))
        self.assertIn("showcase_high_to_low low", {x["check"].label for x in rows})
        self.assertNotIn("Withdrawn, not met", "\n".join(report_scen.families_section({"rows": rows, "moves": {}})))

    def test_the_pinned_rules_choose_the_checks_never_the_runs(self):
        rows = self.rows(self.runs(c1c2=False))
        self.assertIn("showcase_high_to_low low" + NOTES, {x["check"].label for x in rows})
        self.assertEqual({x["certified"] for x in rows if x["arm"] == "after"}, {False})
        rows = self.rows(self.runs(), contract.B7C0435)
        self.assertEqual({x["certified"] for x in rows if x["arm"] == "after"}, {False})
        before = [x for x in self.runs() if x["what"]["arm"] == "before"]
        self.assertNotIn("showcase_high_to_low low", {x["check"].label for x in self.rows(before)})

    def test_a_vectorless_scenario_is_tagged(self):
        recs = [scen_run(arm, sid, 1) for arm in ("before", "after") for sid in ("disc_dos", "disc_dos_novec")]
        rows = self.rows(recs)
        tags = {x["row"]["item"]: x["vectorless"] for x in rows}
        self.assertEqual((tags["disc_dos"], tags["disc_dos_novec"]), (False, True))
        self.assertIn("disc_dos_novec [vectorless]",
                      "\n".join(report_scen.families_section({"rows": rows, "moves": {}})))


class TestTheChecks(unittest.TestCase):
    """CHECKS_C1C2 under no relay."""

    def test_the_c1c2_check_set(self):
        quantities = {c.quantity for c in verdicts.CHECKS_C1C2}
        self.assertFalse(quantities & {"LC", "LI", "LAV", "answer LC", "answer LI", "answer LAV", "status", "rating"})
        changed = {(c.family, c.label, c.kinds) for c in verdicts.CHECKS_C1C2 if c not in verdicts.CHECKS}
        self.assertEqual(changed, {
            ("showcases", "showcase_high_to_low low" + NOTES, verdicts.BOTH(verdicts.DIAGNOSTIC)),
            ("reachability", "the score above the unreachable one's by more than 0.5" + NOTES,
             verdicts.BOTH(verdicts.DIAGNOSTIC)),
            ("reachability", "O, unreachable at most reachable" + NOTES, verdicts.AFTER(verdicts.DIAGNOSTIC)),
            ("reachability", "EE, unreachable at most reachable" + NOTES, verdicts.AFTER(verdicts.DIAGNOSTIC))})
        (med,) = [c for c in verdicts.CHECKS_C1C2 if c.label == "showcase_med_to_high high or critical"]
        self.assertIn(med, verdicts.CHECKS)
        self.assertEqual(med.kinds, verdicts.BOTH(verdicts.CARRIED))
        self.assertEqual(verdicts.checks_for(contract.C1C2), verdicts.CHECKS_C1C2)
        self.assertEqual(verdicts.checks_for(contract.REACH_RULES), verdicts.CHECKS)


def config(sid):
    with open(os.path.join(SCENARIOS, sid, "config.yaml"), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


class TestTheCorpus(unittest.TestCase):
    """Step 5's corpus, which declares no reachability (plan Z0d): no config holds a reachability key."""

    def test_step_5s_corpus(self):
        self.assertEqual([sid for sid in IDS if "reachability" in config(sid)], [])
        self.assertEqual(campaign.FROZEN, "4f4b86ade2e1c464142728d5c68a3c86ede2db21c47a4a5b64aadf19c44232a1")


if __name__ == "__main__":
    unittest.main()
