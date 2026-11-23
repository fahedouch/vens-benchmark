"""C1 + C2', the candidate C2''s one-shot screen kept (plan Z0d section 2), as the chain mirrors vens 310-c1c2 at the
C2' commit (contract.C2P_COMMIT), on synthetic inputs: Loss of availability crossed with availability_requirement, unset
reading primary with its counter; answers.json against the pinned contract, both ways; the families, the checks and
the gate under c1c2p; the counter totals and the reading against the commit's own contract (the mirror review's M1, M1+
and M2); the impact-provenance marker its commit alone writes (M3, M3+). No vens is run:
tests/test_c1c2_mock.py runs these rules against the C2' commit's mock."""
import contextlib
import os
import tempfile
import unittest
from unittest import mock

import ctx_analyze
from chain import answers, attempt, cdx, conform, contract, families, report_scen, verdicts
from chain import cells as cellmod
from tests import records as r
from tests import support as s
from tests.test_c1c2 import DEP, SCENARIOS, c1c2_entry, doc, impact_of, load, scen_run
from tests.test_c1c2_gate import GIVEN, corpus_copy

A, B, C = "CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"
AR, VM = "availability_requirement_missing", "cvss_v3_missing"
PROVENANCE, CVSS_V3, FALLBACK = "vens:impact-provenance", "cvss-v3", "missing-cvss-v3-fallback"
# z8_replay.py's C2P_LAV and PRIMARY (step5c-screens, frozen by freeze-z8.sha256): (secondary, primary) per worst A.
Z8_LAV = {"N": (1, 1), "L": (1, 5), "H": (5, 7)}
Z8_PRIMARY = {"low": False, "medium": False, "high": True, "critical": True}
REQUIREMENTS = ("low", "medium", "high", "critical", None)


def dep_with(requirement):
    return dict(DEP, availability_requirement=requirement)


def primary(requirement):
    return requirement is None or Z8_PRIMARY[requirement]


def context(**ctx):
    return {"context": {"exposure": "internet", "data_sensitivity": "low", **ctx}}


class TestTheTable(unittest.TestCase):
    """C2''s table and cut, z8_replay.py's, and the field as vens loads it."""

    def test_the_table_is_z8s(self):
        self.assertEqual(contract.C2P_LAV, Z8_LAV)
        self.assertEqual(contract.PRIMARY_SERVICES, Z8_PRIMARY)
        # the primary column is C2's: a declared high or critical requirement changes nothing
        self.assertEqual({v: p for v, (_, p) in contract.C2P_LAV.items()}, contract.C2_LAV)

    def test_lav_by_availability_requirement(self):
        for requirement in REQUIREMENTS:
            dep = dep_with(requirement)
            for value in ("N", "L", "H"):
                imp = impact_of(f"C:{value}/I:{value}/A:{value}")
                c2p = {f: contract.c1c2_options(f, dep, imp, rules=contract.C1C2P) for f in contract.AXIS}
                c2 = {f: contract.c1c2_options(f, dep, imp) for f in contract.AXIS}
                self.assertEqual(c2p["LAV"], {None: Z8_LAV[value][primary(requirement)]}, (requirement, value))
                self.assertEqual((c2p["LC"], c2p["LI"]), (c2["LC"], c2["LI"]), (requirement, value))
                self.assertEqual(c2["LAV"], {None: contract.C2_LAV[value]}, (requirement, value))
                self.assertEqual(contract.c1c2_source("LAV", dep, imp), "cvss")
            for rules in contract.C1C2_RULES:
                self.assertEqual(contract.impact_level("LAV", dep, contract.NO_IMPACT_READ, rules), 9)
        # a deployment read without the key is unset: primary
        self.assertEqual(contract.impact_level("LAV", DEP, impact_of("C:L/I:L/A:L"), contract.C1C2P), 5)

    def test_the_field_as_vens_loads_it(self):
        cases = ((context(), None), (context(availability_requirement=None), None),
                 (context(availability_requirement="low"), "low"), (context(availability_requirement=" High "), "high"),
                 (context(availability_requirement="CRITICAL"), "critical"),
                 (context(availability_requirement=" medium\n"), "medium"))
        for config, want in cases:
            self.assertEqual(contract.deployment(config)["availability_requirement"], want, config)
        for value in ("", "urgent", "\x1chigh", 3, ["high"]):
            with self.assertRaisesRegex(ValueError, "availability_requirement"):
                contract.deployment(context(availability_requirement=value))

    def test_the_counters(self):
        vectored, vectorless = impact_of("C:H/I:H/A:L"), contract.NO_IMPACT_READ
        for requirement in REQUIREMENTS:
            dep = dep_with(requirement)
            self.assertEqual(contract.c1c2_counters(dep, vectorless, contract.C1C2P), ["cvss_v3_missing"])
            self.assertEqual(contract.c1c2_counters(dep, vectorless, contract.C1C2), ["cvss_v3_missing"])
            self.assertEqual(contract.c1c2_counters(dep, vectored, contract.C1C2P), [AR] if requirement is None else [])
            self.assertEqual(contract.c1c2_counters(dep, vectored, contract.C1C2), [])

    def test_only_lav_moves(self):
        imp, given = impact_of("C:H/I:L/A:H"), {"M": "possible_reward", "PV": "thousands"}
        for requirement in REQUIREMENTS:
            dep = dep_with(requirement)
            c2 = contract.c1c2_levels(dep, imp, True, given)
            c2p = contract.c1c2_levels(dep, imp, True, given, rules=contract.C1C2P)
            self.assertEqual({f: x for f, x in c2p.items() if c2[f] != x},
                             {} if primary(requirement) else {"LAV": (5, "cvss")}, requirement)


def c2p_entry(vid=A, cvss="H", lav=None, counters=()):
    """A rated answers.json entry, as c1c2_entry, its Loss of availability at lav (C2''s secondary column by
    default)."""
    e = c1c2_entry(vid, cvss, counters)
    (x,) = [f for f in e["factors"] if f["factor"] == "LAV"]
    x["level"] = contract.C2P_LAV[cvss][0] if lav is None else lav
    return e


class TestTheRecord(unittest.TestCase):
    """answers.json under C1 + C2' as the reader checks it: what C2' shows, the pinned contract both ways."""

    def test_what_a_record_shows(self):
        secondary, counted, plain = c2p_entry(A, "H"), c1c2_entry(B, "L", counters=[AR]), c1c2_entry(C, "N")
        self.assertEqual([answers.marks(doc(e)) for e in (secondary, counted, plain, c2p_entry(C, "N"))],
                         [{contract.C1C2P}, {contract.C1C2P}, {contract.C1C2}, {contract.C1C2}])
        # a record C2 could give, beside one only C2' gives, is C2''s: the run is one
        self.assertEqual(answers.marks(doc(secondary, plain)), {contract.C1C2P})
        self.assertEqual(answers.rules_of(doc(secondary, plain)), contract.C1C2P)

    def test_the_pinned_contract_both_ways(self):
        secondary, counted, plain = c2p_entry(A, "H"), c1c2_entry(B, "L", counters=[AR]), c1c2_entry(C, "N")
        old = load(s.answers_doc([(A, s.VECTOR)]))
        for d in (doc(secondary, counted, plain), doc(plain), doc(c1c2_entry(A, None, counters=["cvss_v3_missing"]))):
            self.assertEqual(answers.validate(d, contract.C1C2P), [])
        self.assertEqual(answers.validate(doc(secondary, plain), None), [])
        for d in (doc(secondary), doc(counted), doc(secondary, plain)):
            self.assertEqual(answers.validate(d, contract.C1C2), ["answers.json follows c1c2p, not the pinned c1c2"])
            self.assertEqual(answers.validate(d, contract.B7C0435),
                             ["answers.json follows c1c2p, not the pinned b7c0435"])
        self.assertEqual(answers.validate(old, contract.C1C2P), ["answers.json follows b7c0435, not the pinned c1c2p"])
        reach = {**old["vulnerabilities"][0], "reachability": {"factor": "R", "answer": "reachable"}}
        self.assertEqual(answers.validate(doc(reach, c2p_entry(B)), contract.C1C2P),
                         ["answers.json mixes contracts: 5f797bf, c1c2p"])

    def test_lav_and_the_counter_off_c2p(self):
        cases = ((c2p_entry(A, "H", lav=3), "LAV at 3 from cvss 'H'"),
                 (c2p_entry(A, "L", lav=7), "LAV at 7 from cvss 'L'"),
                 (c1c2_entry(A, None, counters=["cvss_v3_missing", AR]), f"{AR} counted without a usable vector"),
                 (c2p_entry(A, "H", counters=[AR]), f"{AR} counted, LAV at 5 off the primary column"),
                 (c1c2_entry(A, "H", counters=[AR, AR]), f"{AR} counted 2 times"))
        for e, why in cases:
            got = answers.c1c2(doc(e), contract.C1C2P)
            self.assertEqual(len(got), 1, (why, got))
            self.assertIn(why, got[0])
        self.assertEqual(answers.c1c2(doc(c1c2_entry(A, "H", counters=[AR])), contract.C1C2),
                         [f"{A}: {AR} counted, C2 reads no availability_requirement",
                          f"{AR} in the totals, C2 reads no availability_requirement"])
        self.assertEqual(answers.c1c2(doc(c2p_entry(A, "H")), contract.C1C2), [f"{A}: LAV at 5 from cvss 'H'"])


class TestThePins(unittest.TestCase):
    """N and the C2' commit, each pinning its contract; 2de5d34, which relayed, none."""

    def rules(self, *argv):
        return ctx_analyze.pinned_rules(ctx_analyze.parse(list(argv) + ["dir"]))

    def test_the_commits(self):
        self.assertEqual(contract.N_COMMIT, "33a5dbf2ae8d7a6522874058de659e1b58f422aa")
        self.assertEqual(len(contract.C2P_COMMIT), 40)
        self.assertEqual({sha: contract.CONTRACTS.get(sha) for sha in (contract.N_COMMIT, contract.C2P_COMMIT,
                                                                       s.RELAY_SHA)},
                         {contract.N_COMMIT: contract.C1C2, contract.C2P_COMMIT: contract.C1C2P, s.RELAY_SHA: None})
        self.assertEqual((s.C1C2_SHA, s.C1C2P_SHA), (contract.N_COMMIT, contract.C2P_COMMIT))
        self.assertEqual(attempt.pinned_contract({"arm": "after", "vens_commit": contract.C2P_COMMIT}), contract.C1C2P)
        self.assertEqual(attempt.pinned_contract({"arm": "after", "vens_commit": contract.N_COMMIT}), contract.C1C2)

    def test_the_reading_pins_c1c2p(self):
        self.assertEqual(self.rules("--rules", "c1c2p"), contract.C1C2P)
        self.assertEqual(self.rules("--commit", f"after={contract.C2P_COMMIT}"), contract.C1C2P)
        self.assertEqual(self.rules("--commit", f"after={contract.N_COMMIT}"), contract.C1C2)
        self.assertIsNone(self.rules("--commit", f"after={s.RELAY_SHA}"))
        with self.assertRaisesRegex(ctx_analyze.InputError, "--rules c1c2p, but --commit after= pins c1c2$"):
            self.rules("--rules", "c1c2p", "--commit", f"after={contract.N_COMMIT}")
        with self.assertRaisesRegex(ctx_analyze.InputError, "--rules c1c2, but --commit after= pins c1c2p"):
            self.rules("--rules", "c1c2", "--commit", f"after={contract.C2P_COMMIT}")


def shown_c2p(rec):
    """The record with every after CVE counting availability_requirement_missing, as C2' shows an unset field."""
    for e in ((rec.get("answers") or {}).get("per_cve") or {}).values():
        e["counters"] = [AR]
    return rec


class TestTheFamilies(unittest.TestCase):
    """The no-relay checks under c1c2p; a row certified on the runs C1 + C2' can give."""

    SIDS = ("reach_no", "reach_yes", "showcase_high_to_low", "showcase_med_to_high")

    @classmethod
    def setUpClass(cls):
        cls.scen = verdicts.load(SCENARIOS, contract.C1C2P)

    def runs(self, c2p):
        recs = [scen_run(arm, sid, rep) for rep in (1, 2) for sid in self.SIDS for arm in ("before", "after")]
        return [shown_c2p(x) if c2p else x for x in recs]

    def rows(self, recs, rules):
        return families.evaluate(cellmod.group(recs), self.scen, rules=rules)

    def test_the_contract_a_run_shows(self):
        plain, c2p = (scen_run("after", "reach_no", 1), shown_c2p(scen_run("after", "reach_no", 1)))
        self.assertEqual((families.run_rules(plain), families.run_rules(c2p)), (contract.C1C2, contract.C1C2P))
        lav = scen_run("after", "reach_no", 1)
        lav["answers"]["per_cve"][A]["factors"]["LAV"].update(cvss="L", level=1)
        self.assertEqual(families.run_rules(lav), contract.C1C2P)

    def test_certified_on_what_c2p_can_give(self):
        for c2p in (False, True):
            rows = self.rows(self.runs(c2p), contract.C1C2P)
            self.assertEqual({x["rules"] for x in rows}, {contract.C1C2P})
            self.assertTrue(all(x["certified"] for x in rows), c2p)
        rows = self.rows(self.runs(True), contract.C1C2)
        self.assertEqual({x["certified"] for x in rows if x["arm"] == "after"}, {False})
        self.assertEqual(verdicts.checks_for(contract.C1C2P), verdicts.CHECKS_C1C2)

    def test_step_5s_corpus_reads_the_same_under_c2p(self):
        # its configs declare availability_requirement high or nothing: the primary column, C2's
        self.assertEqual({sc["dep"]["availability_requirement"] for sc in self.scen.values()}, {"high", None})
        for sid, sc in self.scen.items():
            for f in cdx.FACTORS:
                args = (f, sc["dep"], sc["impact"], sc["described"])
                self.assertEqual(contract.c1c2_options(*args, rules=contract.C1C2P), contract.c1c2_options(*args),
                                 (sid, f))

    def test_the_report_names_the_contract(self):
        rows = self.rows(self.runs(True), contract.C1C2P)
        text = "\n".join(report_scen.families_section({"rows": rows, "moves": {}, "rules": contract.C1C2P,
                                                        "implementation": {}}))
        self.assertIn("Under C1 + C2' (rules c1c2p, no reachability relay), each after scenario", text)
        self.assertEqual(text.count("Withdrawn, not met (plan Z0d): #333's expected low"), 2)


def published(sid, scen, counters=None, replicate=1, commit=contract.C2P_COMMIT, provenance=()):
    """One after run of a scenario as the C2' commit publishes it on GIVEN's answers, at commit, its VEX carrying the
    provenance values given."""
    sc = scen[sid]
    got = contract.c1c2_levels(sc["dep"], sc["impact"], sc["described"], GIVEN, rules=contract.C1C2P)
    vec = "/".join(f"{f}:{got[f][0]}" for f in cdx.FACTORS)
    given = {f: (GIVEN.get(f), "answer") for f in cdx.FACTORS}
    rating = dict(r.rating(vec), provenance=list(provenance))
    rec = r.record("after", sid, replicate, {sc["vuln_id"]: rating}, scenario=True,
                   answers={sc["vuln_id"]: r.factors(vec, **given)}, commit=commit)
    entry = rec["answers"]["per_cve"][sc["vuln_id"]]
    entry["counters"] = contract.c1c2_counters(sc["dep"], sc["impact"], contract.C1C2P) if counters is None \
        else counters
    return rec


class TestTheGate(unittest.TestCase):
    """chain/conform.py under c1c2p: Loss of availability by the run's own config, the counter recomputed."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = corpus_copy(cls.tmp.name, {})
        path = os.path.join(root, "reach_no", "config.yaml")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        s.write(path, text.replace("context:\n", "context:\n  availability_requirement: low\n", 1))
        cls.scen = verdicts.load(root, contract.C1C2P)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def problems(self, rec, sid, rules=contract.C1C2P):
        sc = self.scen[sid]
        return conform.run_problems(rec, sc["config"], {sc["vuln_id"]: sc["findings"]}, rules)

    def test_runs_as_the_c2p_commit_publishes_them(self):
        self.assertEqual(self.scen["reach_no"]["dep"]["availability_requirement"], "low")
        self.assertEqual(self.scen["reach_yes"]["dep"]["availability_requirement"], None)
        for sid in ("reach_no", "reach_yes", "disc_dos", "disc_dos_novec"):
            self.assertEqual(self.problems(published(sid, self.scen), sid), [], sid)
        self.assertEqual(published("reach_yes", self.scen)["answers"]["per_cve"][A]["counters"], [AR])
        got = conform.read(cellmod.group([published(sid, self.scen) for sid in ("reach_no", "reach_yes")]),
                           self.scen, None, contract.C1C2P)
        self.assertEqual({c["verdict"] for c in got.values()}, {"pass"})

    def test_lav_by_the_config(self):
        rec = published("reach_no", self.scen)
        self.assertEqual(rec["ratings"][A]["levels"]["LAV"], 5)
        (got,) = self.problems(rec, "reach_no", contract.C1C2)
        self.assertTrue(got.startswith(f"{A}: LAV 5 not 7, vector "), got)

    def test_the_counter_recomputed(self):
        for sid, counters, want in (
                ("reach_yes", [], f"{AR} counted 0 times, not 1"),
                ("reach_no", [AR], f"{AR} counted 1 times, not 0"),
                ("disc_dos_novec", ["cvss_v3_missing", AR], f"{AR} counted 1 times, not 0"),
                ("disc_dos_novec", [], "cvss_v3_missing counted 0 times, not 1")):
            vid = self.scen[sid]["vuln_id"]
            self.assertEqual(self.problems(published(sid, self.scen, counters), sid), [f"{vid}: {want}"], sid)
        # under c1c2, never counted
        self.assertEqual(self.problems(published("reach_yes", self.scen), "reach_yes", contract.C1C2),
                         [f"{A}: {AR} counted 1 times, not 0"])

    def test_the_report_names_the_contract(self):
        got = conform.read(cellmod.group([published("reach_yes", self.scen, [])]), self.scen, None, contract.C1C2P)
        gate = conform.failures(got)
        text = "\n".join(report_scen.c2_reads({"implementation": got, "gate": gate, "rules": contract.C1C2P}))
        self.assertIn("## C1 + C2' recomputed on every after run", text)
        self.assertIn("The after's contract pinned: c1c2p, no reachability relay.", text)
        self.assertIn("C1 + C2''s implementation gate: 1 failure(s), no go.", text)


def unrated(vid=B, counters=()):
    return {"vulnId": vid, "unrated": True, "adjustment": "not_asked",
            "factors": [{"factor": "M", "answer": "a", "reading": "answered"}], "counters": list(counters)}


class TestTheCounterTotals(unittest.TestCase):
    """M1 and M1+: availability_requirement_missing nowhere under c1c2, no C2 counter on an unrated entry, and each
    C2 counter's total its entries' sum, omission read as zero."""

    def test_the_counter_only_in_the_totals(self):
        bypass = doc(c1c2_entry(A, "H"), counters={AR: 1})
        for pinned in (contract.C1C2, None):
            self.assertEqual(sorted(answers.validate(bypass, pinned)),
                             [f"{AR} in the totals, C2 reads no availability_requirement",
                              f"{AR} totals 1, its entries count 0"], pinned)
        self.assertEqual(answers.validate(bypass, contract.C1C2P), [f"{AR} totals 1, its entries count 0"])

    def test_a_c2_counter_on_an_unrated_entry(self):
        for name in (AR, VM):
            for pinned in contract.C1C2_RULES:
                totals = [f"{AR} in the totals, C2 reads no availability_requirement"] \
                    if (name, pinned) == (AR, contract.C1C2) else []
                self.assertEqual(answers.validate(doc(c1c2_entry(A, "H"), unrated(counters=[name])), pinned),
                                 [f"{B}: an unrated entry counting {name}"] + totals, (name, pinned))
        # the counters an unrated entry does keep: cannot_tell's and reasoning_missing
        kept = unrated(counters=["motive_cannot_tell", "reasoning_missing"])
        self.assertEqual(answers.validate(doc(c1c2_entry(A, "H"), kept), contract.C1C2), [])

    def test_each_total_against_its_entries(self):
        vectorless, counted = c1c2_entry(A, None, counters=[VM]), c1c2_entry(B, "H", counters=[AR])
        for pinned in contract.C1C2_RULES:
            self.assertEqual(answers.validate(doc(vectorless), pinned), [])
            self.assertEqual(answers.validate(doc(vectorless, counters={}), pinned),
                             [f"{VM} totals 0, its entries count 1"])
            self.assertEqual(answers.validate(doc(vectorless, counters={VM: 2, AR: 0}), pinned),
                             [f"{VM} totals 2, its entries count 1"])
        self.assertEqual(answers.validate(doc(vectorless, counted), contract.C1C2P), [])
        self.assertEqual(answers.validate(doc(vectorless, counted, counters={VM: 1}), contract.C1C2P),
                         [f"{AR} totals 0, its entries count 1"])


def baseline_run(root, commit, entry):
    """A baseline.yml download at commit whose answers.json holds entry, its VEX the entry's levels."""
    vec = "/".join(f"{x['factor']}:{x['level']}" for x in entry["factors"])
    folder = s.baseline_folder(root, 1000, "internal", 1, 1, record=s.COMPLETE_RECORD, commit=commit)
    s.write(os.path.join(folder, "vex-internal.cdx.json"), s.vex([(A, vec, "high", 30.0)]))
    s.write(os.path.join(folder, "calls", "run-1", "answers.json"),
            {"vulnerabilities": [entry], "counters": {}, "defects": {}})
    return folder


class TestTheReadingAgainstTheCommit(unittest.TestCase):
    """M2: a reading whose pinned contract is not the one the run's own commit pins refuses the run."""

    def test_n_read_under_c1c2p(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = baseline_run(tmp, contract.N_COMMIT, c1c2_entry(A, "H"))
            plain, own, other = (attempt.read_attempt(folder, rules=x) for x in (None, contract.C1C2, contract.C1C2P))
        self.assertEqual([x["answers"]["problems"] for x in (plain, own)], [[], []])
        self.assertEqual(other["answers"]["problems"],
                         [f"the reading pins c1c2p, vens {contract.N_COMMIT} pins c1c2"])
        self.assertEqual([x["scores_usable"] for x in (plain, own, other)], [True, True, False])

    def test_a_commit_that_pins_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = baseline_run(tmp, s.RELAY_SHA, c1c2_entry(A, "H"))
            got = attempt.read_attempt(folder, rules=contract.C1C2P)
        self.assertEqual((got["answers"]["problems"], got["scores_usable"]), ([], True))


MARK = "f" * 40


@contextlib.contextmanager
def marker_at(sha):
    """The marker commit set to sha for a test, CONTRACTS pinning it to c1c2p."""
    with mock.patch.object(contract, "MARKER_COMMIT", sha), mock.patch.dict(contract.CONTRACTS, {sha: contract.C1C2P}):
        yield


class TestTheMarker(unittest.TestCase):
    """M3 and M3+: the vens:impact-provenance property, required of the marker commit's runs alone, one per CVE,
    missing-cvss-v3-fallback exactly where the report gives no usable v3 vector and the entry counts cvss_v3_missing;
    any other commit's runs carry none. Most cases run on a stand-in SHA, MARK, set as the marker commit."""

    @classmethod
    def setUpClass(cls):
        cls.scen = verdicts.load(SCENARIOS, contract.C1C2P)

    def problems(self, rec, sid, rules=contract.C1C2P):
        sc = self.scen[sid]
        return conform.run_problems(rec, sc["config"], {sc["vuln_id"]: sc["findings"]}, rules)

    def test_the_marker_commits_pin(self):
        mark = contract.MARKER_COMMIT
        self.assertEqual((len(mark), contract.CONTRACTS[mark]), (40, contract.C1C2P))
        self.assertEqual(attempt.pinned_contract({"arm": "after", "vens_commit": mark}), contract.C1C2P)
        self.assertEqual([contract.marker_commit(x) for x in (mark, contract.C2P_COMMIT, None)], [True, False, False])
        # a run of any other commit, pinned or not, carrying the marker is refused
        for commit in (MARK, contract.C2P_COMMIT):
            self.assertEqual(self.problems(published("reach_yes", self.scen, commit=commit, provenance=[CVSS_V3]),
                                           "reach_yes"),
                             [f"{A}: {PROVENANCE} published, vens {commit[:12]} writes no marker"], commit)
        self.assertEqual(self.problems(published("reach_yes", self.scen, commit=mark, provenance=[CVSS_V3]),
                                       "reach_yes"), [])

    def test_the_vex_property(self):
        vex = s.vex([(A, s.VECTOR, s.SEVERITY, s.SCORE), (B, s.VECTOR, s.SEVERITY, s.SCORE),
                     (C, s.VECTOR, s.SEVERITY, s.SCORE)])
        vex["vulnerabilities"][0]["properties"] = [{"name": PROVENANCE, "value": CVSS_V3}, {"name": "x", "value": "y"}]
        vex["vulnerabilities"][2]["properties"] = "cvss-v3"
        with tempfile.TemporaryDirectory() as tmp:
            got, problems = cdx.ratings(s.write(os.path.join(tmp, "vex.json"), vex))
        self.assertEqual({vid: x["provenance"] for vid, x in got.items()}, {A: [CVSS_V3], B: [], C: []})
        self.assertEqual(problems, [f"{C}: properties 'cvss-v3' is not a list of objects"])

    def test_other_commits_carry_none(self):
        # disc_dos declares availability_requirement high: the same record under either contract
        vid = self.scen["disc_dos"]["vuln_id"]
        for commit, rules in ((contract.C2P_COMMIT, contract.C1C2P), (contract.N_COMMIT, contract.C1C2)):
            with self.subTest(commit=commit):
                with marker_at(MARK):
                    plain = published("disc_dos", self.scen, commit=commit)
                    self.assertEqual(self.problems(plain, "disc_dos", rules), [])
                    marked = published("disc_dos", self.scen, commit=commit, provenance=[CVSS_V3])
                    self.assertEqual(self.problems(marked, "disc_dos", rules),
                                     [f"{vid}: {PROVENANCE} published, vens {commit[:12]} writes no marker"])

    def test_the_marker_commits_runs(self):
        novec = self.scen["disc_dos_novec"]["vuln_id"]
        with marker_at(MARK):
            self.assertEqual(attempt.pinned_contract({"arm": "after", "vens_commit": MARK}), contract.C1C2P)
            self.assertTrue(contract.marker_commit(MARK))
            for sid, value in (("reach_yes", CVSS_V3), ("disc_dos_novec", FALLBACK)):
                ok = published(sid, self.scen, commit=MARK, provenance=[value])
                self.assertEqual(self.problems(ok, sid), [], sid)
            cases = (("reach_yes", [], None, f"{A}: 0 {PROVENANCE} properties, not one"),
                     ("reach_yes", [CVSS_V3, CVSS_V3], None, f"{A}: 2 {PROVENANCE} properties, not one"),
                     ("reach_yes", [FALLBACK], None, f"{A}: {PROVENANCE} '{FALLBACK}', its report gives '{CVSS_V3}'; "
                                                     f"{A}: {PROVENANCE} '{FALLBACK}' against {VM} counted 0 times"),
                     ("disc_dos_novec", [CVSS_V3], None,
                      f"{novec}: {PROVENANCE} '{CVSS_V3}', its report gives '{FALLBACK}'; "
                      f"{novec}: {PROVENANCE} '{CVSS_V3}' against {VM} counted 1 times"),
                     ("disc_dos_novec", [FALLBACK], [],
                      f"{novec}: {VM} counted 0 times, not 1; {novec}: {PROVENANCE} '{FALLBACK}' against {VM} counted "
                      f"0 times"))
            for sid, values, counters, want in cases:
                rec = published(sid, self.scen, commit=MARK, provenance=values, counters=counters)
                self.assertEqual("; ".join(self.problems(rec, sid)), want, (sid, values))
            # the marker keys on the run's commit, whatever the reading pins
            rec = published("reach_yes", self.scen, commit=MARK)
            got = conform.read(cellmod.group([rec]), self.scen, None, contract.C1C2P)
            self.assertEqual([c["problems"] for c in got.values()], [[f"r1 {A}: 0 {PROVENANCE} properties, not one"]])


if __name__ == "__main__":
    unittest.main()
