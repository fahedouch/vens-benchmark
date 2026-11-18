"""Which verdicts the scenarios can decide (chain.verdicts), and the corpus on vens's mock at both commits: every
config loads, a strict run passes or stops where it must, and the after's rules as chain.contract encodes them give
the levels and sources vens wrote, on every scenario under its declared values and on six scenarios under four other
assignments of G2 to G4. The 45 combinations the corpus-wide check enumerates are not run through Go. No model is
called and vens gets no API key."""
import contextlib
import glob
import io
import itertools
import json
import os
import tempfile
import unittest

import yaml

import make_scenarios as ms
from chain import contract, runvens, venslog, verdicts
from chain.verdicts import AFTER, BOTH, CARRIED, DIAGNOSTIC, NEW, Check
from tests import support as s

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS = os.path.join(ROOT, "scenarios")
IDS = sorted(d for d in os.listdir(SCENARIOS) if os.path.isdir(os.path.join(SCENARIOS, d)))
COPIES = {sid + ms.COPY_SUFFIX for sid in ms.WITHOUT_VECTOR}
NO_VECTOR = "no CVSS vector in the scanner's report"
DETECTION = {c: "not_logged" for c in contract.CHANNELS}


def scenario(sid, ds="high", floors="", trace="none", frameworks=()):
    dep = {"exposure": "internet", "data_sensitivity": ds, "frameworks": tuple(frameworks), "detection": DETECTION,
           "traceability": trace, "data_subjects": "millions"}
    return {"id": sid, "dep": dep, "floors": frozenset(floors), "described": True,
            "null": {"technical_impact": 7, "business_impact": 7}}


class TestTheCheck(unittest.TestCase):
    """The check on synthetic scenarios: no vens needed."""

    def sensitivity(self, floors, reached):
        scen = {"low": scenario("low", ds="low", floors=floors), "high": scenario("high", ds="high", floors=floors)}
        return scen, {("low", "high"): (frozenset(reached), False)}

    def test_it_fails_while_a_carried_or_new_check_has_one_outcome(self):
        # Data sensitivity reaches Motive and Privacy violation alone where the vector floors integrity, as on the
        # corpus: Loss of confidentiality's question does not show it, so T rises with Go's column only.
        scen, reach = self.sensitivity("IA", {"M", "PV"})
        for kind in (CARRIED, NEW):
            c = Check("3", "T not falling", BOTH(kind), (("low", "high"),), "T", "le")
            _, problems = verdicts.check(scen, reach, {("low", "high"): True}, (c,))
            self.assertEqual(problems, [f"3, T not falling, after, low / high: labelled {kind}, pass only"])
            lines, problems = verdicts.report(scen, reach, {("low", "high"): True}, (c,))
            self.assertIn("problems: 1", lines)

    def test_a_diagnostic_with_one_outcome_is_no_problem(self):
        scen, reach = self.sensitivity("IA", {"M", "PV"})
        c = Check("3", "T not falling", BOTH(DIAGNOSTIC), (("low", "high"),), "T", "le")
        rows, problems = verdicts.check(scen, reach, {("low", "high"): True}, (c,))
        self.assertEqual(problems, [])
        self.assertEqual([(arm, res) for _, arm, _, _, res in rows], [("before", (True, True)),
                                                                     ("after", (True, False))])

    def test_both_outcomes_where_the_vector_leaves_integrity_unfloored(self):
        scen, reach = self.sensitivity("A", {"M", "LI", "PV"})
        c = Check("3", "T not falling", BOTH(CARRIED), (("low", "high"),), "T", "le")
        self.assertEqual(verdicts.check(scen, reach, {("low", "high"): True}, (c,))[1], [])

    def test_the_before_holds_an_unchanged_prompt_equal(self):
        scen = {"a": scenario("a"), "b": scenario("b")}
        c = Check("x", "the score not falling", BOTH(CARRIED), (("a", "b"),), "score", "le")
        reach = {("a", "b"): (frozenset(contract.QUESTIONS), True)}
        self.assertEqual(verdicts.check(scen, reach, {("a", "b"): True}, (c,))[1], [])
        _, problems = verdicts.check(scen, reach, {("a", "b"): False}, (c,))
        self.assertEqual(problems, ["x, the score not falling, before, a / b: labelled carried, pass only"])

    def test_an_answer_the_contrast_does_not_reach_is_held_equal(self):
        scen = {"a": scenario("a"), "b": scenario("b")}
        c = Check("x", "EE the same", AFTER(NEW), (("a", "b"),), "EE", "eq")
        self.assertEqual(verdicts.check(scen, {("a", "b"): (frozenset(), False)}, {}, (c,))[1],
                         ["x, EE the same, after, a / b: labelled new, pass only"])
        self.assertEqual(verdicts.check(scen, {("a", "b"): (frozenset({"EE"}), False)}, {}, (c,))[1], [])

    def test_the_scores_range_is_the_brute_forces(self):
        G = contract.GROUPS
        pairs = [(scenario("a", ds="low", floors="I"), scenario("b", ds="critical", floors="C")),
                 (scenario("a", floors="CI", trace="per_individual"), scenario("b", frameworks=("GDPR",)))]
        for (sa, sb), reached in itertools.product(pairs, (frozenset(), frozenset({"M", "EE", "LAC", "FD"}))):
            sums = {}
            for k in ("L", "T", "B"):
                out = {(0, 0)}
                for f in G[k]:
                    ps = verdicts._level_pairs(f, sa, sb, reached, {})
                    out = {(p + x, q + y) for p, q in out for x, y in ps}
                sums[k] = out
            diffs = {l2 * max(t2, b2) - l1 * max(t1, b1) for l1, l2 in sums["L"] for t1, t2 in sums["T"]
                     for b1, b2 in sums["B"]}
            lo, hi = verdicts.score_range(sa, sb, reached)
            self.assertEqual((lo * 32, hi * 32), (min(diffs), max(diffs)))

    def test_the_answer_ids_name_one_question_each(self):
        self.assertEqual(len(set(contract.ANSWER_IDS.values())), len(contract.ANSWER_IDS))
        human = "VULNERABILITIES\n[]\n\nQUESTION\nq?\n\nANSWERS\n" + "".join(
            f"- {a}: text\n" for a in contract.ANSWER_IDS["LAC"]) + "\nAnswer every vulnerability."
        self.assertEqual(contract.question_of(human), "LAC")
        self.assertIsNone(contract.question_of("FLAGGED VULNERABILITY\n{}"))


def find(family, label):
    found = [c for c in verdicts.CHECKS if (c.family, c.label) == (family, label)]
    if len(found) != 1:
        raise AssertionError(f"{family}, {label}: {len(found)} checks")
    return found[0]


# The diagnostics decided for each family, with the arms each reads, and those that read no contrast.
DECIDED = {
    ("1 Exposure", "L not falling"): ("before", "after"),
    ("1 Exposure", "TA not falling"): ("before", "after"),
    ("3 Data sensitivity", "T not falling"): ("after",),
    ("3 Data sensitivity", "LC's extent answer the same"): ("after",),
    ("3 Data sensitivity", "LI not falling"): ("after",),
    ("4 Business criticality", "FD not falling"): ("after",),
    ("4 Business criticality", "RD not falling"): ("after",),
    ("5 Compliance", "B not falling"): ("after",),
    ("5 Compliance", "NC's answer under GDPR, at least Go's 2 without"): ("after",),
    ("5 Compliance", "FD not lower with the framework"): ("after",),
    ("5 Compliance", "RD not lower with the framework"): ("after",),
    ("5 Compliance", "PV not lower with the framework"): ("after",),
    ("6 DoS discriminator", "T below the null model's"): ("after",),
    ("6 DoS discriminator", "LAV's answer"): ("after",),
    ("6 DoS discriminator", "without a vector: T below the null model's"): ("before", "after"),
    ("6 DoS discriminator", "without a vector: LC's extent answer"): ("after",),
    ("6 DoS discriminator", "without a vector: LI's answer"): ("after",),
    ("7 Accountability discriminator", "T above the null model's"): ("before", "after"),
    ("7 Accountability discriminator", "without a vector: T above the null model's"): ("before", "after"),
    ("7 Accountability discriminator", "without a vector: LC's extent answer"): ("after",),
    ("7 Accountability discriminator", "without a vector: LI's answer"): ("after",),
    ("8 Relevant against irrelevant control", "VU, ctrl_on below ctrl_off"): ("before", "after"),
    ("9 DoS, telegraphed or not", "T's drift"): ("before", "after"),
    ("9 DoS, telegraphed or not", "LAV's drift"): ("after",),
    ("9 DoS, telegraphed or not", "without a vector: T's drift"): ("before", "after"),
    ("9 DoS, telegraphed or not", "without a vector: LC's extent answer's drift"): ("after",),
    ("9 DoS, telegraphed or not", "without a vector: LI's drift"): ("after",),
    ("10 Accountability, telegraphed or not", "T's drift"): ("before", "after"),
    ("10 Accountability, telegraphed or not", "LAC's answer's drift"): ("after",),
    ("10 Accountability, telegraphed or not", "without a vector: T's drift"): ("before", "after"),
    ("10 Accountability, telegraphed or not", "without a vector: LC's extent answer's drift"): ("after",),
    ("10 Accountability, telegraphed or not", "without a vector: LI's drift"): ("after",),
    ("11 Irrelevant WAF on the local bug", "VU not lower with the WAF"): ("before", "after"),
}
NAMED = ("consistency", "wrong YAML", "the table against the null model")


class TestTheLabels(unittest.TestCase):
    def test_data_sensitivity_and_compliance_decide_in_the_before_only(self):
        for family, label in (("3 Data sensitivity", "T not falling"), ("5 Compliance", "B not falling")):
            c = find(family, label)
            self.assertEqual((c.kind("before"), c.kind("after")), (CARRIED, DIAGNOSTIC), family)

    def test_every_decided_diagnostic_is_present(self):
        for (family, label), arms in DECIDED.items():
            c = find(family, label)
            self.assertEqual([c.kind(arm) for arm in arms], [DIAGNOSTIC] * len(arms), (family, label))
        # And the other way: no diagnostic in the checks that was not decided.
        present = {(c.family, c.label): tuple(arm for arm, kind in c.kinds if kind == DIAGNOSTIC)
                   for c in verdicts.CHECKS if DIAGNOSTIC in dict(c.kinds).values()}
        self.assertEqual(present, DECIDED)
        self.assertEqual(tuple(d.name for d in verdicts.NAMED), NAMED)

    def test_every_copy_is_read_by_diagnostics_alone(self):
        for copy in sorted(COPIES):
            reading = [c for c in verdicts.CHECKS if any(copy in (i if isinstance(i, tuple) else (i,))
                                                         for i in c.scenarios)]
            self.assertTrue(reading, copy)
            self.assertEqual({k for c in reading for _, k in c.kinds}, {DIAGNOSTIC}, copy)
            self.assertTrue({"answer LC", "LI"} <= {c.quantity for c in reading}, copy)

    def test_the_named_diagnostics_list_each_scenarios_levels_by_source(self):
        lines, _ = verdicts.report(verdicts.load(SCENARIOS), {}, {}, checks=())
        for name in NAMED:
            self.assertTrue(any(line.startswith(f"  {name}: ") for line in lines), name)
        start = lines.index("each scenario's levels in the after by source:")
        self.assertEqual([line.split(":")[0].strip() for line in lines[start + 1:start + 1 + len(IDS)]], IDS)
        self.assertIn("  disc_dos: answer M O EE LAV LAC FD RD; config S ID NC; constant SL ED A; floor LC LI PV",
                      lines[start + 1:])


class TestTheShowcaseCorner(unittest.TestCase):
    """showcase_high_to_low's `low` needs T below 3, B below 3 and L below 6, likelihood never below 4.25."""

    def setUp(self):
        self.s = verdicts.load(SCENARIOS)["showcase_high_to_low"]

    def levels(self, group):
        return [sorted(set(contract.options(f, self.s["dep"], self.s["floors"]).values()))
                for f in contract.GROUPS[group]]

    def test_t_below_3_at_one_set_of_levels(self):
        corner = [lv for lv in itertools.product(*self.levels("T")) if sum(lv) < 12]
        self.assertEqual(corner, [(2, 1, 1, 7)])

    def test_l_below_6_only_where_m_o_ee_s_sum_below_12(self):
        for lv in itertools.product(*self.levels("L")):
            named = dict(zip(contract.GROUPS["L"], lv))
            if sum(lv) < 48:
                self.assertLess(named["M"] + named["O"] + named["EE"] + named["S"], 12)

    def test_low_attainable_in_the_after(self):
        self.assertIn("low", verdicts.after_single("severity", self.s))
        self.assertNotIn("info", verdicts.after_single("severity", self.s))


_CORPUS = {}


def tearDownModule():
    if "tmp" in _CORPUS:
        _CORPUS["tmp"].cleanup()


class MockCorpus(unittest.TestCase):
    """Every scenario on vens's mock: the after, the before, the after with --strict, and the after with every
    answer cannot_tell; run once for the module's classes."""

    @classmethod
    def setUpClass(cls):
        cls.after, cls.before = s.env("VB_VENS_AFTER"), s.env("VB_VENS_BEFORE")
        if cls.after is None or cls.before is None:
            raise unittest.SkipTest("set VB_VENS_AFTER and VB_VENS_BEFORE to vens binaries built from b7c0435 and "
                                    "43ab10b to run the corpus on the mock")
        if not _CORPUS:
            tmp, runs = tempfile.TemporaryDirectory(), {}
            for tag, binary, strict, extra in (("after", cls.after, False, None), ("before", cls.before, False, None),
                                               ("strict", cls.after, True, None),
                                               ("cannot_tell", cls.after, False,
                                                {"VENS_MOCK_LLM_CANNOT_TELL": "cannot_tell"})):
                for sid in IDS:
                    folder = os.path.join(tmp.name, tag, sid)
                    d = os.path.join(SCENARIOS, sid)
                    rec = runvens.generate(binary, os.path.join(d, "config.yaml"), os.path.join(d, "report.json"),
                                           folder, record={"arm": tag}, strict=strict, env_extra=extra)
                    runs[(tag, sid)] = (folder, rec["generate"]["exit_status"],
                                        venslog.read(os.path.join(folder, "vens.log")))
            _CORPUS.update(tmp=tmp, runs=runs)
        cls.runs = _CORPUS["runs"]

    @staticmethod
    def config(sid):
        with open(os.path.join(SCENARIOS, sid, "config.yaml"), encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    def answers(self, tag, sid):
        with open(os.path.join(verdicts.run_dir(self.runs[(tag, sid)][0]), "answers.json"), encoding="utf-8") as fh:
            return json.load(fh)["vulnerabilities"][0]["factors"]


class TestTheCorpusLoads(MockCorpus):
    def test_every_config_loads_in_the_after_with_nothing_undeclared(self):
        for sid in IDS:
            folder, code, recs = self.runs[("after", sid)]
            self.assertEqual(code, 0, sid)
            self.assertFalse([r for r in recs if r["level"] in ("ERROR", "WARN")], sid)
            loaded = [r for r in recs if r["msg"] == "Config loaded"]
            self.assertEqual(len(loaded), 1, sid)
            self.assertEqual((loaded[0]["schema_version"], loaded[0]["listener"], loaded[0]["undeclared"]),
                             ("2", self.config(sid)["context"]["listener"], ""), sid)
            summary = venslog.summary(recs)
            self.assertFalse(summary["failed"], sid)
            # No fallback is counted but a missing vector's, on the ten copies.
            self.assertEqual(summary["counters"], {"applicability_missing": 1} if sid in COPIES else {}, sid)
            self.assertNotIn("adjustment", summary["calls"], sid)

    def test_every_config_loads_in_the_before_listener_included(self):
        listeners = set()
        for sid in IDS:
            _, code, recs = self.runs[("before", sid)]
            self.assertEqual(code, 0, sid)
            self.assertFalse(venslog.summary(recs)["failed"], sid)
            listeners.add(self.config(sid)["context"]["listener"])
        self.assertEqual(listeners, {"present", "absent", "unknown"})

    def test_a_strict_run_passes_on_the_vectored_and_stops_the_copies_at_the_preflight(self):
        for sid in IDS:
            folder, code, recs = self.runs[("strict", sid)]
            vex = os.path.join(folder, "vex.cdx.json")
            if sid in COPIES:
                self.assertEqual(code, 1, sid)
                self.assertIn(NO_VECTOR, venslog.cause(recs), sid)
                self.assertFalse(os.path.exists(vex), sid)
                self.assertFalse(glob.glob(os.path.join(folder, "calls", "run-*", "batch-*")), sid)
                self.assertEqual(venslog.summary(recs)["llm_calls"], 0, sid)
            else:
                self.assertEqual(code, 0, sid)
                self.assertFalse(venslog.summary(recs)["failed"], sid)
                self.assertTrue(os.path.exists(vex), sid)


class TestTheRules(MockCorpus):
    """chain.contract against what the after's mock wrote: each call's question, which questions a CVE is asked,
    and every level of answers.json, cannot_tell's included."""

    def test_the_levels_vens_wrote(self):
        scen = verdicts.load(SCENARIOS)
        for tag, sid in itertools.product(("after", "cannot_tell"), IDS):
            sc = scen[sid]
            for e in self.answers(tag, sid):
                opts = contract.options(e["factor"], sc["dep"], sc["floors"], sc["described"])
                if tag == "cannot_tell" and "answer" in e:
                    self.assertEqual(e["answer"], contract.CANNOT_TELL, (sid, e))
                want = opts.get(e["answer"]) if "answer" in e else opts.get(None)
                self.assertEqual(e["level"], want, (tag, sid, e))
                self.assertEqual(e["source"], contract.source(e["factor"], sc["dep"], sc["floors"], e.get("answer"),
                                                              sc["described"]), (tag, sid, e))

    def test_each_call_asks_the_questions_the_rules_give(self):
        scen = verdicts.load(SCENARIOS)
        for sid in IDS:
            sc = scen[sid]
            asked = [q for q in contract.QUESTIONS if contract.asked(q, sc["dep"], sc["floors"], sc["described"])]
            self.assertEqual(list(verdicts.after_prompts(self.runs[("after", sid)][0])), asked, sid)
            self.assertEqual([e["factor"] for e in self.answers("after", sid) if "answer" in e], asked, sid)


class TestTheVerdicts(MockCorpus):
    """The check on the corpus as written: each check labelled carried or new has a pass and a fail."""

    def setUp(self):
        ids = verdicts.needed()
        self.scen = verdicts.load(SCENARIOS)
        self.reach, self.differs = verdicts.contrasts({i: self.runs[("after", i)][0] for i in ids},
                                                      {i: self.runs[("before", i)][0] for i in ids})

    def outcomes(self, family, label, arm):
        rows, _ = verdicts.check(self.scen, self.reach, self.differs)
        return {item: res for c, a, _, item, res in rows if (c.family, c.label, a) == (family, label, arm)}

    def test_no_carried_or_new_check_has_one_outcome(self):
        lines, problems = verdicts.report(self.scen, self.reach, self.differs)
        self.assertEqual(problems, [], "\n".join(lines))
        rows, _ = verdicts.check(self.scen, self.reach, self.differs)
        decided = [r for r in rows if r[2] in (CARRIED, NEW)]
        self.assertEqual(len(decided), 42)
        self.assertTrue(all(r[4] == (True, True) for r in decided))

    def test_the_diagnostics_the_contrasts_cannot_decide(self):
        for family, label in (("3 Data sensitivity", "T not falling"), ("5 Compliance", "B not falling"),
                              ("6 DoS discriminator", "T below the null model's")):
            self.assertEqual(set(self.outcomes(family, label, "after").values()), {(True, False)}, family)
            # The before's prompts differ in these contrasts: there the check is carried, both outcomes open.
            self.assertEqual(set(self.outcomes(family, label, "before").values()), {(True, True)}, family)
        self.assertEqual(self.reach[("sens_low", "sens_high")], (frozenset({"M", "PV"}), False))
        self.assertEqual(self.reach[("comp_none", "comp_gdpr")], (frozenset({"NC"}), False))
        for pair in verdicts.WAF:
            self.assertEqual(self.reach[pair], (frozenset({"EE"}), False))

    def test_carried_mislabelled_fails_on_the_corpus(self):
        relabelled = tuple(Check(c.family, c.label, BOTH(CARRIED), c.scenarios, c.quantity, c.test)
                           if (c.family, c.label) == ("3 Data sensitivity", "T not falling") else c
                           for c in verdicts.CHECKS)
        _, problems = verdicts.check(self.scen, self.reach, self.differs, relabelled)
        self.assertEqual(problems, [f"3 Data sensitivity, T not falling, after, {a} / {b}: labelled carried, pass only"
                                    for a, b in verdicts.SENS])

    def test_the_corpus_wide_values_change_no_pair_outcome(self):
        self.assertEqual(verdicts.corpus_wide(self.scen, self.reach), [])
        self.assertEqual(verdicts.corpus_wide(self.scen, self.reach, unfloored=True), [])
        for sid, by in verdicts.showcase_by_detection(self.scen).items():
            self.assertEqual(len({tuple(v) for v in by.values()}), 1, (sid, by))

    def test_the_cli(self):
        with tempfile.TemporaryDirectory() as work, contextlib.redirect_stdout(io.StringIO()) as out:
            code = verdicts.main(["--after", self.after, "--before", self.before, "--scenarios", SCENARIOS,
                                  "--work", work])
        self.assertEqual(code, 0, out.getvalue()[-2000:])
        self.assertIn("problems: 0", out.getvalue())



# Values of G2 to G4 the corpus does not declare: three inside the 45 combinations the corpus-wide check reads
# (detection at one level or undeclared, data_subjects above the floor's band) and one outside it (detection levels
# that differ, so Intrusion detection is asked; data_subjects at the floor's band; traceability undeclared).
ALTERNATES = (
    {"detection": "logged_and_reviewed", "traceability": "per_request", "data_subjects": "hundreds"},
    {"detection": "logged", "traceability": "per_individual", "data_subjects": "thousands"},
    {"detection": None, "traceability": "none", "data_subjects": "millions"},
    {"detection": {"network": "logged", "host": "not_logged", "application": "active_in_application"},
     "traceability": None, "data_subjects": "one_individual"},
)
INSIDE = 3
SAMPLE = ("expo_internet", "sens_low", "comp_gdpr", "disc_audit", "showcase_high_to_low", "disc_dos_novec")


def alternate(sid, values):
    with open(os.path.join(SCENARIOS, sid, "config.yaml"), encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    for key, value in values.items():
        if value is None:
            cfg["context"].pop(key, None)
        else:
            cfg["context"][key] = {c: value for c in contract.CHANNELS} if key == "detection" and isinstance(
                value, str) else value
    return cfg


def expected_level(e, opts):
    if "answer" not in e:
        return opts[None]
    if e["factor"] == "ID":
        chosen = e["answer"]
        return opts[contract.CANNOT_TELL] if contract.CANNOT_TELL in chosen else min(opts[c] for c in chosen)
    return opts[e["answer"]]


class TestTheRulesUnderOtherValues(unittest.TestCase):
    """chain.contract against the after's mock on values the corpus does not declare: the levels and sources Go
    writes, and, inside the 45 combinations, the same prompts as under the declared values."""

    @classmethod
    def setUpClass(cls):
        after = s.env("VB_VENS_AFTER")
        if after is None:
            raise unittest.SkipTest("set VB_VENS_AFTER to a vens binary built from b7c0435")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.runs = {}
        for sid, (n, values) in itertools.product(SAMPLE, enumerate((None,) + ALTERNATES)):
            d = os.path.join(SCENARIOS, sid)
            cfg = alternate(sid, values or {})
            path = os.path.join(cls.tmp.name, "configs", f"{sid}-{n}.yaml")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(yaml.safe_dump(cfg, sort_keys=False))
            for tag, extra in (("as", None), ("cannot_tell", {"VENS_MOCK_LLM_CANNOT_TELL": "cannot_tell"})):
                folder = os.path.join(cls.tmp.name, sid, f"{n}-{tag}")
                rec = runvens.generate(after, path, os.path.join(d, "report.json"), folder, record={"arm": "after"},
                                       env_extra=extra)
                cls.runs[(sid, n, tag)] = (folder, rec["generate"]["exit_status"], cfg)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_levels_and_sources_go_writes(self):
        scen = verdicts.load(SCENARIOS)
        for (sid, n, tag), (folder, code, cfg) in self.runs.items():
            self.assertEqual(code, 0, (sid, n, tag))
            dep, floors = contract.deployment(cfg), scen[sid]["floors"]
            with open(os.path.join(verdicts.run_dir(folder), "answers.json"), encoding="utf-8") as fh:
                factors = json.load(fh)["vulnerabilities"][0]["factors"]
            self.assertEqual([e["factor"] for e in factors if "answer" in e],
                             [q for q in contract.QUESTIONS if contract.asked(q, dep, floors)], (sid, n))
            for e in factors:
                opts = contract.options(e["factor"], dep, floors)
                self.assertEqual(e["level"], expected_level(e, opts), (sid, n, tag, e))
                self.assertEqual(e["source"], contract.source(e["factor"], dep, floors, e.get("answer")),
                                 (sid, n, tag, e))

    def test_inside_the_45_combinations_no_prompt_changes(self):
        for sid in SAMPLE:
            declared = verdicts.after_prompts(self.runs[(sid, 0, "as")][0])
            for n in range(1, INSIDE + 1):
                self.assertEqual(verdicts.after_prompts(self.runs[(sid, n, "as")][0]), declared, (sid, n))


if __name__ == "__main__":
    unittest.main()
