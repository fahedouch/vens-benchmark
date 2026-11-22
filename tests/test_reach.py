"""Reachability, the question 310-step3b asks of every CVE first from 19b333a (venslabs/vens#310, path A):
chain.contract's rules under it, answers.json's reachability record and the omissions it decides as the reader takes
them, the adjustment of a flagged CVE not reachable through 5f797bf's exact request, R in the measures,
chain/verdicts.py kept to historical runs, and, with VB_VENS_REACH, every scenario and a flagged copy of one on the mock
of a binary built at 5f797bf. No model is called and vens gets no API key."""
import hashlib
import json
import os
import tempfile
import unittest

import ctx_analyze
from chain import answers, attempt, calls, cdx, contract, diagnostics, families, kpi, report_scen, runvens, venslog
from chain import verdicts
from chain import cells as cellmod
from chain.errors import Refused
from tests import records as r
from tests import support as s

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS = os.path.join(ROOT, "scenarios")
IDS = sorted(d for d in os.listdir(SCENARIOS) if os.path.isdir(os.path.join(SCENARIOS, d)))
A, B = "CVE-2099-0001", "CVE-2099-0002"
MODEL = f"c1 · openai/{s.MODEL}"
NONE = frozenset()
# Every question asked: detection declared at three levels, a framework, data_subjects above the floor's band.
DEP = {"exposure": "internet", "data_sensitivity": "high", "frameworks": ("gdpr",),
       "detection": {"network": "logged", "host": "not_logged", "application": "active_in_application"},
       "traceability": "per_individual", "data_subjects": "millions"}
# vens's request for the reachability question, 19b333a to 5f797bf
# (pkg/contract/testdata/internet-facing/00-R.request.txt).
R_PROMPT = """VULNERABILITIES
[entries]

QUESTION
Can anonymous Internet users reach the vulnerable code of this vulnerability in this deployment, whatever access or \
effort that takes, as reachability is defined above?

ANSWERS
- reachable: Reachable here: the vulnerable code is reachable in this deployment, as defined above.
- not_reachable: Not reachable here: the facts given show that the vulnerable code is not reachable in this \
deployment, as defined above.
- cannot_tell: The facts given do not decide between the answers above.

Answer every vulnerability listed above once, by its vulnId, with one answer id from ANSWERS.
Reply with {"answers": [{"vulnId": "...", "reasoning": "...", "answer": "..."}]}."""
# vens 5f797bf's adjustment request for a flagged CVE not reachable
# (pkg/contract/testdata/internet-facing/13-adjustment-not-reachable.request.txt).
ADJ_PROMPT = """FLAGGED VULNERABILITY
[entry]

This vulnerability is flagged: its maintainers dispute it, or its severity sources disagree. Its entry carries the \
evidence: every CVSS vector published for it with its source, every vendor severity, the flag's quoted evidence, and \
the answer it was given without that evidence: not reachable here, as reachability is defined above. That answer \
stands and is not asked again. Assuming exploitation were possible here, with every other deployment fact unchanged, \
answer the question below from the supplied evidence alone. Unreachability alone does not justify `not_affected`.

QUESTIONS
confidentiality: Given this evidence, can exploiting it here affect confidentiality at all? Answer with affected, \
not_affected or cannot_tell.

Choose cannot_tell only when the evidence does not decide.
Reply with {"reasoning": "...", "confidentiality": "..."}."""
# The sha256 vens 5f797bf's pkg/contract/testdata/SHA256SUMS records for those two internet-facing requests, each
# golden file the request as sent and a newline.
VENS_SUMS = {"R": "ac0a725638f332b3afa7c596983543f3a363aea39dbf85fdd7583ba3f90274ab",
             "adjustment": "efee93ade5b49b0c1de908c269875abab1f55975a3ad53e368b40162a677c86b"}
# An unreachable CVE's vector: O 0, EE 1, LC 2, LI 1, LAV 1, LAC 7 (traceability none).
UNREACHED = "SL:9/M:4/O:0/S:9/ED:9/EE:1/A:9/ID:9/LC:2/LI:1/LAV:1/LAC:7/FD:1/RD:4/NC:2/PV:9"
SIX = {f: (None, contract.REACH_SOURCE) for f in contract.REACHED_ONLY}
READING = {"reachable": "answered", "not_reachable": "answered", "cannot_tell": "cannot_tell"}


def human(ids):
    return "VULNERABILITIES\n[]\n\nQUESTION\nq?\n\nANSWERS\n" + "".join(f"- {a}: text\n" for a in ids) + "\nAnswer."


def r_prompt(ids):
    return R_PROMPT.replace("[entries]", json.dumps([{"vulnId": i} for i in ids]))


def reach_record(answer):
    return {"factor": contract.R, "answer": answer, "reading": READING.get(answer, "invalid")}


def entry(vid, reach, vector=s.VECTOR, given=None):
    """A rated entry as 19b333a writes it: reachability's record apart, each level answered unless given as (answer,
    source), an answer of None a question not asked."""
    given = given or {}
    out = []
    for f, part in zip(s.VECTOR_FACTORS, vector.split("/")):
        answer, source = given.get(f, ("a", "answer"))
        x = {"factor": f, "level": int(part.split(":")[1]), "source": source}
        out.append(x if answer is None else {**x, "answer": answer, "reading": "answered"})
    return {"vulnId": vid, "adjustment": "not_asked", "reachability": reach_record(reach), "factors": out}


def adj_prompt(vid):
    return ADJ_PROMPT.replace("[entry]", json.dumps({"vulnId": vid, "answers": {"reachability": "not_reachable"}}))


def request_parts(human):
    """An adjustment request's entry, the request with its entry line put back as [entry], and the fields its
    QUESTIONS ask."""
    lines = human.split("\n")
    block = lines[lines.index("QUESTIONS") + 1:]
    template = "\n".join([lines[0], "[entry]"] + lines[2:])
    return json.loads(lines[1]), template, [ln.partition(":")[0] for ln in block[:block.index("")]]


def adjusted(vid, lc_source=contract.REACH_SOURCE, floored=()):
    """The entry 0421679 on writes for a flagged CVE not reachable: confidentiality adjusted not_affected, which
    leaves Loss of confidentiality at reachability's floor and lowers Privacy violation to its own; floored, the
    impacts whose axis the vector floors, from floor."""
    given = {**SIX, **{f: (None, "floor") for f in floored}, "LC": (None, lc_source), "PV": ("hundreds", "adjustment")}
    e = entry(vid, "not_reachable", UNREACHED.replace("PV:9", "PV:3"), given)
    lc = lambda x: {**x, "adjusted": "not_affected"} if x["factor"] == "LC" else x
    return {**e, "adjustment": "answered", "factors": [lc(x) for x in e["factors"]]}


def doc(*entries):
    return {"vulnerabilities": list(entries), "counters": {}, "defects": {}}


def load(content):
    with tempfile.TemporaryDirectory() as tmp:
        return answers.load(s.write(os.path.join(tmp, "answers.json"), content))


def ratings(rows):
    with tempfile.TemporaryDirectory() as tmp:
        return cdx.ratings(s.write(os.path.join(tmp, "vex.cdx.json"), s.vex(rows)))[0]


def with_reach(rec, answer):
    """A record of tests/records.py, its one CVE answered reachability."""
    (vid, cve), = rec["answers"]["per_cve"].items()
    per = {vid: {**cve, "reachability": {"answer": answer, "reading": READING.get(answer, "invalid")}}}
    return {**rec, "answers": {**rec["answers"], "per_cve": per}}


class TestTheRules(unittest.TestCase):
    """chain.contract under 19b333a's contract, reach= its reachability answer, against b7c0435's."""

    def test_reachability_first_and_the_six_dropped_when_not_reachable(self):
        old = contract.questions(DEP, NONE)
        self.assertEqual(old, list(contract.QUESTIONS))
        for answer in ("reachable", "cannot_tell", "off_the_list", ["not_reachable"]):
            self.assertEqual(contract.questions(DEP, NONE, reach=answer), ["R"] + old, answer)
        self.assertEqual(contract.questions(DEP, NONE, reach="not_reachable"), ["R", "M", "ID", "FD", "RD", "NC", "PV"])

    def test_the_six_at_their_lowest_from_reachability(self):
        for f, level in {"O": 0, "EE": 1, "LC": 2, "LI": 1, "LAV": 1, "LAC": 1}.items():
            self.assertEqual(contract.options(f, DEP, NONE, reach="not_reachable"), {None: level}, f)
            self.assertEqual(contract.source(f, DEP, NONE, reach="not_reachable"), "reachability", f)
        # no accountability loss's cell of the traceability column, undeclared read as none
        for trace, level in (("per_request", 7), (None, 7)):
            self.assertEqual(contract.options("LAC", dict(DEP, traceability=trace), NONE, reach="not_reachable"),
                             {None: level})
        for f in ("SL", "M", "S", "ED", "A", "ID", "FD", "RD", "NC", "PV"):
            self.assertEqual(contract.options(f, DEP, NONE, reach="not_reachable"), contract.options(f, DEP, NONE), f)
            self.assertEqual(contract.source(f, DEP, NONE, reach="not_reachable"), contract.source(f, DEP, NONE), f)

    def test_a_floored_axis_keeps_its_floor(self):
        floored = frozenset({"C", "A"})
        got = {f: (contract.options(f, DEP, floored, reach="not_reachable"),
                   contract.source(f, DEP, floored, reach="not_reachable")) for f in ("LC", "LI", "LAV")}
        self.assertEqual(got, {"LC": ({None: 2}, "floor"), "LI": ({None: 1}, "reachability"),
                               "LAV": ({None: 1}, "floor")})

    def test_not_reachable_takes_precedence_over_no_description(self):
        for f, level in (("O", 0), ("EE", 1)):
            self.assertEqual(contract.options(f, DEP, NONE, described=False), {None: 9})
            self.assertEqual(contract.options(f, DEP, NONE, described=False, reach="not_reachable"), {None: level})
            self.assertEqual(contract.source(f, DEP, NONE, described=False, reach="not_reachable"), "reachability")
        self.assertEqual(contract.options("M", DEP, NONE, described=False, reach="not_reachable"), {None: 9})
        self.assertEqual(contract.questions(DEP, NONE, described=False, reach="reachable"),
                         ["R"] + [q for q in contract.QUESTIONS if q not in ("M", "O", "EE")])

    def test_no_impact_at_the_floor_under_19b333a_alone(self):
        for f in ("LC", "LI", "LAV"):
            old = contract.options(f, DEP, NONE)
            self.assertNotIn("no_impact", old)
            self.assertEqual(contract.options(f, DEP, NONE, reach="reachable"), {"no_impact": contract.FLOOR[f], **old})
            self.assertEqual(contract.source(f, DEP, NONE, "no_impact", reach="reachable"), "answer")
        self.assertEqual(contract.options("LAC", DEP, NONE, reach="cannot_tell"), contract.options("LAC", DEP, NONE))

    def test_r_is_a_question_with_no_level(self):
        with self.assertRaisesRegex(ValueError, "no factor"):
            contract.options("R", DEP, NONE, reach="reachable")
        self.assertFalse(contract.asked("R", DEP, NONE))
        self.assertTrue(contract.asked("R", DEP, NONE, reach="not_reachable"))

    def test_the_questions_read_from_either_contracts_prompts(self):
        self.assertEqual(contract.question_of(r_prompt([A])), "R")
        got = calls.asked(calls.Call(1, b"", r_prompt([A]).encode(), None), "after")
        self.assertEqual((got.kind, got.ids), ("question", (A,)))
        for f in ("LC", "LI", "LAV"):
            self.assertEqual(contract.question_of(human(contract.ANSWER_IDS[f])), f)
            self.assertEqual(contract.question_of(human(("no_impact",) + contract.ANSWER_IDS[f])), f)
        known = {}
        for table in (contract.ANSWER_IDS, contract.REACH_ANSWER_IDS):
            for f, ids in table.items():
                known.setdefault(ids, set()).add(f)
        self.assertEqual({ids: fs for ids, fs in known.items() if len(fs) > 1}, {})


class TestTheRecord(unittest.TestCase):
    """answers.json at 19b333a: the reachability record outside the 16 factors, the six it leaves out."""

    def test_the_record_outside_the_16_factors(self):
        d = load(doc(entry(A, "reachable")))
        self.assertEqual(answers.check(d, ratings([(A, s.VECTOR, s.SEVERITY, s.SCORE)])), [])
        self.assertEqual(answers.reachability(d), [])
        got = answers.per_cve(d["vulnerabilities"][0])
        self.assertEqual(got["reachability"], {"answer": "reachable", "reading": "answered"})
        self.assertEqual(sorted(got["factors"]), sorted(s.VECTOR_FACTORS))

    def test_not_reachable_with_the_six_left_out(self):
        for given in (SIX, {**SIX, "LC": (None, "floor")}):
            d = load(doc(entry(A, "not_reachable", UNREACHED, given)))
            self.assertEqual(answers.check(d, ratings([(A, UNREACHED, "high", 49.5)])), [])
            self.assertEqual(answers.reachability(d), [])

    def test_not_reachable_yet_asked_or_off_its_lowest(self):
        vector = UNREACHED.replace("EE:1", "EE:3")
        given = {**SIX, "O": ("full_access_or_expensive_resources_required", "answer")}
        self.assertEqual(answers.reachability(load(doc(entry(A, "not_reachable", vector, given)))),
                         [f"{A}: not reachable, yet O answered", f"{A}: not reachable, yet O at 0 from answer",
                          f"{A}: not reachable, yet EE at 3 from reachability"])

    def test_a_flagged_cve_not_reachable_keeps_its_adjustment(self):
        d = load(doc(adjusted(A)))
        self.assertEqual(answers.check(d, ratings([(A, UNREACHED.replace("PV:9", "PV:3"), "high", 49.5)])), [])
        self.assertEqual(answers.reachability(d), [])
        got = answers.per_cve(d["vulnerabilities"][0])
        self.assertEqual((got["adjustment"], got["factors"]["LC"]["adjusted"], got["factors"]["PV"]["source"]),
                         ("answered", "not_affected", "adjustment"))
        # the adjustment never moves the six: Loss of confidentiality stays reachability's
        self.assertEqual(answers.reachability(load(doc(adjusted(A, lc_source="adjustment")))),
                         [f"{A}: not reachable, yet LC at 2 from adjustment"])

    def test_reachability_as_a_source_needs_not_reachable(self):
        d = load(doc(entry(A, "cannot_tell", given={"O": (None, "reachability")})))
        self.assertEqual(answers.reachability(d), [f"{A}: O from reachability, yet its answer is 'cannot_tell'"])
        old = s.answers_doc([(A, s.VECTOR)])
        old["vulnerabilities"][0]["factors"][2] = {"factor": "O", "level": 7, "source": "reachability"}
        self.assertEqual(answers.reachability(load(old)), [f"{A}: O from reachability, yet its answer is None"])

    def test_every_rated_entry_holds_reachability_once_one_does(self):
        old = s.answers_doc([(B, s.VECTOR)])["vulnerabilities"][0]
        self.assertEqual(answers.reachability(load(doc(entry(A, "reachable"), old))),
                         [f"{B}: a rated entry without reachability, other entries holding it"])

    def test_before_19b333a_nothing_changes(self):
        d = load(s.answers_doc([(A, s.VECTOR)], [(B, ["M"])]))
        rated, unrated = answers.entries(d)
        self.assertEqual((answers.reachability(d), answers.unrated_shape(d)), ([], []))
        self.assertIsNone(answers.per_cve(rated[A])["reachability"])
        self.assertIsNone(answers.per_cve(unrated[B])["reachability"])

    def test_an_unrated_entry_answered_reachability_alone(self):
        # A strict run stopped on reachability's cannot_tell: Go writes the CVE's empty factor list as null.
        alone = {"vulnId": B, "unrated": True, "adjustment": "not_asked", "reachability": reach_record("cannot_tell"),
                 "factors": None, "counters": ["reachability_cannot_tell"]}
        d = load(doc(alone))
        _, unrated = answers.entries(d)
        self.assertEqual((answers.unrated_shape(d), answers.reachability(d), answers.duplicates(d)), ([], [], []))
        got = answers.per_cve(unrated[B])
        self.assertEqual((got["unrated"], got["factors"], got["reachability"]),
                         (True, {}, {"answer": "cannot_tell", "reading": "cannot_tell"}))
        leveled = {**alone, "reachability": {**reach_record("cannot_tell"), "level": 9}}
        self.assertEqual(answers.unrated_shape(load(doc(leveled))), [f"{B}: an unrated entry with a level or a source"])

    def test_no_factor_list_or_another_record_is_refused(self):
        rated_null = {**entry(A, "reachable"), "factors": None}
        unrated_null = {"vulnId": B, "unrated": True, "adjustment": "not_asked", "factors": None}
        not_r = {**entry(A, "reachable"), "reachability": {"factor": "M", "answer": "reachable"}}
        for content in (doc(rated_null), doc(unrated_null), doc(not_r), doc({**entry(A, "x"), "reachability": "x"})):
            with self.assertRaisesRegex(Refused, "not answers.json"):
                load(content)


class TestTheAttempt(unittest.TestCase):
    """An attempt of the after at 19b333a as baseline.yml uploads it, and its calls."""

    def folder(self, tmp, vector, content):
        questions = [(s.SYSTEM, r_prompt([A]), s.reply([A]))] + s.after_calls(A, ("M", "FD", "RD", "NC", "PV"))
        folder = s.baseline_folder(tmp, 3001, "internal", 1, 1, record=s.COMPLETE_RECORD, commit=s.REACH_SHA, vid=A,
                                   calls=questions, vex_file=False, answers=False)
        s.write(os.path.join(folder, "vex-internal.cdx.json"), s.vex([(A, vector, "high", 49.5)]))
        s.write(os.path.join(folder, "calls", "run-1", "answers.json"), content)
        return folder

    def test_reachability_in_the_record_and_the_scores_usable(self):
        for reach, vector, given in (("reachable", s.VECTOR, None), ("not_reachable", UNREACHED, SIX)):
            with tempfile.TemporaryDirectory() as tmp:
                rec = attempt.read_attempt(self.folder(tmp, vector, doc(entry(A, reach, vector, given))),
                                           commits={"after": s.REACH_SHA})
            self.assertEqual((rec["outcome"], rec["scores_usable"], rec["answers"]["problems"]), ("complete", True, []))
            self.assertEqual(set(rec["calls"]["kinds"]), {"planned"})
            printed = json.loads(json.dumps(rec, sort_keys=True))
            self.assertEqual(printed["answers"]["per_cve"][A]["reachability"], {"answer": reach, "reading": "answered"})

    def test_the_fixtures_are_5f797bfs_requests(self):
        for name, text in (("R", R_PROMPT), ("adjustment", ADJ_PROMPT)):
            self.assertEqual(hashlib.sha256((text + "\n").encode()).hexdigest(), VENS_SUMS[name], name)

    def test_5f797bfs_unreachable_adjustment_through_parsing_and_adjustment(self):
        # Not reachable, the vector flooring integrity and availability: R, then the questions R leaves, then the
        # adjustment on confidentiality alone, 5f797bf's request word for word.
        questions = [(s.SYSTEM, r_prompt([A]), s.reply([A]))] + s.after_calls(A, ("M", "FD", "RD", "NC", "PV"))
        questions.append((s.SYSTEM, adj_prompt(A), json.dumps({"reasoning": "r", "confidentiality": "not_affected"})))
        with tempfile.TemporaryDirectory() as tmp:
            folder = s.baseline_folder(tmp, 3001, "internal", 1, 1, record=s.COMPLETE_RECORD, commit=s.REACH_SHA,
                                       vid=A, calls=questions, vex_file=False, answers=False)
            s.write(os.path.join(folder, "vex-internal.cdx.json"),
                    s.vex([(A, UNREACHED.replace("PV:9", "PV:3"), "high", 49.5)]))
            s.write(os.path.join(folder, "calls", "run-1", "answers.json"), doc(adjusted(A, floored=("LI", "LAV"))))
            last = calls.load(os.path.join(folder, "calls", "run-1"))[-1]
            rec = attempt.read_attempt(folder, commits={"after": s.REACH_SHA})
        got = calls.asked(last, "after")
        self.assertEqual((got.kind, got.ids), ("adjustment", (A,)))
        shown, template, fields = request_parts(last.text("human"))
        self.assertEqual((shown["answers"], template, fields),
                         ({"reachability": "not_reachable"}, ADJ_PROMPT, ["confidentiality"]))
        self.assertEqual((rec["scores_usable"], rec["problems"], rec["answers"]["problems"]), (True, [], []))
        self.assertEqual((rec["calls"]["kinds"], rec["recovery"]["adjustment"]), (["planned"] * 6 + ["adjustment"], 1))
        cve = rec["answers"]["per_cve"][A]
        self.assertEqual((cve["adjustment"], cve["reachability"]), ("answered", {"answer": "not_reachable",
                                                                                "reading": "answered"}))
        fs = cve["factors"]
        self.assertEqual({f: (fs[f]["answer"], fs[f]["level"], fs[f]["source"], fs[f]["adjusted"])
                          for f in contract.REACHED_ONLY + ("PV",)},
                         {"O": (None, 0, "reachability", None), "EE": (None, 1, "reachability", None),
                          "LC": (None, 2, "reachability", "not_affected"), "LI": (None, 1, "floor", None),
                          "LAV": (None, 1, "floor", None), "LAC": (None, 7, "reachability", None),
                          "PV": ("hundreds", 3, "adjustment", None)})

    def test_a_record_off_the_rule_leaves_its_scores_unread(self):
        with tempfile.TemporaryDirectory() as tmp:
            content = doc(entry(A, "reachable", given={"LAC": (None, "reachability")}))
            rec = attempt.read_attempt(self.folder(tmp, s.VECTOR, content))
        self.assertFalse(rec["scores_usable"])
        self.assertEqual(rec["answers"]["problems"], [f"{A}: LAC from reachability, yet its answer is 'reachable'"])

    def test_the_calls_after_reachability_list_the_cves_it_leaves(self):
        # batch 2: R asked again for B; A not reachable, so Opportunity and Ease of exploit ask about B alone
        seq = [(r_prompt([A, B]), [A, B], [B]), (r_prompt([B]), [B], []),
               (s.after_human("Question M?", [A, B]), [A, B], []), (s.after_human("Question O?", [B]), [B], []),
               (s.after_human("Question EE?", [B]), [B], [])]
        archived = [calls.Call(n, s.SYSTEM.encode(), h.encode(), s.reply(ids, skip).encode())
                    for n, (h, ids, skip) in enumerate(seq, 1)]
        self.assertEqual(calls.classify(archived, "after"),
                         (["planned", "again_omission", "planned", "planned", "planned"], None))


class TestTheMeasures(unittest.TestCase):
    """R in the measures: answer agreement, cannot_tell, the families' moves, the fallback's check."""

    def demo_run(self, reach, replicate):
        rec = r.record("after", "internal", replicate, {A: r.rating(s.VECTOR)}, answers={A: r.factors(s.VECTOR)})
        return with_reach(rec, reach) if reach else rec

    def scen_run(self, sid, reach, lac, replicate=1):
        vec = r.vector(LAC=lac[0])
        rec = r.record("after", sid, replicate, {A: r.rating(vec)}, scenario=True,
                       answers={A: r.factors(vec, LAC=lac[1:])})
        return with_reach(rec, reach) if reach else rec

    def test_cannot_tell_and_agreement_per_question(self):
        got = kpi.cannot_tell([self.demo_run("cannot_tell", 1), self.demo_run("reachable", 2)])
        self.assertEqual(got["questions"]["R"], {"rate": 0.5, "asked": 2, "agreement": 0.0})
        self.assertEqual((got["cves_affected"], list(got["questions"])[0]), (0.5, "R"))
        self.assertEqual(kpi.answers_across([self.demo_run("reachable", 1)], [self.demo_run("not_reachable", 1)],
                                            [A])["R"], (0.0, None))
        old = kpi.cannot_tell([self.demo_run(None, 1), self.demo_run(None, 2)])
        self.assertEqual(("R" in old["questions"], old["cves_affected"]), (False, 0.0))

    def test_the_answer_and_the_moves(self):
        a = self.scen_run("disc_audit", "not_reachable", (7, None, "reachability"))
        b = self.scen_run("disc_audit2", "not_reachable", (1, None, "reachability"))
        c = self.scen_run("disc_audit3", "reachable", (9, "defeats_attribution", "answer"))
        self.assertEqual((families.value(a, "answer R"), families.value(c, "answer R")), ("not_reachable", "reachable"))
        self.assertIsNone(families.value(self.demo_run(None, 1), "answer R"))
        # both from reachability: one answer, which Go crossed with traceability
        self.assertEqual(families.moved(a, b, "LAC"), [("LAC", 7, 1, "reachability", "reachability", True)])
        self.assertEqual((families.move(a, b, "LAC"), families.move(a, c, "LAC")), (families.GO, families.MIXED))

    def test_consistency_reads_reachability(self):
        recs = [self.scen_run("expo_internal", "reachable", (5, "a5", "answer"), 1),
                self.scen_run("expo_internal", "not_reachable", (5, "a5", "answer"), 2)]
        got = diagnostics.consistency(cellmod.group(recs))
        self.assertEqual((got["answers"][(MODEL, "R")], got["answers"][(MODEL, "LAC")]), ((0.0, 1), (1.0, 1)))

    def test_the_b7c0435_rules_certify_no_run_that_asks_r(self):
        # families: a row read on runs that ask R is marked, its verdict not certified
        checks = [c for c in verdicts.CHECKS if c.family == "reachability" and c.quantity == "O"]
        for reach, historical in ((None, True), ("reachable", False)):
            recs = [self.scen_run(sid, reach, (5, "a5", "answer")) for sid in ("reach_no", "reach_yes")]
            rows = families.evaluate(cellmod.group(recs), {}, checks)
            self.assertEqual([x["historical"] for x in rows], [historical], reach)
            text = "\n".join(report_scen.families_section({"rows": rows, "moves": {}}))
            self.assertEqual(("not certified, asks R" in text, "certify none of them" in text), (not historical,) * 2)
        # verdicts: a run whose calls ask R is refused
        second = (s.SYSTEM, human(contract.ANSWER_IDS["M"]), s.reply([A]))
        with tempfile.TemporaryDirectory() as tmp:
            for name, first in (("historical", human(contract.ANSWER_IDS["O"])), ("asks-r", r_prompt([A]))):
                s.write_calls(os.path.join(tmp, name, "calls", "run-1"), [(s.SYSTEM, first, s.reply([A])), second])
            self.assertEqual(sorted(verdicts.after_prompts(os.path.join(tmp, "historical"))), ["M", "O"])
            with self.assertRaisesRegex(RuntimeError, r"asks reachability \(R\): chain.verdicts holds b7c0435's"):
                verdicts.after_prompts(os.path.join(tmp, "asks-r"))

    def test_the_fallback_holds_reachability_at_cannot_tell(self):
        every = {f: ("cannot_tell", "answer") for f in cdx.FACTORS}
        rec = r.record("after", "internal", 1, {A: r.rating(s.VECTOR)}, answers={A: r.factors(s.VECTOR, **every)})
        self.assertEqual(ctx_analyze._not_cannot_tell([with_reach(rec, "cannot_tell")]), [])
        self.assertEqual(ctx_analyze._not_cannot_tell([with_reach(rec, "reachable")]),
                         ["1 answer(s) other than cannot_tell"])


def level_of(opts, answer):
    """The level options give an answer; Intrusion detection's, a set of channels, the lowest chosen."""
    if not isinstance(answer, list):
        return opts.get(answer)
    return opts[contract.CANNOT_TELL] if contract.CANNOT_TELL in answer else min(opts[c] for c in answer)


class TestReachOnTheMock(unittest.TestCase):
    """Every scenario on the mock of vens 5f797bf, as answered and with every answer cannot_tell, a strict run stopped
    on reachability's cannot_tell, and a flagged copy of a scenario not reachable: chain.contract's rules under R and
    the reader against what vens wrote."""

    STRICT = "comp_gdpr"
    # Not reachable on the mock and asked Privacy violation; a dispute in its description flags it, and its copy's
    # vector floors integrity and availability. The mock answers not_affected to this wording.
    FLAGGED = "crit_critical"
    DISPUTE = " Fixed in 2.0. The maintainer disputes this report."
    VECTORS = ("C:H/I:H/A:H", "C:H/I:N/A:N")

    @classmethod
    def setUpClass(cls):
        cls.binary = s.env("VB_VENS_REACH")
        if cls.binary is None:
            raise unittest.SkipTest("set VB_VENS_REACH to a vens binary built from 310-step3b 5f797bf to run "
                                    "reachability on the mock")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.scen = verdicts.load(SCENARIOS)
        cls.runs = {}
        for tag, strict, extra in (("after", False, None),
                                   ("cannot_tell", False, {"VENS_MOCK_LLM_CANNOT_TELL": "cannot_tell"}),
                                   ("strict", True, {"VENS_MOCK_LLM_CANNOT_TELL": "reachable"})):
            for sid in (IDS if tag != "strict" else (cls.STRICT,)):
                folder = os.path.join(cls.tmp.name, tag, sid)
                d = os.path.join(SCENARIOS, sid)
                rec = runvens.generate(cls.binary, os.path.join(d, "config.yaml"), os.path.join(d, "report.json"),
                                       folder, record={"arm": "after"}, strict=strict, env_extra=extra)
                cls.runs[(tag, sid)] = (folder, rec["generate"]["exit_status"])
        cls.flagged_report = os.path.join(cls.tmp.name, "flagged-report.json")
        with open(os.path.join(SCENARIOS, cls.FLAGGED, "report.json"), encoding="utf-8") as fh:
            text = fh.read()
        description = contract.finding(os.path.join(SCENARIOS, cls.FLAGGED, "report.json"))["Description"]
        s.write(cls.flagged_report, text.replace(json.dumps(description), json.dumps(description + cls.DISPUTE), 1)
                .replace(*cls.VECTORS, 1))
        report = cls.flagged_report
        folder = os.path.join(cls.tmp.name, "flagged", cls.FLAGGED)
        rec = runvens.generate(cls.binary, os.path.join(SCENARIOS, cls.FLAGGED, "config.yaml"), report, folder,
                               record={"arm": "after"})
        cls.runs[("flagged", cls.FLAGGED)] = (folder, rec["generate"]["exit_status"])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def entry(self, tag, sid):
        with open(os.path.join(verdicts.run_dir(self.runs[(tag, sid)][0]), "answers.json"), encoding="utf-8") as fh:
            (e,) = json.load(fh)["vulnerabilities"]
        return e

    def test_both_reachability_answers_on_the_corpus(self):
        self.assertEqual({self.entry("after", sid)["reachability"]["answer"] for sid in IDS},
                         {"reachable", "not_reachable"})
        self.assertEqual({self.entry("cannot_tell", sid)["reachability"]["answer"] for sid in IDS}, {"cannot_tell"})

    def test_each_call_asks_the_questions_the_rules_give(self):
        for tag in ("after", "cannot_tell"):
            for sid in IDS:
                sc, reach = self.scen[sid], self.entry(tag, sid)["reachability"]["answer"]
                asked = [contract.question_of(c.text("human"))
                         for c in calls.load(verdicts.run_dir(self.runs[(tag, sid)][0]))]
                self.assertEqual(asked, contract.questions(sc["dep"], sc["floors"], sc["described"], reach=reach),
                                 (tag, sid))

    def test_the_levels_and_sources_vens_wrote(self):
        for tag in ("after", "cannot_tell"):
            for sid in IDS:
                sc, e = self.scen[sid], self.entry(tag, sid)
                reach = e["reachability"]["answer"]
                self.assertEqual([x["factor"] for x in e["factors"]], list(cdx.FACTORS), (tag, sid))
                for x in e["factors"]:
                    f, answer = x["factor"], x.get("answer")
                    opts = contract.options(f, sc["dep"], sc["floors"], sc["described"], reach=reach)
                    want = level_of(opts, answer) if "answer" in x else opts.get(None)
                    self.assertEqual(x["level"], want, (tag, sid, x))
                    self.assertEqual(x["source"], contract.source(f, sc["dep"], sc["floors"], answer, sc["described"],
                                                                  reach=reach), (tag, sid, x))

    def test_the_reader_reads_every_run(self):
        records = {}
        for tag in ("after", "cannot_tell"):
            for sid in IDS:
                folder, code = self.runs[(tag, sid)]
                rec = attempt.read_attempt(folder)
                (vid,) = rec["ratings"]
                self.assertEqual((code, rec["outcome"], rec["scores_usable"], rec["problems"],
                                  rec["answers"]["problems"]), (0, "complete", True, [], []), (tag, sid))
                self.assertEqual(rec["answers"]["per_cve"][vid]["reachability"],
                                 {k: self.entry(tag, sid)["reachability"][k] for k in ("answer", "reading")})
                self.assertEqual(set(rec["calls"]["kinds"]), {"planned"}, (tag, sid))
                records.setdefault(tag, []).append(rec)
        self.assertEqual(ctx_analyze._not_cannot_tell(records["cannot_tell"]), [])
        self.assertNotEqual(ctx_analyze._not_cannot_tell(records["after"]), [])

    def test_a_flagged_cve_not_reachable_keeps_its_adjustment_on_confidentiality(self):
        folder, code = self.runs[("flagged", self.FLAGGED)]
        sc, e = self.scen[self.FLAGGED], self.entry("flagged", self.FLAGGED)
        floors = contract.floors(contract.vectors(contract.finding(self.flagged_report)))
        self.assertEqual((code, e["reachability"]["answer"], e["adjustment"], floors),
                         (0, "not_reachable", "answered", frozenset({"I", "A"})))
        archived = calls.load(verdicts.run_dir(folder))
        self.assertEqual([contract.question_of(c.text("human")) for c in archived[:-1]],
                         contract.questions(sc["dep"], floors, sc["described"], reach="not_reachable"))
        shown, template, fields = request_parts(archived[-1].text("human"))
        self.assertEqual((shown["answers"], template, fields),
                         ({"reachability": "not_reachable"}, ADJ_PROMPT, ["confidentiality"]))
        fs = {x["factor"]: x for x in e["factors"]}
        self.assertEqual([(f, x["adjusted"]) for f, x in fs.items() if "adjusted" in x], [("LC", "not_affected")])
        self.assertEqual({f: (fs[f]["level"], fs[f]["source"]) for f in contract.REACHED_ONLY + ("PV",)},
                         {"O": (0, "reachability"), "EE": (1, "reachability"), "LC": (2, "reachability"),
                          "LI": (1, "floor"), "LAV": (1, "floor"), "LAC": (7, "reachability"),
                          "PV": (3, "adjustment")})
        for x in e["factors"]:
            if x["factor"] != "PV":
                opts = contract.options(x["factor"], sc["dep"], floors, sc["described"], reach="not_reachable")
                self.assertEqual(x["level"], level_of(opts, x.get("answer")) if "answer" in x else opts.get(None), x)
        rec = attempt.read_attempt(folder)
        self.assertEqual((rec["scores_usable"], rec["problems"], rec["answers"]["problems"]), (True, [], []))
        self.assertEqual((rec["calls"]["kinds"][-1], rec["summary"]["calls"].get("adjustment")), ("adjustment", 1))

    def test_a_strict_run_stops_on_reachability_cannot_tell(self):
        folder, code = self.runs[("strict", self.STRICT)]
        self.assertEqual(code, 1)
        self.assertIsNone(self.entry("strict", self.STRICT)["factors"])
        rec = attempt.read_attempt(folder)
        self.assertIn("the answer to Reachability (R)", rec["failure"]["cause"])
        self.assertEqual((rec["failure"]["kind"], rec["answers"]["rated"], rec["answers"]["unrated"],
                          rec["answers"]["problems"], rec["problems"]), ("scoring", 0, 1, [], []))
        (got,) = rec["answers"]["per_cve"].values()
        self.assertEqual((got["unrated"], got["factors"], got["reachability"]),
                         (True, {}, {"answer": "cannot_tell", "reading": "cannot_tell"}))
        recs = venslog.read(os.path.join(folder, "vens.log"))
        self.assertEqual(venslog.summary(recs)["counters"], {"reachability_cannot_tell": 1})
        self.assertEqual([contract.question_of(c.text("human")) for c in calls.load(verdicts.run_dir(folder))], ["R"])


if __name__ == "__main__":
    unittest.main()
