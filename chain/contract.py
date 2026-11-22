"""The after's rules for one CVE, as vens states them at 310-step3 b7c0435: the level each answer gives, the levels Go
sets itself, which questions a CVE is asked and the axes its CVSS vectors floor (pkg/contract/rules.go and table.go,
pkg/owasp/levels.go, pkg/cvss/applicability.go and pkg/riskconfig/fields.go there). chain/verdicts.py reads the
scenarios through them. tests/test_verdicts.py checks them against the levels and sources the after's mock writes:
every scenario under its declared values, and six scenarios under four other assignments of G2 to G4. The 45
combinations chain/verdicts.py enumerates run on these Python rules alone.

The same rules at 310-step3b 19b333a, which asks reachability first, take reach=, the CVE's answer to it: R is no
factor and has no level; read as reachable unless it is not_reachable, it otherwise sets Opportunity and Ease of
exploit to their lowest levels, the three impacts to their floors where the vector does not floor them already, and
Loss of accountability to no accountability loss's cell of its traceability column, each with source reachability and
none of the six asked. Since 219aad9 the three impacts also answer no_impact, at their floors. From 0421679 a flagged
CVE not reachable whose Privacy violation was asked gets an adjustment call on confidentiality alone, its request
showing R's answer (reworded at 5f797bf: the answer stands, confidentiality judged as if exploitation were possible),
which can lower Privacy violation (source adjustment), never the six. tests/test_reach.py checks these rules against
the mock of a binary built at 5f797bf. reach=None is b7c0435's contract, which asks no R; chain/verdicts.py keeps it,
for historical runs alone.
"""
import json

# The model-answered factors in the order a batch's calls ask them.
QUESTIONS = ("M", "O", "EE", "ID", "LC", "LI", "LAV", "LAC", "FD", "RD", "NC", "PV")
CANNOT_TELL = "cannot_tell"

# Each answer's level; cannot_tell takes the factor's worst case.
ANSWERS = {
    "M": {"low_or_no_reward": 1, "possible_reward": 4, "high_reward": 9, CANNOT_TELL: 9},
    "O": {"no_access_or_resources_required": 9, "some_access_or_resources_required": 7,
          "special_access_or_resources_required": 4, "full_access_or_expensive_resources_required": 0,
          CANNOT_TELL: 9},
    "EE": {"theoretical": 1, "difficult": 3, "easy": 5, "automated_tools_available": 9, CANNOT_TELL: 9},
    "LI": {"minimal_slightly_corrupt": 1, "minimal_seriously_corrupt": 3, "extensive_slightly_corrupt": 5,
           "extensive_seriously_corrupt": 7, "all_data_totally_corrupt": 9, CANNOT_TELL: 9},
    "LAV": {"minimal_secondary_interrupted": 1, "minimal_primary_interrupted": 5,
            "extensive_secondary_interrupted": 5, "extensive_primary_interrupted": 7,
            "all_services_completely_lost": 9, CANNOT_TELL: 9},
    "FD": {"less_than_cost_to_fix": 1, "minor_effect_on_annual_profit": 3, "significant_effect_on_annual_profit": 7,
           "bankruptcy": 9, CANNOT_TELL: 9},
    "RD": {"minimal_damage": 1, "loss_of_major_accounts": 4, "loss_of_goodwill": 5, "brand_damage": 9,
           CANNOT_TELL: 9},
    "NC": {"minor_violation": 2, "clear_violation": 5, "high_profile_violation": 7, CANNOT_TELL: 7},
    # Privacy violation's answers are data_subjects' bands.
    "PV": {"none": 3, "one_individual": 3, "hundreds": 5, "thousands": 7, "millions": 9, CANNOT_TELL: 9},
}
# Loss of confidentiality's answer is an extent, crossed with data_sensitivity's column: low and medium data are
# non-sensitive, high and critical data critical.
LC_EXTENT = {"minimal": (2, 6), "extensive": (6, 7), "all": (9, 9), CANNOT_TELL: (9, 9)}
CRITICAL_DATA = {"low": False, "medium": False, "high": True, "critical": True}
# Loss of accountability's answer says what the attacker leaves, crossed with what is in place to trace it: an
# identified attacker is fully traceable under per_individual alone.
LAC_ACTOR = {
    "identified": {"none": 7, "per_request": 7, "per_individual": 1},
    "unidentified": {"none": 9, "per_request": 7, "per_individual": 7},
    "defeats_attribution": {"none": 9, "per_request": 9, "per_individual": 9},
    CANNOT_TELL: {"none": 9, "per_request": 9, "per_individual": 9},
}
# Intrusion detection's answer is a set of channels, each at its declared level; the lowest chosen counts.
CHANNELS = ("network", "host", "application")
DETECTION_LEVEL = {"not_logged": 9, "logged": 8, "logged_and_reviewed": 3, "active_in_application": 1}
# Size, from the attacker group exposure names.
SIZE = {"internet": 9, "private": 6, "internal": 4}
# Every finding is a published CVE a scanner matched: OWASP's worst case for the group's skill, the flaw's
# discovery and its awareness.
CONSTANT = {"SL": 9, "ED": 9, "A": 9}
# An axis every vector gives N takes its factor's lowest level, Privacy violation following confidentiality.
FLOOR = {"LC": 2, "LI": 1, "LAV": 1, "PV": 3}
# data_subjects caps Privacy violation at its band's level; none and one individual cap it at the floor.
PV_CAP = {"none": 3, "one_individual": 3, "hundreds": 5, "thousands": 7, "millions": 9}
# Non-compliance without a framework: OWASP's lowest level, not asked.
NO_FRAMEWORK = 2
AXES = ("C", "I", "A")
GROUPS = {"L": ("SL", "M", "O", "S", "ED", "EE", "A", "ID"), "TA": ("SL", "M", "O", "S"),
          "VU": ("ED", "EE", "A", "ID"), "T": ("LC", "LI", "LAV", "LAC"), "B": ("FD", "RD", "NC", "PV")}
ANSWER_IDS = {**{f: tuple(a) for f, a in ANSWERS.items()}, "LC": tuple(LC_EXTENT), "LAC": tuple(LAC_ACTOR),
              "ID": CHANNELS + (CANNOT_TELL,)}


# 310-step3b 19b333a's reachability question, asked first, and what its answer decides.
R = "R"
NOT_REACHABLE, NO_IMPACT = "not_reachable", "no_impact"
REACHABILITY = ("reachable", NOT_REACHABLE, CANNOT_TELL)
REACH_SOURCE = "reachability"
REACHED_ONLY = ("O", "EE", "LC", "LI", "LAV", "LAC")
REACH_QUESTIONS = (R,) + QUESTIONS
# The lowest level each factor reachability decides takes; Loss of accountability's is no accountability loss's,
# identified's row, by traceability.
UNREACHED = {"O": 0, "EE": 1, "LC": FLOOR["LC"], "LI": FLOOR["LI"], "LAV": FLOOR["LAV"]}
AXIS = {"LC": "C", "LI": "I", "LAV": "A"}
REACH_ANSWER_IDS = {**ANSWER_IDS, R: REACHABILITY, **{f: (NO_IMPACT,) + ANSWER_IDS[f] for f in AXIS}}


def reachable(answer):
    """Whether Go reads a reachability answer as reachable: every answer but not_reachable, cannot_tell and one off
    the list taking the worst case."""
    return answer != NOT_REACHABLE


def _unreached(f, floored, reach):
    """Whether reachability, answered reach under 19b333a's contract, sets factor f: one of the six, the CVE read as
    not reachable, and not an impact whose axis the vector floors, which keeps its floor."""
    return reach is not None and f in REACHED_ONLY and not reachable(reach) and AXIS.get(f) not in floored


def v3_axes(vector):
    """{C, I, A: value} of a CVSS 3.x vector."""
    parts = dict(p.partition(":")[::2] for p in vector.split("/")[1:])
    return {a: parts[a] for a in AXES}


def finding(report_path):
    with open(report_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    found = [v for r in doc.get("Results") or [] for v in r.get("Vulnerabilities") or []]
    if len(found) != 1:
        raise ValueError(f"{report_path}: {len(found)} findings, a scenario holds one")
    return found[0]


def vectors(f):
    """The distinct v3 vectors of a Trivy finding, every source's."""
    out = []
    for c in (f.get("CVSS") or {}).values():
        v = c.get("V3Vector")
        if v and v not in out:
            out.append(v)
    return out


def floors(vecs):
    """The axes Applicability floors: those every vector gives N; none without a vector."""
    if not vecs:
        return frozenset()
    return frozenset(a for a in AXES if all(v3_axes(v)[a] == "N" for v in vecs))


def deployment(config):
    """What the rules read from a schema-2 config: exposure, data sensitivity, frameworks and G2 to G4, None where
    undeclared."""
    ctx = config["context"]
    return {"exposure": ctx["exposure"], "data_sensitivity": ctx["data_sensitivity"],
            "frameworks": tuple(ctx.get("compliance_requirements") or ()), "detection": ctx.get("detection"),
            "traceability": ctx.get("traceability"), "data_subjects": ctx.get("data_subjects")}


def asked(f, dep, floored, described=True, *, reach=None):
    """Whether a CVE gets factor f's question; reach: its reachability answer under 19b333a's contract, None under
    b7c0435's."""
    if reach is not None:
        if f == R:
            return True
        if f in REACHED_ONLY and not reachable(reach):
            return False
    if f in ("M", "O", "EE"):
        return described
    if f == "ID":
        # Undeclared, every channel is the worst case; declared at one level, any set of channels gives it.
        return dep["detection"] is not None and len({dep["detection"][c] for c in CHANNELS}) > 1
    if f == "LC":
        return "C" not in floored
    if f == "LI":
        return "I" not in floored
    if f == "LAV":
        return "A" not in floored
    if f == "NC":
        return bool(dep["frameworks"])
    if f == "PV":
        ds = dep["data_subjects"]
        return "C" not in floored and (ds is None or PV_CAP[ds] > FLOOR["PV"])
    return f in ("LAC", "FD", "RD")


def options(f, dep, floored, described=True, *, reach=None):
    """Factor f's level for each answer its question can get, {answer: level}; {None: level} where Go sets it. reach:
    the CVE's reachability answer under 19b333a's contract, None under b7c0435's."""
    if f == R:
        raise ValueError("R is the reachability question, no factor: it has no level")
    if f in CONSTANT:
        return {None: CONSTANT[f]}
    if f == "S":
        return {None: SIZE[dep["exposure"]]}
    if _unreached(f, floored, reach):
        if f == "LAC":
            return {None: LAC_ACTOR["identified"][dep["traceability"] or "none"]}
        return {None: UNREACHED[f]}
    if reach is not None and f in AXIS and asked(f, dep, floored, described):
        return {NO_IMPACT: FLOOR[f], **options(f, dep, floored, described)}
    if not asked(f, dep, floored, described):
        if f == "ID":
            det = dep["detection"]
            return {None: DETECTION_LEVEL["not_logged"] if det is None else DETECTION_LEVEL[det["network"]]}
        if f in ("M", "O", "EE"):
            return {None: ANSWERS[f][CANNOT_TELL]}
        if f == "NC":
            return {None: NO_FRAMEWORK}
        return {None: FLOOR[f]}
    if f == "ID":
        levels = {c: DETECTION_LEVEL[dep["detection"][c]] for c in CHANNELS}
        return {**levels, CANNOT_TELL: max(levels.values())}
    if f == "LC":
        column = int(CRITICAL_DATA[dep["data_sensitivity"]])
        return {x: lv[column] for x, lv in LC_EXTENT.items()}
    if f == "LAC":
        trace = dep["traceability"] or "none"
        return {x: lv[trace] for x, lv in LAC_ACTOR.items()}
    if f == "PV":
        cap = 9 if dep["data_subjects"] is None else PV_CAP[dep["data_subjects"]]
        return {x: min(lv, cap) for x, lv in ANSWERS["PV"].items()}
    return dict(ANSWERS[f])


def source(f, dep, floored, answer=None, described=True, *, reach=None):
    """Where factor f's level comes from, as answers.json names it: constant, config, floor, answer or, under
    19b333a's contract (reach, the CVE's reachability answer), reachability. An asked Privacy violation's source is
    config where data_subjects caps the answer given."""
    if f in CONSTANT:
        return "constant"
    if f == "S":
        return "config"
    if _unreached(f, floored, reach):
        return REACH_SOURCE
    if f in ("M", "O", "EE"):
        # Without a description the level is cannot_tell's, still recorded as the answer's.
        return "answer"
    if not asked(f, dep, floored, described):
        if f in ("ID", "NC"):
            return "config"
        if f == "PV":
            return "floor" if "C" in floored else "config"
        return "floor"
    ds = dep["data_subjects"]
    if f == "PV" and answer is not None and ds is not None and PV_CAP[ds] < ANSWERS["PV"][answer]:
        return "config"
    return "answer"


def questions(dep, floored, described=True, *, reach=None):
    """The questions a CVE gets, in the order its calls ask them: under b7c0435's contract (reach None) the factors
    asked; under 19b333a's, R first, then those its answer, reach, leaves."""
    order = QUESTIONS if reach is None else REACH_QUESTIONS
    return [q for q in order if asked(q, dep, floored, described, reach=reach)]


def question_of(human_prompt):
    """The question a call asks, from the answer ids its prompt lists, at b7c0435 or 19b333a: a factor, or R for
    reachability; None for another call."""
    lines = human_prompt.split("\n")
    if "ANSWERS" not in lines:
        return None
    ids = []
    for line in lines[lines.index("ANSWERS") + 1:]:
        if not line.startswith("- "):
            break
        ids.append(line[2:].partition(":")[0])
    found = {f for table in (ANSWER_IDS, REACH_ANSWER_IDS) for f, known in table.items() if tuple(ids) == known}
    return next(iter(found)) if len(found) == 1 else None
