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

C1 + C2, the candidate of venslabs/vens#310's plans Z0 and Z0d (no reachability relay), as vens 310-c1c2 builds it at
N (N_COMMIT; 2de5d34 relayed and pins nothing), take the c1c2_ functions. No R and no reachability input at all: a
CVE gets at most nine questions, M, O, EE, ID, LAC, FD, RD, NC and PV, under b7c0435's rules. Loss of confidentiality,
integrity and availability are Go's, source cvss: the worst value each axis takes over the CVE's usable CVSS v3
vectors (impact(), pkg/cvss/impact.go) through C2's table, confidentiality crossed with data_sensitivity; with none
usable, each at 9 and the CVE counted cvss_v3_missing. Privacy violation keeps a floor, 3 from source floor and not
asked, where usable vectors exist and their worst C is N; a flagged CVE's adjustment asks opportunity when it is
described and confidentiality when Privacy violation was asked, and lowers Privacy violation alone. The system prompt
is b7c0435's byte for byte. vens publishes no VEX status: chain/conform.py fails any run holding one, or a declared
block. tests/test_c1c2.py checks these rules, tests/test_c1c2_mock.py against N's mock.

C1 + C2', the candidate since C2''s one-shot screen (plan Z0d section 2), as vens 310-c1c2 builds it at the C2' commit
(C2P_COMMIT, N plus C2'), take the same functions with rules=C1C2P: C1 + C2 but Loss of availability, read in
availability_requirement's column, OWASP's secondary then primary services, C2P_LAV, z8_replay.py's table; low and
medium are secondary, high and critical primary; unset reads primary and the CVE, one with a usable v3 vector, counts
availability_requirement_missing once. The field is read as vens loads it: absent or null unset, any other value
trimmed and lowercased as Go does, refused off the four. tests/test_c1c2p.py checks these rules,
tests/test_c1c2_mock.py against the C2' commit's mock and its Go counts on the demo scan.

The marker commit (MARKER_COMMIT; EARLIER_MARKERS, read the same; agreed.md items 2 and 5) pins C1 + C2' too, its
levels C2''s, and writes on each VEX vulnerability one property vens:impact-provenance: missing-cvss-v3-fallback where
no usable v3 vector gave the three impacts, cvss-v3 otherwise. chain/conform.py requires it of those commits' runs,
keyed on the run's commit, and fails it on any other's.
"""
import collections
import json

from chain.cdx import FACTORS

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
    """What the rules read from a schema-2 config: exposure, data sensitivity, frameworks, G2 to G4 and
    availability_requirement, None where undeclared."""
    ctx = config["context"]
    return {"exposure": ctx["exposure"], "data_sensitivity": ctx["data_sensitivity"],
            "frameworks": tuple(ctx.get("compliance_requirements") or ()), "detection": ctx.get("detection"),
            "traceability": ctx.get("traceability"), "data_subjects": ctx.get("data_subjects"),
            "availability_requirement": availability_requirement(ctx)}


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


# ---- C1 + C2 and C1 + C2', no reachability relay: vens 310-c1c2 at N and at the C2' commit ----

B7C0435, REACH_RULES, C1C2, C1C2P = "b7c0435", "5f797bf", "c1c2", "c1c2p"
# N, the commit on 310-c1c2 over 2de5d34 that removes the reachability relay (plan Z0d section 1).
N_COMMIT = "33a5dbf2ae8d7a6522874058de659e1b58f422aa"
# The C2' commit, N plus C2' (plan Z0d section 2), S2's after: re-pinned here alone if it is amended.
C2P_COMMIT = "861017143dec63e24097c8979ffd02bc9efff27b"
# The marker commit, the C2' commit plus the vens:impact-provenance VEX property, S2's after: re-pinned here alone.
# e3007ed also sorts each CVE's rows and counts severity_contested_unavailable on both scanners.
MARKER_COMMIT = "e3007ed5db9cce0e9810a466d17cee5880b29bd4"
# Earlier marker commits, still read as such: 7ce0211, the first to write the property.
EARLIER_MARKERS = ("7ce0211bb3abef311bc3dd29be23b9ecdb4a861c",)
# The contract each pinned after commit follows; any other commit pins none. 2de5d34 relays declared reachability,
# which C1 no longer allows: S1's frozen reader reads it, this chain pins it to nothing.
CONTRACTS = {"b7c0435835447027b04d54d4e6befaaee6b0626b": B7C0435,
             "5f797bfbd8e3a0ae49200f9d64861558240b8361": REACH_RULES, N_COMMIT: C1C2, C2P_COMMIT: C1C2P,
             **dict.fromkeys(EARLIER_MARKERS + ((MARKER_COMMIT,) if MARKER_COMMIT else ()), C1C2P)}
# The no-relay contracts, whose technical impacts are Go's, from the CVSS v3 vectors.
C1C2_RULES = (C1C2, C1C2P)
NAMES = {C1C2: "C1 + C2", C1C2P: "C1 + C2'"}
C1C2_QUESTIONS = ("M", "O", "EE", "ID", "LAC", "FD", "RD", "NC", "PV")
CVSS_SOURCE, FLOOR_SOURCE, ADJUSTMENT_SOURCE = "cvss", "floor", "adjustment"
VECTOR_MISSING = "cvss_v3_missing"
# C2's table: the level each worst v3 value gives; confidentiality's non-sensitive then critical column.
C2_LC = {"N": (2, 2), "L": (2, 6), "H": (6, 7)}
C2_LI = {"N": 1, "L": 3, "H": 7}
C2_LAV = {"N": 1, "L": 5, "H": 7}
VECTORLESS_LEVEL = 9
# C2''s Loss of availability, (secondary, primary) services per worst A; availability_requirement's cut; the counter of
# a CVE read in the primary column for want of the field.
C2P_LAV = {"N": (1, 1), "L": (1, 5), "H": (5, 7)}
PRIMARY_SERVICES = {"low": False, "medium": False, "high": True, "critical": True}
AVAILABILITY_MISSING = "availability_requirement_missing"
# The marker commit's VEX property and its two values.
PROVENANCE, FROM_CVSS_V3, FALLBACK = "vens:impact-provenance", "cvss-v3", "missing-cvss-v3-fallback"
# H over L over N.
WORSE = {"N": 0, "L": 1, "H": 2}
# The adjustment's fields.
OPPORTUNITY, CONFIDENTIALITY = "opportunity", "confidentiality"
# The confidentiality answer that lowers Privacy violation to its floor.
NOT_AFFECTED = "not_affected"
# strings.TrimSpace's set, Unicode White_Space: str.strip() also takes \x1c to \x1f, which Go keeps.
GO_SPACE = "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a" \
           "\u2028\u2029\u202f\u205f\u3000"
TIERS = {"2.0": 2, "2": 2, "3.0": 3, "3.1": 3, "3": 3, "4.0": 4}
TRIVY_FIELDS = (("V2Vector", "2.0"), ("V3Vector", "3"), ("V40Vector", "4.0"))

# What a CVE's CVSS v3 vectors give the three technical impacts: values, {C, I, A: worst value}, empty without a
# usable vector; usable, the distinct usable vectors; rejected, (vector, why) per distinct v3 vector refused whole;
# v4, the distinct v4 vectors, counted, not read.
Impact = collections.namedtuple("Impact", "values usable rejected v4")
NO_IMPACT_READ = Impact({}, 0, (), 0)


def go_trim(text):
    return text.strip(GO_SPACE)


def go_lower(text):
    """strings.ToLower: each rune's simple lowercase, which str.lower() gives but for U+0130, made i."""
    return "".join("i" if c == "\u0130" else c.lower() for c in text)


def availability_requirement(ctx):
    """A config context's availability_requirement as vens loads it: None when absent or null, else trimmed and
    lowercased; ValueError off low, medium, high and critical."""
    value = (ctx or {}).get("availability_requirement")
    if value is None:
        return None
    norm = go_lower(go_trim(value)) if isinstance(value, str) else None
    if norm not in PRIMARY_SERVICES:
        raise ValueError(f"availability_requirement {value!r} is not low, medium, high or critical")
    return norm


def primary_services(dep):
    """Whether Loss of availability reads the primary services column: availability_requirement high or critical,
    or unset."""
    value = dep.get("availability_requirement")
    return value is None or PRIMARY_SERVICES[value]


def prefix_version(vector):
    """The version a vector's CVSS: prefix states, past surrounding space, the prefix in any case (ASCII: Go compares
    its first five bytes); None without one. 'CVSS:/...' states ''."""
    text = go_trim(vector)
    if text.encode()[:5].lower() != b"cvss:":
        return None
    return text[5:].partition("/")[0]


def tier(version):
    return TIERS.get(version, 0)


def trivy_vectors(f):
    """vens's trivyVectors: every vector of a Trivy finding, sources in name order, each source's v2, v3 and v4 in that
    order, as (source, version, vector); the version is the one its CVSS: prefix states, else its field's."""
    out = []
    by_source = f.get("CVSS") or {}
    for source in sorted(by_source):
        for field, unprefixed in TRIVY_FIELDS:
            v = (by_source[source] or {}).get(field)
            if v:
                version = prefix_version(v)
                out.append((source, unprefixed if version is None else version, v))
    return out


def _v3_values(version, vector):
    """({C, I, A: value}, None) of a v3 vector, or (None, why it is refused whole): pkg/cvss's impactValues and
    Parse."""
    if tier(version) != 3:
        return None, f"CVSS version {version!r} is neither 3.0 nor 3.1"
    stated = prefix_version(vector)
    if stated is not None and stated not in ("3.0", "3.1"):
        return None, f"prefix CVSS:{stated} states neither 3.0 nor 3.1"
    body = go_trim(vector)
    if stated is not None:
        body = body[5:].partition("/")[2]
    metrics = {}
    for part in body.split("/"):
        metric, _, value = part.partition(":")
        if not metric or not value or ":" in value:
            return None, f"{part!r} is not a metric:value pair"
        if metric in metrics:
            return None, f"metric {metric} given twice"
        metrics[metric] = value
    if any(metrics.get(a) not in WORSE for a in AXES):
        return None, f"{next(a for a in AXES if metrics.get(a) not in WORSE)} is absent or off H, L and N"
    return {a: metrics[a] for a in AXES}, None


def impact(vectors):
    """cvss.ImpactOf over (source, version, vector): a v3 vector is one whose version reads as 3, or another 3.x,
    distinct once trimmed; usable when its version is 3.0, 3.1 or 3, a prefix states 3.0 or 3.1, it parses and gives C,
    I and A on H, L or N; any other v3 vector is refused whole. v2 is not read; v4 is counted."""
    worst, usable, rejected, seen, seen4 = {}, 0, [], [], []
    for _, version, vector in vectors:
        text = go_trim(vector)
        if tier(version) == 4:
            seen4 += [] if text in seen4 else [text]
            continue
        if (tier(version) != 3 and not version.startswith("3.")) or text in seen:
            continue
        seen.append(text)
        values, why = _v3_values(version, vector)
        if values is None:
            rejected.append((vector, why))
            continue
        usable += 1
        for a, x in values.items():
            if a not in worst or WORSE[x] > WORSE[worst[a]]:
                worst[a] = x
    return Impact(worst, usable, tuple(rejected), len(seen4))


def cve_impact(findings):
    """impact() over every vector of every row of one CVE, in row order."""
    return impact([v for f in findings for v in trivy_vectors(f)])


def privacy_floored(imp):
    """Whether Privacy violation takes its floor: a usable v3 vector, and C:N their worst confidentiality."""
    return imp.usable > 0 and imp.values["C"] == "N"


def _pv_floor(imp):
    """The floored axes b7c0435's rules read, under C1 + C2: confidentiality's alone, for Privacy violation."""
    return frozenset("C") if privacy_floored(imp) else frozenset()


def impact_level(f, dep, imp, rules=C1C2):
    """Loss of confidentiality's, integrity's or availability's level from C2's table, availability's from C2''s under
    rules C1C2P, 9 without a usable vector."""
    if imp.usable == 0:
        return VECTORLESS_LEVEL
    value = imp.values[AXIS[f]]
    if f == "LC":
        return C2_LC[value][int(CRITICAL_DATA[dep["data_sensitivity"]])]
    if f == "LAV" and rules == C1C2P:
        return C2P_LAV[value][int(primary_services(dep))]
    return (C2_LI if f == "LI" else C2_LAV)[value]


def c1c2_counters(dep, imp, rules=C1C2):
    """The counters Go adds for the three technical impacts: cvss_v3_missing without a usable vector; under C1 + C2',
    availability_requirement_missing with one, the field unset."""
    if imp.usable == 0:
        return [VECTOR_MISSING]
    return [AVAILABILITY_MISSING] if rules == C1C2P and dep.get("availability_requirement") is None else []


def c2p_shown(lav, counters):
    """Whether a CVE's record shows C1 + C2' rather than C1 + C2: availability_requirement_missing counted, or Loss of
    availability from cvss at the secondary column's level where C2's differs. A record C2 gives shows nothing: C2'
    gives the same where availability_requirement is high or critical."""
    lav, value = lav or {}, (lav or {}).get("cvss")
    secondary = lav.get("source") == CVSS_SOURCE and value in C2P_LAV and C2P_LAV[value][0] != C2_LAV[value] \
        and lav.get("level") == C2P_LAV[value][0]
    return AVAILABILITY_MISSING in (counters or ()) or secondary


def marker_commit(commit):
    """Whether a run's vens commit is the marker commit or an earlier one, which alone write vens:impact-provenance."""
    return commit is not None and commit in (MARKER_COMMIT,) + EARLIER_MARKERS


def accepted(pinned):
    """The contracts a record may show under the pinned one: C1 + C2's under C1 + C2' too, which gives the same
    record where availability_requirement is high or critical."""
    return {C1C2, C1C2P} if pinned == C1C2P else {pinned}


def c1c2_asked(f, dep, imp, described=True):
    """Whether a CVE gets factor f's question under C1 + C2: one of the nine, as b7c0435 asks it, Privacy violation
    floored by the usable vectors' C:N alone."""
    return f in C1C2_QUESTIONS and asked(f, dep, _pv_floor(imp), described)


def c1c2_questions(dep, imp, described=True):
    return [q for q in C1C2_QUESTIONS if c1c2_asked(q, dep, imp, described)]


def c1c2_options(f, dep, imp, described=True, rules=C1C2):
    """Factor f's level for each answer its question can get, {None: level} where Go sets it, under C1 + C2 or, rules
    C1C2P, C1 + C2'."""
    if f in AXIS:
        return {None: impact_level(f, dep, imp, rules)}
    return options(f, dep, _pv_floor(imp), described)


def c1c2_source(f, dep, imp, answer=None, described=True):
    """Where factor f's level comes from under C1 + C2, before any adjustment: cvss for the three technical impacts,
    floor for a floored Privacy violation, otherwise as under b7c0435."""
    if f in AXIS:
        return CVSS_SOURCE
    return source(f, dep, _pv_floor(imp), answer, described)


def adjustment_fields(dep, imp, described=True):
    """A flagged CVE's adjustment fields: opportunity when it is described, confidentiality when it was asked Privacy
    violation; none, no call."""
    return [OPPORTUNITY] * described + [CONFIDENTIALITY] * c1c2_asked("PV", dep, imp, described)


def _read(f, opts, answer):
    """The level an answer, as the reply wrote it, gives an asked factor: one off the list, or of another shape, reads
    as cannot_tell; Intrusion detection's, a set, takes its lowest channel, empty or holding cannot_tell its worst."""
    if f != "ID":
        return answer if isinstance(answer, str) and answer in opts else CANNOT_TELL, None
    if not isinstance(answer, list) or not answer or any(a not in CHANNELS for a in answer):
        return CANNOT_TELL, opts[CANNOT_TELL]
    return answer, min(opts[a] for a in answer)


def c1c2_levels(dep, imp, described, answers, adjusted=None, rules=C1C2):
    """{factor: (level, source)}, the 16, from a CVE's answers as answers.json writes them ({factor: answer}, an
    unasked factor absent or None) and, for a flagged CVE, its adjustment ({"O": opportunity's answer, "PV":
    confidentiality's}): Compute's rules under C1 + C2 or, rules C1C2P, C1 + C2'. No reachability input reaches
    them."""
    adjusted = adjusted or {}
    out = {}
    for f in FACTORS:
        opts = c1c2_options(f, dep, imp, described, rules)
        if None in opts:
            out[f] = (opts[None], c1c2_source(f, dep, imp, described=described))
            continue
        read, level = _read(f, opts, answers.get(f))
        level = opts[read] if level is None else level
        out[f] = (level, c1c2_source(f, dep, imp, read if f != "ID" else None, described))
    lower = adjusted.get("O")
    if described and lower in ANSWERS["O"] and lower != CANNOT_TELL and ANSWERS["O"][lower] < out["O"][0]:
        out["O"] = (ANSWERS["O"][lower], ADJUSTMENT_SOURCE)
    if adjusted.get("PV") == NOT_AFFECTED and c1c2_asked("PV", dep, imp, described) and FLOOR["PV"] < out["PV"][0]:
        out["PV"] = (FLOOR["PV"], ADJUSTMENT_SOURCE)
    return out


def described(findings):
    """Whether a row of the CVE has a description."""
    return any((f.get("Description") or "").strip() for f in findings)


# ---- what C2 reads of a report ----

def report_cves(report_path):
    """{vulnId: [finding]} of a Trivy report, the ids in first-seen order, each id's findings in report order."""
    with open(report_path, encoding="utf-8") as fh:
        doc = json.load(fh)
    out = {}
    for r in doc.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            out.setdefault(v["VulnerabilityID"], []).append(v)
    return out


def disagreeing_axes(vectors):
    """The axes on which a CVE's usable v3 vectors, each read alone, give different values."""
    alone = [one.values for one in (impact([v]) for v in vectors) if one.usable]
    return [a for a in AXES if any(x[a] != alone[0][a] for x in alone[1:])]


def impact_counts(cves):
    """What C2 reads of a report's CVEs ({vulnId: [finding]}): those with no usable v3 vector, with a v3 vector
    refused, whose usable vectors disagree and on how many axes, with a v4 vector beside, and those whose Privacy
    violation takes its floor."""
    out = dict.fromkeys(("cves", "vectorless", "rejected", "disagree", "disagree_axes", "v4", "pv_floor"), 0)
    for findings in cves.values():
        vectors = [v for f in findings for v in trivy_vectors(f)]
        imp, axes = impact(vectors), disagreeing_axes(vectors)
        out["cves"] += 1
        out["vectorless"] += imp.usable == 0
        out["rejected"] += bool(imp.rejected)
        out["disagree"] += bool(axes)
        out["disagree_axes"] += len(axes)
        out["v4"] += imp.v4 > 0
        out["pv_floor"] += privacy_floored(imp)
    return out


def counts_line(name, c):
    return (f"no usable v3 vector, {name}: {c['vectorless']} of {c['cves']} CVEs (LC, LI, LAV at 9); a rejected v3 "
            f"vector {c['rejected']} CVEs; usable vectors disagreeing {c['disagree']} CVEs, {c['disagree_axes']} axes "
            f"(worst value kept); a v4 vector beside {c['v4']} CVEs; Privacy violation at its floor {c['pv_floor']} "
            f"CVEs")


def main(argv=None):
    import argparse
    import os

    ap = argparse.ArgumentParser(description="What C2 reads of the demo scan and of the scenarios, each apart.")
    ap.add_argument("--demo", help="the demo scan, a Trivy report")
    ap.add_argument("--scenarios", help="the scenario corpus, scenarios/<id>/report.json")
    a = ap.parse_args(argv)
    if a.demo:
        print(counts_line("demo scan", impact_counts(report_cves(a.demo))))
    if a.scenarios:
        cves = {}
        for sid in sorted(os.listdir(a.scenarios)):
            path = os.path.join(a.scenarios, sid, "report.json")
            if os.path.isfile(path):
                cves[sid] = [f for fs in report_cves(path).values() for f in fs]
        print(counts_line("scenarios", impact_counts(cves)))
    return 0


if __name__ == "__main__":
    main()
