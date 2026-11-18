"""The report's scenario section, its KPI measures and what the records cannot show (chain/report.py renders the
rest)."""
import collections
from fractions import Fraction

from chain import families, verdicts
from chain import cells as cellmod
from chain.report import NA, num, ordered, table


def _v(x):
    if isinstance(x, tuple):
        return "+".join(x) or "none"
    return num(float(x) if isinstance(x, Fraction) else x, 3)


def _tally(items):
    return ", ".join(f"{k} x{n}" for k, n in collections.Counter(items).most_common()) or NA


def _diffs(row, check):
    if check.pairs():
        if check.quantity.startswith("answer ") or check.quantity == "severity":
            return _tally("same" if p["a"] == p["b"] else "differ" for p in row["per"])
        return "b - a: " + _tally(_v(Fraction(p["b"]) - Fraction(p["a"])) for p in row["per"])
    return _tally(_v(p["value"]) for p in row["per"])


def _medians(row, check):
    show = lambda x: NA if x is None else _v(x)
    if check.pairs():
        return f"{show(row['median'][0])} -> {show(row['median'][1])}"
    return show(row["median"][0])


def _verdict(row, kind):
    if kind == verdicts.DIAGNOSTIC:
        return "judged by nothing"
    ok = row["median"][-1]
    passed = sum(1 for p in row["per"] if p["ok"])
    return f"pass {passed} of {len(row['per'])}; on the medians {'missing' if ok is None else 'pass' if ok else 'fail'}"


def _moves(row):
    moves = [p["move"] for p in row["per"] if p.get("move") is not None]
    if not moves:
        return ""
    example = next((p for p in row["per"] if p.get("moved")), None)
    if example is None:
        return _tally(moves)
    return _tally(moves) + f"; e.g. r{example['replicate']}: " + ", ".join(
        f"{f} {a}->{b} ({sa}/{sb}{', same answer' if same else ''})" for f, a, b, sa, sb, same in example["moved"])


def _by_replicate(row, text_of):
    """One entry per text, the replicates that give it, in a table cell: no pipe."""
    groups = {}
    for p in row["per"]:
        text = text_of(p)
        if text:
            groups.setdefault(text, []).append(p["replicate"])
    return "; ".join(f"{cellmod.replicates(reps)}: {text}" for text, reps in groups.items())


def _sources(row):
    """The after's sources of the quantity's factors, replicate by replicate, a / b where the two differ."""
    word = lambda a, b: str(a) if a == b else f"{a}/{b}"
    return _by_replicate(row, lambda p: ", ".join(f"{' '.join(fs)} {word(a, b)}"
                                                  for (a, b), fs in (p.get("sources") or {}).items()))


def _levels(row):
    """On one scenario, the after's levels of the quantity's factors by source, replicate by replicate."""
    def text(p):
        by = {}
        for f, (level, src) in (p.get("levels") or {}).items():
            by.setdefault(src, []).append(f"{f}={level}")
        return ", ".join(f"{' '.join(fs)} {src}" for src, fs in by.items())
    return _by_replicate(row, text)


def _check_rows(rows):
    out = []
    for r in rows:
        c, row = r["check"], r["row"]
        item = " / ".join(row["item"]) if c.pairs() else row["item"]
        out.append([c.label, r["arm"], r["kind"], r["model"], item, _diffs(row, c), _medians(row, c),
                    _verdict(row, r["kind"]), cellmod.replicates(row["missing"]) if row["missing"] else "none",
                    _sources(row) if c.pairs() else _levels(row), _moves(row)])
    return out


def families_section(sc):
    out = ["### The families, the showcases and reachability", "",
           "Per check, arm and model, replicate by replicate, a pair's two runs of one replicate together; a "
           "diagnostic is printed and judged by nothing. The medians are over each scenario's runs, the most common "
           "value for a severity or an answer. The after's sources: where each factor of the quantity took its level, "
           "replicate by replicate, a / b where the two differ; on one scenario, each factor's level by its source. "
           "The move, in the after: none, Go's (levels Go set, or one answer Go crossed with a declared field), the "
           "model's (both runs answered, the answers differ), or mixed (any other mix, a level Go set in one run "
           "and answered in the other among them).", ""]
    by_family = collections.OrderedDict()
    for r in sc["rows"]:
        by_family.setdefault(r["check"].family, []).append(r)
    for family, rows in by_family.items():
        out += [f"#### {family}", ""]
        if family == "showcases":
            out += ["; ".join(f"{sid}: {text}" for sid, text in (sc.get("headings") or {}).items()) + ".", ""]
        out += table(["check", "arm", "kind", "model", "scenarios", "values", "medians", "verdict", "missing",
                      "sources (after)", "moves"], _check_rows(rows))
        for (fam, model), counter in sorted(sc["moves"].items()):
            if fam == family and counter:
                word = ("all Go's: the after's move here is Go's, not the model's reading"
                        if families.all_gos(counter) else "no factor moved" if set(counter) == {families.NONE}
                        else "not all Go's")
                out += [f"After, {model}: moves {_tally(counter.elements())}; {word}.", ""]
    return out


def consistency(sc):
    c = sc["consistency"]
    out = ["### Consistency (diagnostic)", "", "The SD (n - 1) of the score over the replicates, averaged over the "
           "scenarios; for the after, each question's answer agreement over the replicate pairs.", ""]
    if not c["score_sd"]:
        return out + ["Needs two replicates: none here.", ""]
    out += table(["model", "arm", "mean score SD", "scenarios"],
                 [[m, a, num(v), n] for (m, a), (v, n) in ordered(c["score_sd"])])
    if c["answers"]:
        out += table(["model", "question", "answer agreement", "scenarios"],
                     [[m, q, num(v), n] for (m, q), (v, n) in ordered(c["answers"])])
    return out


def wrong_yaml(sc):
    out = ["### The wrong YAML (diagnostic)", "", "wrong_yaml's context contradicts its CVE's text.", ""]
    rows = []
    for (model, arm), runs in ordered(sc["wrong_yaml"]):
        for rep, score, sev, lv in runs:
            by = collections.defaultdict(list)
            for f, (level, src) in (lv or {}).items():
                by[src].append(f"{f}{level}")
            rows.append([model, arm, f"r{rep}", _v(score), NA if sev is None else sev,
                         "; ".join(f"{s}: {' '.join(v)}" for s, v in sorted(by.items()))
                         or "no rated answers.json entry"])
    return out + (table(["model", "arm", "run", "score", "severity", "levels by source"], rows) if rows
                  else ["Not run.", ""])


def _fallback(fb):
    if fb is None:
        return "not given (--fallback)."
    return (f"from campaign {fb['campaign']} (`{fb['path']}`), vens {fb['commit']}, vens's mock with "
            f"VENS_MOCK_LLM_CANNOT_TELL={fb['flag']}.")


def _summary(s):
    score, sev, scored, runs = s
    return f"{_v(score)} {NA if sev is None else sev} ({runs if scored == runs else f'{runs} runs, {scored} scored'})"


def null_table(sc):
    out = ["### Against the null model (diagnostic)", "",
           "baseline.py's four aggregates per scenario, scored under the before's rule and under the after's; each "
           "arm's median score and most common severity per model (n/a on a tie), over the runs that give one "
           "(runs); and the after's conservative fallback, every answer cannot_tell, " + _fallback(sc["fallback"])
           + " The fallback is not a null model.", ""]
    rows = []
    for t in sc["null"]:
        n, rules, fb = t["null"], t["rules"], t["fallback"]
        arms = "; ".join(f"{m} {a}: {_summary(s)}" for (m, a), s in sorted(t["arms"].items()))
        rows.append([t["scenario"], f"{n['threat_agent']}/{n['vulnerability']}/{n['technical_impact']}/"
                     f"{n['business_impact']}", f"{_v(rules['before'][0])} {rules['before'][1]}",
                     f"{_v(rules['after'][0])} {rules['after'][1]}", arms or "not run",
                     NA if fb is None else _summary(fb)])
    return out + table(["scenario", "null TA/VU/T/B", "null, before's rule", "null, after's rule", "runs",
                        "fallback"], rows)


def scenarios(data):
    sc = data["scenarios"]
    if sc is None:
        return ["## The scenarios", "", "No scenario campaign read.", ""]
    return ["## The scenarios", ""] + families_section(sc) + consistency(sc) + wrong_yaml(sc) + null_table(sc)


def _stability(k):
    rows = []
    for (campaign, model, ctx, arm), s in ordered(k["stability"]):
        low = sorted((v, f) for f, v in s["factor"].items() if v is not None)[:3]
        answers = ", ".join(f"{f} {num(v, 2)}" for f, v in (s.get("answers") or {}).items())
        rows.append([f"{campaign} · {model}", ctx, arm, cellmod.replicates(s["replicates"]), s["cves"],
                     num(s["vector"]),
                     ", ".join(f"{f} {num(v, 2)}" for v, f in low) or NA, num(s["severity_unchanged"]),
                     answers or NA])
    return ["### Stability", "", "Each model's MPD and run spreads are the floor's, above. Agreement is the mean over "
            "the CVEs of the share of run pairs alike, n/a below two runs; the factors listed are the three least "
            "stable.", ""] + \
        (table(["campaign · model", "context", "arm", "replicates", "CVEs", "vector agreement", "least stable factors",
                "severity unchanged in every run", "answer agreement per question"], rows) if rows
         else ["No demo-scan run.", ""])


def _context(k):
    rows = []
    for (campaign, model, arm), c in ordered(k["context"]):
        for (x, y), p in c["pairs"].items():
            ans = ", ".join(f"{f} {num(a, 2)}/{num(w, 2)}" for f, (a, w) in (p.get("answers") or {}).items())
            rows.append([f"{campaign} · {model}", arm, _reps_by(c["replicates"]), c["cves"], num(c["in_order"]),
                         f"{x} -> {y}",
                         num(p["gap"]),
                         num(p["noise"]), ans or NA])
    return ["### Context sensitivity", "", "The share of CVEs whose mean L does not fall from internal to internal-api "
            "to internet-facing; per context pair, the mean gap in L against the noise floor (the mean of the two "
            "contexts' MPDs of L); for the after, per question, answer agreement across the pair / within it.", ""] + \
        (table(["campaign · model", "arm", "replicates", "CVEs", "in order", "pair", "gap in L", "noise floor",
                "answers across/within"], rows)
         if rows else ["Needs the three contexts: not all read here.", ""])


def _reps_by(by_context):
    return "; ".join(f"{ctx} {cellmod.replicates(reps)}" for ctx, reps in sorted(by_context.items()))


def _tally_dict(d):
    return ", ".join(f"{k} {v}" for k, v in sorted(d.items()) if v) or "none"


def _failures(k):
    rows = []
    for key, f in ordered(k["failures"]):
        ct = f["cannot_tell"]
        qs = ", ".join(f"{q} {num(v['rate'], 2)} ({num(v['agreement'], 2)})" for q, v in ct["questions"].items()
                       if v["rate"])
        rows.append([cellmod.label(key), f["incomplete"], _tally_dict(f["defects"]), sum(f["failed"].values()),
                     cellmod.replicates(f["without_complete"]) if f["without_complete"] else "none", qs or "none",
                     num(ct["cves_affected"])])
    return ["### Failures, with cannot_tell apart", "", "cannot_tell per question: its rate over the questions "
            "answered (its repeat-run agreement); CVEs affected: the mean share of a run's CVEs with one.", ""] + \
        table(["cell", "complete, record incomplete", "defects", "failed attempts",
               "replicates without a complete attempt", "cannot_tell", "CVEs affected"], rows)


def kpis(data):
    k = data["kpi"]
    out = ["## KPI measures", "", "Stability, sensitivity and conformance; none of them measures validity.", ""]
    out += _stability(k)
    out += ["### Model sensitivity", "", "The mean per-CVE gap of the two models' mean scores, and the CVEs whose "
            "ranges over the runs do not overlap; Delta, its gap test and band agreement are above.", ""]
    rows = [[campaign, ctx, arm, a, b, " / ".join(cellmod.replicates(x) for x in m["replicates"]), m["cves"],
             num(m["gap"], 2), m["apart"]] for (campaign, ctx, arm, a, b), m in ordered(k["model"])]
    out += table(["campaign", "context", "arm", "model a", "model b", "replicates a / b", "CVEs", "mean gap",
                  "CVEs apart"],
                 rows) if rows else \
        ["Needs two models: none here.", ""]
    out += _context(k)
    out += ["### Discrimination", "", "W and H per run are above; across the contexts, the SD of each CVE's mean "
            "score pooled over them.", ""]
    out += table(["campaign · model", "arm", "replicates", "values", "pooled SD"],
                 [[f"{cp} · {m}", a, _reps_by(d["replicates"]), d["values"], num(d["sd"], 2)]
                  for (cp, m, a), d in ordered(k["discrimination"])])
    out += _failures(k)
    out += ["### Cost per run", "", "Calls and wall time are counted from the records; the dollars are the estimate "
            "above, not the usage exports'.", ""]
    out += table(["cell", "replicates", "calls per run", "calls per CVE", "recovery calls per run",
                  "wall time per run, s", "estimate per run, USD", "estimate per CVE, USD"],
                 [[cellmod.label(key), cellmod.replicates(c["replicates"]), num(c["calls_per_run"], 1),
                   num(c["calls_per_cve"], 2),
                   num(c["recovery_per_run"], 2), num(c["wall_seconds"], 0), num(c["usd_per_run"], 4),
                   num(c["usd_per_cve"], 5)] for key, c in ordered(k["cost"])])
    return out + ["Conformance's checks with known expectations are vens's own Go tests on each commit, and the Java "
                  "check's targets above.", ""]


SCOPE = (
    "Batch interaction: the scenarios hold one CVE each, so within-project spread, ranking entropy, the cross-model "
    "spread and the floor are the demo scan's.",
    "Grype: both corpora are Trivy reports.",
    "The adjustment: no scenario is flagged; the demo scan holds the flagged CVEs, none without a description.",
    "Motive, reward and reputation: no scenario varies them.",
    "EPSS and KEV: vens reads neither; a dated check of Ease of exploit needs real ids, the demo scan's.",
    "Intrusion detection's channels and its application rate: unmeasured where a context declares its three "
    "channels at one level, which leaves the question unasked.",
    "Opportunity on CVEs no draw has used: reported apart, a diagnostic; testing it needs labels no corpus carries.",
    "Non-compliance's model claim: the compliance pair cannot show it, Go setting the level without a framework.",
    "The model's reading of confidentiality and integrity on the discriminators: set by the vectors there; the "
    "copies without a vector show it, judged by nothing.",
    "The cost per attempt and per kind of call: an estimate; the measured figure is a campaign's, an arm's only with "
    "a key per arm and provider.",
    "Validity: a family's direction is the one the scenarios' generator documents; agreement with it, or between "
    "models, is consistency, not correctness.")


def scope(data):
    batches = data.get("batches") or []
    line = ("every run read is at batch 1, one CVE per call: batch interaction is not measured" if batches == [1] else
            f"the runs read are at batch sizes {', '.join(map(str, batches))}; each size is its own cell, never "
            f"pooled, and no statistic here compares two sizes" if batches else "no run read")
    return ["## What these records cannot show", "", f"- Batch size: {line}."] + [f"- {s}" for s in SCOPE] + [""]
