"""The report's scenario section, its KPI measures and what the records cannot show (chain/report.py renders the
rest)."""
import collections
from fractions import Fraction

from chain import conform, contract, families, verdicts
from chain import cells as cellmod
from chain.report import NA, num, ordered, table


def _v(x):
    if isinstance(x, bool):
        return "yes" if x else "no"
    if isinstance(x, tuple):
        return "+".join(x) or "none"
    return num(float(x) if isinstance(x, Fraction) else x, 3)


def _show(check, x):
    """A value as printed: a VEX status by its state and justification (its detail is what the check compares)."""
    if check.quantity == "status" and isinstance(x, tuple):
        return "/".join(str(v) for v in x[:2]) or "none"
    return _v(x)


def _tally(items):
    return ", ".join(f"{k} x{n}" for k, n in collections.Counter(items).most_common()) or NA


def _diffs(row, check):
    if check.pairs():
        if check.quantity == "status":
            return _tally(f"{_show(check, p['a'])} / {_show(check, p['b'])}" for p in row["per"])
        if check.quantity.startswith("answer ") or check.quantity == "severity":
            return _tally("same" if p["a"] == p["b"] else "differ" for p in row["per"])
        return "b - a: " + _tally(_v(Fraction(p["b"]) - Fraction(p["a"])) for p in row["per"])
    return _tally(_show(check, p["value"]) for p in row["per"])


def _medians(row, check):
    show = lambda x: NA if x is None else _show(check, x)
    if check.pairs():
        return f"{show(row['median'][0])} -> {show(row['median'][1])}"
    return show(row["median"][0])


def _verdict(row, kind):
    if kind == verdicts.DIAGNOSTIC:
        return "judged by nothing"
    ok = row["median"][-1]
    passed = sum(1 for p in row["per"] if p["ok"])
    if kind == verdicts.IMPLEMENTATION:
        return f"every replicate: {families.every_replicate(row)} (pass {passed} of {len(row['per'])})"
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
        item = (" / ".join(row["item"]) if c.pairs() else row["item"]) + (" [vectorless]" if r.get("vectorless")
                                                                           else "")
        verdict = _verdict(row, r["kind"])
        verdict = verdict if r.get("certified", True) else \
            f"not certified, a run off {r.get('rules', contract.B7C0435)}'s contract: {verdict}"
        out.append([c.label, r["arm"], r["kind"], r["model"], item, _diffs(row, c), _medians(row, c), verdict,
                    cellmod.replicates(row["missing"]) if row["missing"] else "none",
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
    uncertified = sum(1 for r in sc["rows"] if not r.get("certified", True))
    if uncertified:
        out += [f"{uncertified} row(s) read after runs off the contract their kinds come from, such as runs that ask "
                f"reachability (R) under chain/verdicts.py's b7c0435 rules, which have no R: those rules certify none "
                f"of them (\"not certified\" below).", ""]
    binding = conform.implementation_rows(sc["rows"])
    if any(r.get("rules") == contract.C1C2 for r in sc["rows"]):
        out += ["Under C1 + C2 (rules c1c2), a status is Go's, from the scenario's config: an implementation check "
                "passes where every replicate does (plan Z0's showcase contract). A row tagged [vectorless] reads a "
                "CVE without a usable CVSS v3 vector, its LC, LI and LAV at 9.", ""]
        out += _binding(binding, conform.required(sc["rows"]))
    by_family, gated = collections.OrderedDict(), families.gates(sc["rows"])
    for r in sc["rows"]:
        by_family.setdefault(r["check"].family, []).append(r)
    for family, rows in by_family.items():
        out += [f"#### {family}", ""]
        if family == "showcases":
            out += ["; ".join(f"{sid}: {text}" for sid, text in (sc.get("headings") or {}).items()) + ".", ""]
        out += table(["check", "arm", "kind", "model", "scenarios", "values", "medians", "verdict", "missing",
                      "sources (after)", "moves"], _check_rows(rows))
        out += _gates(gated, family, binding)
        for (fam, model), counter in sorted(sc["moves"].items()):
            if fam == family and counter:
                word = ("all Go's: the after's move here is Go's, not the model's reading"
                        if families.all_gos(counter) else "no factor moved" if set(counter) == {families.NONE}
                        else "not all Go's")
                out += [f"After, {model}: moves {_tally(counter.elements())}; {word}.", ""]
    return out


def _share(x):
    return NA if x is None else num(x, 2)


def _binding(binding, required):
    """Plan Z0's every-replicate reading of the implementation checks, which binds: the counts, then each row failing,
    inconclusive or missing."""
    counts = collections.Counter(binding.values())
    out = [f"Implementation checks (plan Z0, every replicate; binding): {counts['pass']} pass, {counts['fail']} fail, "
           f"{counts['inconclusive']} inconclusive", ""]
    out += [f"- {label} · {conform.name(item)} · {model}: {verdict}"
            for (label, item, model), verdict in sorted(binding.items(), key=str) if verdict != "pass"]
    out += [f"- {label} · {conform.name(item)} · {model}: missing"
            for label, item, model in sorted(required - set(binding), key=str)]
    return out + ([""] if out[2:] else [])


def _gates(gated, family, binding=None):
    """read5's eligibility rule on the family's items (families.gates): where the before passes in fewer than
    FAMILY_ROBUST of its replicates, the item is not gated. Beside an implementation check's, the every-replicate
    reading that binds."""
    found = [(k, v) for k, v in gated.items() if k[0] == family]
    if not found:
        return []
    out = [f"read5's rule (an item gates where the before passes in at least {families.FAMILY_ROBUST} of its "
           f"replicates):", ""]
    for (_, label, item, model), (pb, fa, verdict) in found:
        bound = (binding or {}).get((label, item, model))
        out.append(f"- {label} · {conform.name(item)} · {model}: the before passes {_share(pb)}, the after fails "
                   f"{_share(fa)}: {verdict}" + ("." if bound is None else f"; read5's eligibility, printed beside; "
                                                 f"the every-replicate reading binds: {bound}."))
    return out + [""]


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


def c2_reads(data):
    """What C2 reads of the reports scored, printed first, the demo scan and the scenarios apart; then, under C1 + C2
    pinned, every after run recomputed (chain/conform.py)."""
    found = data.get("c2") or {}
    out = [] if not found else ["## What C2 reads of the reports", "", "The CVSS v3 vectors C2 gives Loss of "
                                "confidentiality, integrity and availability from (310-c1c2), read by "
                                "chain/contract.py whatever the after's commit.", ""] + \
        [f"- {contract.counts_line(name, c)}." for name, c in found.items()] + [""]
    return out + _recomputed(data)


def _recomputed(data):
    read = data.get("implementation")
    if read is None:
        return []
    w = data.get("witnesses")
    out = ["## C1 + C2 recomputed on every after run", "",
           f"The after's contract pinned: {data.get('rules')}. Each CVE of each complete after run against its frozen "
           "inputs and its own answers: the VEX status its config's reachability entries and the executable witnesses "
           f"publish, the declared block's entries and the 16 levels. Executable witnesses: "
           + (f"{len(w['entries'])} from `{w['name']}` (sha256 {w['sha256']})" if w else "none given") + ". On the "
           "demo scan no CVE may hold a VEX status or a declared block: its contexts declare no reachability.", ""]
    for k, c in sorted(read.items(), key=lambda kc: cellmod.label(kc[0])):
        demo_line = "" if k.corpus == cellmod.SCENARIOS else f"; {len(c['statuses'])} CVE(s) holding a status"
        out.append(f"- {cellmod.label(k)}: {c['runs']} run(s), {c['cves']} CVE(s), {len(c['problems'])} off their "
                   f"recomputation{demo_line}" + (f"; not recomputed: {c['unread']}" if c["unread"] else "") + ".")
    gate = data.get("gate") or []
    out += ["", f"C1 + C2's implementation gate: {'pass' if not gate else f'{len(gate)} failure(s), no go'}.", ""]
    return out + [f"- {g}" for g in gate] + ([""] if gate else [])


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
    sizes, some = [b for b in batches if b is not None], " that record it" if None in batches else ""
    line = ("no run read" if not batches else "not recorded in any run read" if not sizes else
            f"every run read{some} is at batch 1, one CVE per call: batch interaction is not measured" if sizes == [1]
            else f"the runs read{some} are at batch sizes {', '.join(map(str, sizes))}; each size is its own cell, "
                 f"never pooled, and no statistic here compares two sizes")
    return ["## What these records cannot show", "", f"- Batch size: {line}."] + [f"- {s}" for s in SCOPE] + [""]
