"""The analysis's report, Markdown: what was read, the targets, the demo scan's statistics, the scenarios, the
attempts and their calls, the cost and the KPI measures, then what the records cannot show.

Each figure names its cell, arm · provider/model · context or scenario, and the replicates it read; the records
section names each replicate's attempt. Measured figures and estimates sit in separate tables, never summed.
"""
from fractions import Fraction

from chain import cost, ledger, usage
from chain import cells as cellmod

NA = "n/a"


def num(x, d=3):
    if x is None:
        return NA
    if isinstance(x, Fraction):
        x = float(x)
    if isinstance(x, float):
        return f"{x:.{d}f}"
    return str(x)


def share(k, n):
    return NA if k is None or not n else f"{k}/{n} ({k / n:.3f})"


def table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    return out + ["| " + " | ".join(str(c) for c in row) + " |" for row in rows] + [""]


def ordered(d):
    return sorted(d.items(), key=lambda kv: str(kv[0]))


def records(data):
    out = ["## Records", "", "Inputs, each read by chain/read.py:", ""]
    out += [f"- `{path}`: {n} attempts" for path, n in data["inputs"]] + [""]
    rows = []
    for k, c in ordered(data["cells"]):
        led = data["ledgers"][k]
        rows.append([k[0], cellmod.label(k), led["attempts"], led["complete"],
                     f"{len(c['runs'])} ({cellmod.replicates(c['runs'])})", len(c["unusable"]),
                     sum(led["failed"].values()), led["stray"], led["not_read"]])
    out += table(["corpus", "cell", "attempts", "complete", "runs read (replicates)", "complete, not usable",
                  "failed", "stray", "not read"], rows)
    out += ["Each replicate's run is its first complete attempt; a scenario campaign's lie at "
            "`<provider>/<model>/r<n>/<scenario>/<arm>-a<k>`, listed here only when not the first attempt.", ""]
    for k, c in ordered(data["cells"]):
        runs = {rep: rec for rep, rec in c["runs"].items()
                if k[0] == cellmod.DEMO or rec["what"].get("run_attempt") != 1}
        if runs:
            out.append(f"- {cellmod.label(k)}: {cellmod.sources(runs)}")
        for rep, (rec, why) in sorted(c["unusable"].items()):
            out.append(f"- {cellmod.label(k)}: r{rep} {cellmod.source(rec)} complete, its scores not read: {why}")
        out += [f"- {cellmod.label(k)}: {p}" for p in c["problems"]]
    return out + [""]


def _per_run(per, field):
    """Each run's share, once when every run has the same."""
    got = {rep: (t[field], t["cves"]) for rep, t in sorted(per.items())}
    if len(set(got.values())) == 1:
        k, n = next(iter(got.values()))
        return f"each run {share(k, n)}" if len(got) > 1 else share(k, n)
    return "; ".join(f"r{rep} {share(k, n)}" for rep, (k, n) in got.items())


def _demo_rows(data, field):
    rows = []
    for k, per in ordered(data["targets"]):
        if k[0] != cellmod.DEMO:
            continue
        row = [cellmod.label(k), cellmod.replicates(per), next(iter(per.values()))["over"], _per_run(per, field)]
        if field == "recomputable":
            row.append(_per_run(per, "severity_ok"))
        rows.append(row)
    return rows


def _scenario_rows(data, field):
    agg = {}
    for k, per in ordered(data["targets"]):
        if k[0] != cellmod.SCENARIOS:
            continue
        a = agg.setdefault((k[1], cellmod.model_of(k)), {"k": 0, "n": 0, "scenarios": 0, "below": [], "sev": 0})
        a["scenarios"] += 1
        for rep, t in sorted(per.items()):
            a["k"] += t[field]
            a["n"] += t["cves"]
            a["sev"] += t["severity_ok"]
            if t[field] < t["cves"]:
                a["below"].append(f"{k[4]} r{rep}")
    return [[arm, model, a["scenarios"], a["n"], share(a["k"], a["n"]), ", ".join(a["below"]) or "none"]
            + ([share(a["sev"], a["n"])] if field == "recomputable" else []) for (arm, model), a in sorted(agg.items())]


TARGETS = (("legal", "Target (i), the legal-vector share: the report's CVEs whose rating the Java check accepts, a CVE "
                     "without a rating not legal"),
           ("recomputable", "Target (ii), the recomputable-score share: the report's CVEs whose published score equals "
                            "exactly the arm's own formula on the vector; beside it, the severity agreeing with the "
                            "arm's own rule"))


def targets(data):
    out = ["## Targets", ""]
    for field, title in TARGETS:
        out += [f"### {title}", ""]
        if field == "legal" and not data["java"]:
            out += ["Not computed: no JAR given (--jar).", ""]
            continue
        extra = ["severity agreeing"] if field == "recomputable" else []
        demo_rows, scen_rows = _demo_rows(data, field), _scenario_rows(data, field)
        if demo_rows:
            out += table(["cell", "replicates", "over", "per run"] + extra, demo_rows)
        if scen_rows:
            out += ["The scenarios, one CVE each, summed per arm and model:", ""]
            out += table(["arm", "model", "scenarios", "CVE-runs", "share", "runs below 1"] + extra, scen_rows)
        if not demo_rows and not scen_rows:
            out += ["No run published a VEX.", ""]
    return out


def _range(xs):
    xs = [x for x in xs if x == x]
    return f"{num(sum(xs) / len(xs))} ({num(min(xs))}-{num(max(xs))})" if xs else NA


def _bound(t):
    ratio, bound, _ = t
    return f"ratio {num(ratio)}, lower bound {num(bound)}"


def spreads(data):
    out = ["### Within-project spread W and ranking entropy H", "",
           "Per run, W the SD (n - 1) of its scores and H the entropy in bits of its scores rounded to two decimals, "
           "ties one value, over the CVEs both arms rate; mean (min-max) over the runs. The after against the before "
           "by the non-inferiority bound on mean(after) / mean(before), which needs two runs per arm (0B passed it at "
           "0.90; the gate is set before the run). The before rescored under L x max(T, B) from its own vector is a "
           "diagnostic.", ""]
    rows = []
    for (model, ctx), row in ordered(data["spreads"]):
        for arm in ("after", "before", "before rescored"):
            if arm in row:
                r = row[arm]
                rows.append([f"{model} · {ctx}", arm, cellmod.replicates(r["replicates"]), r["cves"], _range(r["W"]),
                             _range(r["H"])])
        for base in ("before", "before rescored"):
            t = row.get(f"after / {base}")
            if t:
                rows.append([f"{model} · {ctx}", f"after / {base}", "", "", _bound(t["W"]), _bound(t["H"])])
    return out + (table(["model · context", "arm", "replicates", "CVEs", "W", "H"], rows) if rows
                  else ["No demo-scan run.", ""])


def cross(data):
    out = ["### Cross-model spread and band agreement", "",
           "Per context, arm and model pair, over the CVEs both models' runs rate: each model's within-model MPD, the "
           "cross-model MPD, Delta (the cross-model MPD less the mean of the two within-model ones) and its gap test, "
           "10,000 permutations of whole runs, seeded per test; band agreement, the mean over cross-model run pairs "
           "of the share of CVEs with equal severities, and each model's own (its floor). Delta needs two runs per "
           "model.", ""]
    rows = [[ctx, arm, a, b, f"{cellmod.replicates(r['replicates'][0])} / {cellmod.replicates(r['replicates'][1])}",
             r["cves"], num(r["mpd"][0], 2), num(r["mpd"][1], 2), num(r["cross"], 2), num(r["delta"], 2),
             num(r["p"], 4), num(r["bands"]), num(r["bands_within"][0]), num(r["bands_within"][1])]
            for (ctx, arm, a, b), r in ordered(data["cross"])]
    if not rows:
        return out + ["Needs two models with runs in one context and arm: none here.", ""]
    largest = {}
    for (ctx, arm, a, b), r in ordered(data["cross"]):
        if r["delta"] is not None and r["delta"] >= largest.get((ctx, arm), (float("-inf"),))[0]:
            largest[(ctx, arm)] = (r["delta"], f"{a} / {b}")
    out += table(["context", "arm", "model a", "model b", "replicates a / b", "CVEs", "MPD a", "MPD b", "cross MPD",
                  "Delta", "gap p", "bands", "bands a", "bands b"], rows)
    return out + (["The largest Delta over the pairs, which step 5's target bounds: " + "; ".join(
        f"{ctx}, {arm}: {num(d, 2)} ({pair})" for (ctx, arm), (d, pair) in sorted(largest.items())) + ".", ""]
                  if largest else [])


def impacts(data):
    out = ["### #340's report", "", "Per run: the distinct values of T, B and max(T, B), the shares of CVEs where "
           "B > T, T > B and B = T, the share of low severities, and the collapse check, the share whose impact is "
           "HIGH because of B alone (B at 6 or above, T below 6).", ""]
    rows = [[cellmod.label(k), f"r{rep}", i["cves"], i["distinct_T"], i["distinct_B"], i["distinct_max"],
             num(i["B>T"]), num(i["T>B"]), num(i["B=T"]), num(i["low"]), num(i["collapse"])]
            for k, per in ordered(data["impacts"]) for rep, i in sorted(per.items())]
    return out + (table(["cell", "run", "CVEs", "T values", "B values", "max values", "B > T", "T > B", "B = T",
                         "low", "collapse"], rows) if rows else ["No demo-scan run.", ""])


def floors(data):
    out = ["### The floor", "", "Per model, context and arm: the MPD over its runs, its 3-run spread (the mean over "
           "the CVEs of max - min over three runs) averaged over every triple, with the smallest and the largest, "
           "and its N-run spread.", ""]
    rows = [[model, ctx, arm, cellmod.replicates(f["replicates"]), f["cves"], num(f["mpd"], 2),
             f"{num(f['tri_mean'], 2)} ({num(f['tri_min'], 2)}-{num(f['tri_max'], 2)})", num(f["spread"], 2)]
            for (model, ctx, arm), f in ordered(data["floors"])]
    return out + (table(["model", "context", "arm", "replicates", "CVEs", "MPD", "3-run spread", "N-run spread"],
                        rows) if rows else ["No demo-scan run.", ""])


def opportunity(data):
    out = ["### Opportunity on the CVEs no draw has used (diagnostic)", ""]
    if data["opportunity"] is None:
        return out + ["Not computed: no draw list given (--draw-list).", ""]
    rows = []
    for (model, ctx), o in ordered(data["opportunity"]):
        for side in ("in the list", "outside it"):
            s = o[side]
            rows.append([model, ctx, cellmod.replicates(o["replicates"]), side, s["cves"],
                         ", ".join(f"{a} {n}" for a, n in s["answers"].items()) or "none", num(s["mean_level"], 2)])
    return out + table(["model", "context", "replicates", "which CVEs", "CVEs", "answers over the runs", "mean level"],
                       rows) + ["Testing the question needs labels for these CVEs, which no corpus carries.", ""]


def demo_scan(data):
    return ["## The demo scan", ""] + spreads(data) + cross(data) + impacts(data) + floors(data) + opportunity(data)


def _count(led, name):
    """A count summed over the attempts that give it: n/a when none does, the others' number beside it."""
    unknown = led["unknown"][name]
    if unknown == led["attempts"]:
        return NA
    return f"{led['counts'][name]} (+{unknown} unknown)" if unknown else str(led["counts"][name])


def attempts(data):
    out = ["## Attempts, failures and recovery calls", "",
           "Per cell, every attempt, failed and stray ones included. The recovery calls are every call beyond the "
           "planned ones, asked_again + 2 x splits, by kind; a count some attempts do not give says how many.",
           ""]
    rows, causes = [], []
    for k, led in ordered(data["ledgers"]):
        count = lambda name: _count(led, name)
        rows.append([cellmod.label(k), led["attempts"], led["complete"], sum(led["failed"].values()), led["stray"]]
                    + [count(name) for name in ledger.COUNTS] + [led["reply_unreadable"], led["retry_cap_reached"]])
        causes += [f"- {cellmod.label(k)}: {c} ({m})" for c, m in sorted(led["failed"].items())]
    out += table(["cell", "attempts", "complete", "failed", "stray", "calls", "planned", "adjustment",
                  "again, omission", "again, unreadable", "split halves", "recovery", "asked_again", "splits",
                  "reply_unreadable", "retry cap reached"], rows)
    return out + (["Failed attempts by cause:", ""] + causes + [""] if causes else ["No failed attempt.", ""])


def measured(data):
    out = ["## Cost", "", "### Measured: the providers' usage exports", ""]
    if data["usage"] is None:
        return out + ["No usage export given (--usage): no measured spend in this report.", ""]
    fmt = lambda t: [num(t[f], 2) if f == "usd" else num(t[f], 0) for f in usage.NUMBERS]
    for title, by in (("Per provider and model, the whole export", ("provider", "model")),
                      ("Per arm, the keys one arm used alone", ("arm", "provider", "model")),
                      ("Per day, key and model", ("day", "key", "model"))):
        rows = [list(k) + fmt(t) + [", ".join(t["days"])]
                for k, t in usage.totals([r for r in data["usage"] if by[0] != "arm" or r["arm"]], by).items()]
        out += [f"{title}:", ""] + table(list(by) + list(usage.NUMBERS) + ["days"], rows)
    return out + ["A number the export does not give stays n/a, never 0.", ""]


def estimated(data):
    out = ["### Estimated, per attempt (not measured)", "", f"{cost.LABEL}.", ""]
    rows = []
    for k, led in ordered(data["ledgers"]):
        est = led["estimate"]
        rows.append([cellmod.label(k), num(sum(est.values()), 4), num(ledger.recovery_cost(led), 4),
                     ", ".join(f"{kind} {num(v, 4)}" for kind, v in sorted(est.items())) or "none",
                     led["estimate_unknown"]])
    return out + table(["cell", "estimate, USD", "of which recovery calls", "by kind", "attempts without one"], rows)


def render(data, reader):
    from chain import report_scen  # it reads this module's helpers

    head = ["# Half B: what vens published, read per attempt", "",
            f"Read by vens-benchmark `{reader}`. A replicate's run is its first complete attempt that is not a stray "
            "run; its scores are read only where the reader found them usable. Measured figures and estimates are "
            "never in one table.", ""]
    body = (records(data) + targets(data) + demo_scan(data) + report_scen.scenarios(data) + attempts(data)
            + measured(data) + estimated(data) + report_scen.kpis(data) + report_scen.scope())
    return "\n".join(head + body) + "\n"
