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
    out = ["## Records", "", "Inputs, each read by chain/read.py, and the campaign each one's attempts belong to (its "
           "dispatch log's, its campaign.json's, else the input's own name, two inputs of one name two campaigns "
           "never pooled):", ""]
    out += [f"- `{path}`: {n} attempts, campaign {', '.join(map(str, data['campaigns'].get(path, []))) or 'none'}"
            for path, n in data["inputs"]] + [""]
    out += [f"- {' · '.join(map(str, k))}: runs at {len(commits)} vens commits ({', '.join(map(str, commits))}), "
            f"compared with nothing" for k, commits in sorted(data["conflicts"].items(), key=str)]
    rows = []
    for k, c in ordered(data["cells"]):
        led = data["ledgers"][k]
        rows.append([k.corpus, cellmod.label(k), str(k.commit)[:12], led["attempts"], led["complete"],
                     f"{len(c['runs'])} ({cellmod.replicates(c['runs'])})", len(c["unusable"]),
                     sum(led["failed"].values()), led["stray"], led["not_read"]])
    out += table(["corpus", "cell", "vens commit", "attempts", "complete", "runs read (replicates)",
                  "complete, not usable", "failed", "stray", "not read"], rows)
    out += ["Each replicate's run is its first complete attempt; a scenario campaign's lie at "
            "`<provider>/<model>/r<n>/<scenario>/<arm>-a<k>`, listed here only when not the first attempt.", ""]
    for k, c in ordered(data["cells"]):
        runs = {rep: rec for rep, rec in c["runs"].items()
                if k.corpus == cellmod.DEMO or rec["what"].get("run_attempt") != 1}
        if runs:
            out.append(f"- {cellmod.label(k)}: {cellmod.sources(runs)}")
        for rep, (rec, why) in sorted(c["unusable"].items()):
            out.append(f"- {cellmod.label(k)}: r{rep} {cellmod.source(rec)} complete, its scores not read: {why}")
        out += [f"- {cellmod.label(k)}: {p}" for p in c["problems"]]
    return out + [""]


def _per_run(per, field):
    """Each run's share over its report's CVEs, once when every run has the same; a run without a VEX counts 0 and is
    named; unavailable with its reason."""
    gone = [t["unavailable"] for t in per.values() if "unavailable" in t]
    if gone:
        return gone[0]
    got = {rep: (t[field], t["cves"]) for rep, t in sorted(per.items())}
    if len(set(got.values())) == 1:
        k, n = next(iter(got.values()))
        text = f"each run {share(k, n)}" if len(got) > 1 else share(k, n)
    else:
        text = "; ".join(f"r{rep} {share(k, n)}" for rep, (k, n) in got.items())
    novex = [rep for rep, t in per.items() if not t["vex"]]
    return text + (f"; no VEX: {cellmod.replicates(novex)}" if novex else "")


def _demo_rows(data, field):
    rows = []
    for k, per in ordered(data["targets"]):
        if k.corpus != cellmod.DEMO:
            continue
        row = [cellmod.label(k), cellmod.replicates(per), _per_run(per, field)]
        if field == "recomputable":
            row.append(_per_run(per, "severity_ok"))
        rows.append(row)
    return rows


def _scenario_rows(data, field):
    agg = {}
    for k, per in ordered(data["targets"]):
        if k.corpus != cellmod.SCENARIOS:
            continue
        a = agg.setdefault((k.arm, f"{k.campaign} · {cellmod.model_of(k)}"),
                           {"k": 0, "n": 0, "scenarios": 0, "below": [], "sev": 0})
        a["scenarios"] += 1
        for rep, t in sorted(per.items()):
            if "unavailable" in t:
                a["below"].append(f"{k.unit} r{rep} {t['unavailable']}")
                continue
            a["k"] += t[field]
            a["n"] += t["cves"]
            a["sev"] += t["severity_ok"]
            if t[field] < t["cves"]:
                a["below"].append(f"{k.unit} r{rep}" + ("" if t["vex"] else " no VEX"))
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
            out += ["Unavailable: the Java check did not run, no JAR given (--jar).", ""]
            continue
        extra = ["severity agreeing"] if field == "recomputable" else []
        demo_rows, scen_rows = _demo_rows(data, field), _scenario_rows(data, field)
        if demo_rows:
            out += table(["cell", "replicates", "per run, over the report's CVEs"] + extra, demo_rows)
        if scen_rows:
            out += ["The scenarios, one CVE each, summed per arm and model:", ""]
            out += table(["arm", "model", "scenarios", "CVE-runs", "share", "runs below 1"] + extra, scen_rows)
        if not demo_rows and not scen_rows:
            out += ["No complete run.", ""]
    return out


def _range(xs):
    xs = [x for x in xs if x == x]
    return f"{num(sum(xs) / len(xs))} ({num(min(xs))}-{num(max(xs))})" if xs else NA


def _bound(t):
    ratio, bound, _ = t
    return f"ratio {num(ratio)}, lower bound {num(bound)}"


W_ELIGIBILITY = ("0B counted W in a context only where its no-change failure rate, drawn from a reference control's "
                 "runs, was at most 0.05; which runs serve as that reference here is the preregistration's to say, so "
                 "the rule is not applied, and the bound is printed without a verdict, 0B's 0.90 margin for reference "
                 "only.")


def _cohort(c):
    only = "; ".join(f"only the {arm} rates {len(ids)}" + (f" ({', '.join(ids[:5])}{', ...' if len(ids) > 5 else ''})"
                                                            if ids else "") for arm, ids in sorted(c["only"].items()))
    uneven = ", ".join(f"{arm} {n}" for arm, n in sorted(c["uneven"].items()))
    return f"cohorts: {only or 'one arm only'}; runs whose CVEs differ from their arm's: {uneven}"


def spreads(data):
    out = ["### Within-project spread W and ranking entropy H", "",
           "Per run, over its own CVEs: W the SD (n - 1) of its scores, H the entropy in bits of its scores rounded to "
           "two decimals, ties one value; mean (min-max) over the runs. Before the comparison, the CVEs one arm rates "
           "and the other does not. The after against the before by the non-inferiority bound on mean(after) / "
           "mean(before), which needs two runs per arm. The before rescored under L x max(T, B) from its own vector is "
           "a diagnostic. " + W_ELIGIBILITY, ""]
    rows = []
    for (campaign, model, ctx), row in ordered(data["spreads"]):
        where = f"{campaign} · {model} · {ctx}"
        for arm in ("after", "before", "before rescored"):
            if arm in row:
                r = row[arm]
                n = sorted(set(r["cves"]))
                rows.append([where, arm, cellmod.replicates(r["replicates"]), "/".join(map(str, n)), _range(r["W"]),
                             _range(r["H"])])
        rows.append([where, "", "", "", _cohort(row["cohort"]), ""])
        for base in ("before", "before rescored"):
            t = row.get(f"after / {base}")
            if t:
                rows.append([where, f"after / {base}", "", "", _bound(t["W"]), _bound(t["H"])])
    return out + (table(["campaign · model · context", "arm", "replicates", "CVEs per run", "W", "H"], rows) if rows
                  else ["No demo-scan run.", ""])


def cross(data):
    out = ["### Cross-model spread and band agreement", "",
           "Per context, arm and model pair, over the CVEs both models' runs rate: each model's within-model MPD, the "
           "cross-model MPD, Delta (the cross-model MPD less the mean of the two within-model ones) and its gap test, "
           "10,000 permutations of whole runs, seeded per test; band agreement, the mean over cross-model run pairs "
           "of the share of CVEs with equal severities, and each model's own (its floor). Delta needs two runs per "
           "model. The permutations draw from SeedSequence([310, crc32(key)]), each pair's key, listed under the "
           "table, built from its two cells' own fields, `gap|<campaign>|<arm>|<batch size>|<context>|<provider/model "
           "a>|<provider/model b>`, an unnamed campaign by its input's own name: 0B's tests had other keys, so these p "
           "are not 0B's, though Delta and the MPDs are computed as 0B computed them. A pair whose runs share no "
           "rated CVE is unavailable, none of its figures computed.", ""]
    rows = [[campaign, ctx, arm, a, b,
             f"{cellmod.replicates(r['replicates'][0])} / {cellmod.replicates(r['replicates'][1])}", r["cves"],
             num(r["mpd"][0], 2), num(r["mpd"][1], 2), num(r["cross"], 2), num(r["delta"], 2), num(r["p"], 4),
             num(r["bands"]), num(r["bands_within"][0]), num(r["bands_within"][1])]
            for (campaign, ctx, arm, a, b), r in ordered(data["cross"])]
    if not rows:
        return out + ["Needs two models with runs in one context and arm: none here.", ""]
    largest = {}
    for (campaign, ctx, arm, a, b), r in ordered(data["cross"]):
        if r["delta"] is not None and r["delta"] >= largest.get((campaign, ctx, arm), (float("-inf"),))[0]:
            largest[(campaign, ctx, arm)] = (r["delta"], f"{a} / {b}")
    out += table(["campaign", "context", "arm", "model a", "model b", "replicates a / b", "CVEs", "MPD a", "MPD b",
                  "cross MPD", "Delta", "gap p", "bands", "bands a", "bands b"], rows)
    out += ["Each pair's gap test:", ""] + [
        f"- {campaign}, {ctx}, {arm}, {a} / {b}: " + (r["unavailable"] if r.get("unavailable") else f"key `{r['key']}`")
        + "." for (campaign, ctx, arm, a, b), r in ordered(data["cross"])] + [""]
    return out + (["The largest Delta over the pairs, which step 5's target bounds: " + "; ".join(
        f"{cp}, {ctx}, {arm}: {num(d, 2)} ({pair})" for (cp, ctx, arm), (d, pair) in sorted(largest.items(), key=str))
        + ".", ""] if largest else [])


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
    rows = [[campaign, model, ctx, arm, cellmod.replicates(f["replicates"]), f["cves"], num(f["mpd"], 2),
             f"{num(f['tri_mean'], 2)} ({num(f['tri_min'], 2)}-{num(f['tri_max'], 2)})", num(f["spread"], 2)]
            for (campaign, model, ctx, arm), f in ordered(data["floors"])]
    return out + (table(["campaign", "model", "context", "arm", "replicates", "CVEs", "MPD", "3-run spread",
                         "N-run spread"], rows) if rows else ["No demo-scan run.", ""])


def opportunity(data):
    out = ["### Opportunity on the CVEs no draw has used (diagnostic)", ""]
    if data["opportunity"] is None:
        return out + ["Not computed: no draw list given (--draw-list).", ""]
    d = data["draws"]
    read = set().union(*[o["cves_read"] for o in data["opportunity"].values()]) if data["opportunity"] else set()
    out += [f"The draw list `{d['name']}`, sha256 {d['sha256']}, {len(d['ids'])} CVE ids, of which "
            f"{len(read & d['ids'])} are among the {len(read)} CVEs these runs read. Per side, the CVEs (the report's, "
            "else the runs' rated ones), those with an Opportunity answer read, and the others: not asked, unrated or "
            "not rated.", ""]
    rows = []
    for (campaign, model, ctx), o in ordered(data["opportunity"]):
        for side in ("in the list", "outside it"):
            x = o[side]
            rows.append([campaign, model, ctx, cellmod.replicates(o["replicates"]), side, x["cves"], x["answered"],
                         x["dropped"], ", ".join(f"{a} {n}" for a, n in x["answers"].items()) or "none",
                         num(x["mean_level"], 2)])
    return out + table(["campaign", "model", "context", "replicates", "which CVEs", "CVEs", "answered", "no answer",
                        "answers over the runs", "mean level"], rows) + \
        ["Testing the question needs labels for these CVEs, which no corpus carries.", ""]


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
    u = data["usage"]
    if u is None:
        return out + ["No usage export given (--usage): no measured spend in this report.", ""]
    campaigns = sorted({r["campaign"] for r in u["rows"]})
    out += [f"The export `{u['name']}`, sha256 {u['sha256']}, {len(u['rows'])} rows, campaign(s) "
            f"{', '.join(campaigns)}.", ""]
    fmt = lambda t: [num(t[f], 2) if f == "usd" else num(t[f], 0) for f in usage.NUMBERS]
    arm_rows, hidden = usage.by_arm(u["rows"])
    for title, by, rows in (("Per campaign, provider and model, the whole export", ("campaign", "provider", "model"),
                             u["rows"]),
                            ("Per campaign and arm, the keys one arm used alone", ("campaign", "arm", "provider",
                                                                                   "model"), arm_rows),
                            ("Per campaign, day, key and model", ("campaign", "day", "key", "model"), u["rows"])):
        got = [list(k) + fmt(t) + [", ".join(t["days"])] for k, t in usage.totals(rows, by).items()]
        out += [f"{title}:", ""] + (table(list(by) + list(usage.NUMBERS) + ["days"], got) if got else ["none", ""])
    out += [f"No per-arm total for {c} at {p}: {why}." for (c, p), why in sorted(hidden.items())]
    return out + ["A number the export does not give stays n/a, never 0.", ""]


def estimated(data):
    out = ["### Estimated, per attempt (not measured)", "", f"{cost.LABEL}. A cell none of whose attempts gives an "
           "estimate has none, n/a, never 0.", ""]
    rows = []
    for k, led in ordered(data["ledgers"]):
        est, none = led["estimate"], led["estimate_unknown"] == led["attempts"]
        rows.append([cellmod.label(k), NA if none else num(sum(est.values()), 4),
                     NA if none else num(ledger.recovery_cost(led), 4),
                     NA if none else ", ".join(f"{kind} {num(v, 4)}" for kind, v in sorted(est.items())) or "none",
                     led["estimate_unknown"]])
    return out + table(["cell", "estimate, USD", "of which recovery calls", "by kind", "attempts without one"], rows)


def render(data, reader):
    from chain import report_scen  # it reads this module's helpers

    head = ["# Half B: what vens published, read per attempt", "",
            f"Read by vens-benchmark `{reader}`. A replicate's run is its first complete attempt that is not a stray "
            "run; its scores are read only where the reader found them usable. Measured figures and estimates are "
            "never in one table.", ""]
    body = (records(data) + targets(data) + demo_scan(data) + report_scen.scenarios(data) + attempts(data)
            + measured(data) + estimated(data) + report_scen.kpis(data) + report_scen.scope(data))
    return "\n".join(head + body) + "\n"
