"""A scenario campaign's folder, as the scenario runner (ctx_runner.py) lays it out, and its reading.

    DIR/campaign.json            what was run, written before the first call and completed at the end
    DIR/freeze-scenarios.json    the corpus's freeze, and DIR/scenarios/ the corpus, both copied from the repository
                                 and made read-only before the first call
    DIR/<provider>/<model>/r<replicate>/<scenario>/<arm>-a<attempt>/
                                 one attempt: attempt.json, vens.log, calls/, vex.cdx.json and its attestation
    DIR/failures.jsonl           each failed attempt, its folder and its cause as the reader gives them
    DIR/SHA256SUMS               every other file's sha256, written last

campaign.json:

    {"record": 1, "runner": "scenarios", "campaign", "vens_benchmark", "started_at", "ended_at", "stopped",
     "redacted", "corpus": {"freeze", "freeze_sha256", "scenarios"},
     "arms": {"before" | "after": {"vens_ref", "vens_sha", "binary_sha256", "keys": {provider: variable}}},
     "models": [{"provider", "model", "dated"}], "replicates", "llm_batch_size", "sampling", "retry_cap",
     "timeout_seconds", "parallelism", "mock_env", "order", "command"}

stopped is null for a campaign that ran to its end, else why the runner stopped; ended_at is null for one whose
runner was killed, which leaves no failures.jsonl and no SHA256SUMS. redacted lists the files a key was cut out of. A
unit is one scenario, model and replicate; the units run replicate by replicate, model by model, scenario by
scenario, each the before's run then the after's, back to back.
"""
import json
import os

from chain import attempt as attemptmod
from chain import runvens
from chain.errors import Refused, load_object

CAMPAIGN, FREEZE, SCENARIOS, SUMS = "campaign.json", "freeze-scenarios.json", "scenarios", "SHA256SUMS"
FAILURES = "failures.jsonl"
# freeze-scenarios.json as the corpus was frozen; a corpus regenerated is frozen again and this changes with it
FROZEN = "4f4b86ade2e1c464142728d5c68a3c86ede2db21c47a4a5b64aadf19c44232a1"
ARMS = ("before", "after")
# what each attempt's record repeats from campaign.json
SAME = ("llm_batch_size", "retry_cap", "timeout_seconds", "parallelism")


def folder(replicate, provider, model, scenario, arm, attempt):
    return os.path.join(provider, model, f"r{replicate}", scenario, f"{arm}-a{attempt}")


def inputs(scenario):
    """The scenario's config and report, relative to the campaign folder."""
    corpus = os.path.join(SCENARIOS, scenario)
    return os.path.join(corpus, "config.yaml"), os.path.join(corpus, "report.json")


def command(provider, scenario, where):
    """vens generate's arguments for one attempt into the folder where, its paths relative to the campaign folder:
    baseline.yml's flags at batch 1, no --llm-temperature and no --llm-seed."""
    config, report = inputs(scenario)
    return ["generate", "--config-file", config, "--llm", provider, "--llm-batch-size", "1", "--input-format",
            "trivy", "--sbom-serial-number", runvens.SERIAL, "--sbom-version", "1", "--attest", "--debug-dir",
            os.path.join(where, "calls"), report, os.path.join(where, "vex.cdx.json")]


def plan(doc):
    """The units in run order: (replicate, provider, model, scenario)."""
    return [(r, m["provider"], m["model"], s) for r in range(1, doc["replicates"] + 1) for m in doc["models"]
            for s in doc["corpus"]["scenarios"]]


def done(rj):
    """Whether an attempt's record says it completed: vens exited 0 and the runner's record check passed."""
    return (rj.get("generate") or {}).get("exit_status") == 0 and (rj.get("record_check") or {}).get("passed") is True


def check_corpus(root, frozen=FROZEN):
    """({path: sha256} of the corpus's files, the scenario ids) when root holds the frozen corpus:
    freeze-scenarios.json whose sha256 is frozen, and scenarios/ holding its files and no other, each of its sha256;
    Refused otherwise."""
    path = os.path.join(root, FREEZE)
    if not os.path.isfile(path):
        raise Refused(f"{root}: no {FREEZE}")
    got = runvens.sha256(path)
    if got != frozen:
        raise Refused(f"{path}: sha256 {got}, not the frozen corpus's {frozen}")
    want = load_object(path).get("files") or {}
    have = {}
    for d, _, names in os.walk(os.path.join(root, SCENARIOS)):
        for n in names:
            p = os.path.join(d, n)
            have[os.path.relpath(p, root)] = runvens.sha256(p)
    wrong = [f"{p} missing" for p in sorted(set(want) - set(have))]
    wrong += [f"{p} not in the freeze" for p in sorted(set(have) - set(want))]
    wrong += [f"{p} changed" for p in sorted(set(want) & set(have)) if want[p] != have[p]]
    if wrong:
        raise Refused(f"{root}: the scenarios are not the frozen corpus: {'; '.join(wrong[:5])}"
                      + (f" and {len(wrong) - 5} more" if len(wrong) > 5 else ""))
    return want, sorted({p.split("/")[1] for p in want if p.count("/") == 2})


def archive_files(root):
    """Every file of the archive but SHA256SUMS and what a kill mid-write leaves (*.tmp)."""
    return sorted(os.path.relpath(os.path.join(d, n), root) for d, _, names in os.walk(root) for n in names
                  if not n.endswith(".tmp") and os.path.join(d, n) != os.path.join(root, SUMS))


def write_sums(root):
    with open(os.path.join(root, SUMS), "w", encoding="utf-8") as fh:
        fh.writelines(f"{runvens.sha256(os.path.join(root, p))}  {p}\n" for p in archive_files(root))


def check_sums(root):
    """Refused unless SHA256SUMS lists every file of the archive, each with its sha256, and nothing else."""
    listed = {}
    with open(os.path.join(root, SUMS), encoding="utf-8") as fh:
        for line in fh:
            sha, sep, path = line.rstrip("\n").partition("  ")
            if not sep:
                raise Refused(f"{root}: a line of {SUMS} that does not read: {line.strip()!r}")
            listed[path] = sha
    files = archive_files(root)
    wrong = [f"{p} not listed" for p in files if p not in listed]
    wrong += [f"{p} listed, not there" for p in sorted(set(listed) - set(files))]
    wrong += [f"{p} changed" for p in files if p in listed and runvens.sha256(os.path.join(root, p)) != listed[p]]
    if wrong:
        raise Refused(f"{root}: {SUMS} does not match the archive: {'; '.join(wrong[:5])}"
                      + (f" and {len(wrong) - 5} more" if len(wrong) > 5 else ""))


def attempt_folders(root):
    out = []
    for d, dirs, names in os.walk(root):
        if d == root:
            dirs[:] = [x for x in dirs if x != SCENARIOS]
        if "attempt.json" in names:
            out.append(d)
            dirs[:] = []
    return sorted(out)


def failures(root):
    """Each failed attempt under root as the reader gives it, in folder order: its folder, what it ran, its
    failure's kind, step and cause, and whether it reached the retry cap."""
    out = []
    for path in attempt_folders(root):
        if done(load_object(os.path.join(path, "attempt.json"))):
            continue
        rec = attemptmod.read_attempt(path)
        what, failure = rec["what"], rec["failure"] or {}
        out.append({"folder": os.path.relpath(path, root), "arm": what["arm"], "provider": what["provider"],
                    "model": what["model"], "replicate": what["replicate"], "scenario": what["scenario"],
                    "attempt": what["run_attempt"], "kind": failure.get("kind"), "step": failure.get("step"),
                    "cause": failure.get("cause"), "retry_cap_reached": rec["retry_cap_reached"]})
    return out


def write_failures(root):
    with open(os.path.join(root, FAILURES), "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(f, sort_keys=True) + "\n" for f in failures(root))


def _cell(rj):
    return rj.get("replicate"), rj.get("provider"), rj.get("model"), rj.get("scenario"), rj.get("arm")


def _check(root, path, rj, doc, units):
    """Refused when an attempt's record is not one of this campaign's: another campaign, arm, commit, binary,
    freeze, input or command, a unit outside the plan, or a folder elsewhere than its record puts it."""
    arm = rj.get("arm")
    if rj.get("runner") != "scenarios" or arm not in ARMS:
        raise Refused(f"{path}: not a scenario runner's attempt of the before or the after")
    if _cell(rj)[:4] not in units:
        raise Refused(f"{path}: replicate, model or scenario outside campaign.json's plan")
    k = rj.get("attempt")
    if not isinstance(k, int) or not 1 <= k <= doc["retry_cap"]:
        raise Refused(f"{path}: attempt {k!r}, the retry cap {doc['retry_cap']}")
    where = folder(*_cell(rj)[:4], arm, k)
    if os.path.relpath(path, root) != where:
        raise Refused(f"{path}: not the folder its attempt.json names")
    config, report = inputs(rj["scenario"])
    want = {"campaign": doc["campaign"], "vens_sha": doc["arms"][arm]["vens_sha"],
            "vens_binary_sha256": doc["arms"][arm]["binary_sha256"],
            "freeze_sha256": doc["corpus"]["freeze_sha256"], "config": config, "report": report,
            "command": ["vens", *command(rj["provider"], rj["scenario"], where)], **{f: doc[f] for f in SAME}}
    for field, value in want.items():
        if rj.get(field) != value:
            raise Refused(f"{path}: attempt.json gives {field} {rj.get(field)!r}, campaign.json {value!r}")


def _not_run(doc, cell, why):
    r, provider, model, scenario, arm = cell
    line = {"arm": arm, "model": model, "replicate": r, "vens_commit": doc["arms"][arm]["vens_sha"]}
    rec = attemptmod.not_downloaded(line, why, reason="not run")
    return {**rec, "what": {**rec["what"], "runner": "scenarios", "campaign": doc["campaign"], "provider": provider,
                            "scenario": scenario}}


def _read_cell(doc, cell, attempts, ended, commits):
    """The attempts of one unit's arm, in order, from {k: (folder, attempt.json)}; Refused when they are not what the
    runner leaves."""
    where = "{4} of replicate {0} of {3} by {1}/{2}".format(*cell)
    if not attempts:
        if ended:
            raise Refused(f"{where}: no attempt, yet the campaign ran to its end: a truncated archive")
        return [_not_run(doc, cell, f"{where}: not run, the campaign stopped before it")]
    ks = sorted(attempts)
    if ks != list(range(1, len(ks) + 1)):
        raise Refused(f"{where}: attempts {ks}, numbered with a gap: a truncated archive")
    for k in ks:
        path, rj = attempts[k]
        last = k == ks[-1]
        if not last and done(rj):
            raise Refused(f"{path}: a complete attempt, attempted again")
        at_cap = last and k == doc["retry_cap"] and not done(rj) \
            and (rj.get("generate") or {}).get("interrupted") != runvens.STOPPED
        if rj.get("retry_cap_reached") and not at_cap:
            raise Refused(f"{path}: the retry cap reached, at attempt {k} of {doc['retry_cap']}, "
                          f"{'not the last' if not last else 'not a failed one'}")
        if ended and at_cap and not rj.get("retry_cap_reached"):
            raise Refused(f"{path}: the last attempt the retry cap allows, failed, not marked as reaching it")
    path, rj = attempts[ks[-1]]
    if ended and not done(rj) and ks[-1] < doc["retry_cap"]:
        raise Refused(f"{path}: a failed attempt below the retry cap and none after it, yet the campaign ran to its "
                      f"end: a truncated archive")
    return [attemptmod.read_attempt(attempts[k][0], commits=commits) for k in ks]


def read_campaign(root, commits=None, freeze=FROZEN):
    """Every attempt of a campaign in its plan's order, the before's then the after's for each unit, failed
    attempts included, and a record for each run the campaign stopped before. Refused when the archive's corpus is
    not freeze's (the frozen corpus unless the caller names another), SHA256SUMS does not match a campaign the
    runner finished, a record contradicts campaign.json, failures.jsonl does not list the failed attempts, or an
    attempt the runner made is missing."""
    doc = load_object(os.path.join(root, CAMPAIGN))
    if doc.get("runner") != "scenarios":
        raise Refused(f"{root}: {CAMPAIGN} is not a scenario runner's")
    got = doc["corpus"]["freeze_sha256"]
    if got != freeze:
        raise Refused(f"{root}: its corpus's freeze is {got}, not {freeze}; name it to read the archive anyway")
    finished = doc.get("ended_at") is not None
    if finished and not os.path.exists(os.path.join(root, SUMS)):
        raise Refused(f"{root}: a campaign the runner finished, without its {SUMS}")
    if os.path.exists(os.path.join(root, SUMS)):
        check_sums(root)
    check_corpus(root, got)
    units, cells = plan(doc), {}
    unit_set = set(units)
    for path in attempt_folders(root):
        rj = load_object(os.path.join(path, "attempt.json"))
        _check(root, path, rj, doc, unit_set)
        cells.setdefault(_cell(rj), {})[rj["attempt"]] = (path, rj)
    if finished:
        with open(os.path.join(root, FAILURES), encoding="utf-8") as fh:
            listed = sorted(json.loads(line)["folder"] for line in fh)
        failed = sorted(os.path.relpath(p, root) for c in cells.values() for p, rj in c.values() if not done(rj))
        if listed != failed:
            raise Refused(f"{root}: {FAILURES} lists {len(listed)} failed attempts, the attempt records give "
                          f"{len(failed)}")
    ended = finished and doc.get("stopped") is None
    return [rec for unit in units for arm in ARMS
            for rec in _read_cell(doc, (*unit, arm), cells.get((*unit, arm), {}), ended, commits)]
