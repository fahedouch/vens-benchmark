"""A scenario campaign's folder, as the scenario runner (ctx_runner.py) lays it out, and its reading.

    DIR/campaign.json            what was run, written before the first call and completed at the end
    DIR/freeze-scenarios.json    the corpus's freeze, and DIR/scenarios/ the corpus, both copied from the repository
    DIR/<provider>/<model>/r<replicate>/<scenario>/<arm>-a<attempt>/
                                 one attempt: attempt.json, vens.log, calls/, vex.cdx.json and its attestation
    DIR/SHA256SUMS               every other file's sha256, written when the runner ends

campaign.json:

    {"record": 1, "runner": "scenarios", "campaign", "vens_benchmark", "started_at", "ended_at", "stopped",
     "corpus": {"freeze", "freeze_sha256", "scenarios"},
     "arms": {"before" | "after": {"vens_ref", "vens_sha", "binary_sha256", "keys": {provider: variable}}},
     "models": [{"provider", "model", "dated"}], "replicates", "llm_batch_size", "sampling", "retry_cap",
     "timeout_seconds", "parallelism", "mock_env", "order", "command"}

stopped is null for a campaign that ran to its end, else why the runner stopped; ended_at is null for one whose
runner was killed. A unit is one scenario, model and replicate; the units run replicate by replicate, model by model,
scenario by scenario, each the before's run then the after's, back to back.
"""
import os

from chain import attempt as attemptmod
from chain import runvens
from chain.errors import Refused, load_object

CAMPAIGN, FREEZE, SCENARIOS, SUMS = "campaign.json", "freeze-scenarios.json", "scenarios", "SHA256SUMS"
# freeze-scenarios.json as the corpus was frozen; a corpus regenerated is frozen again and this changes with it
FROZEN = "4f4b86ade2e1c464142728d5c68a3c86ede2db21c47a4a5b64aadf19c44232a1"
ARMS = ("before", "after")
# what each attempt's record repeats from campaign.json
SAME = ("llm_batch_size", "retry_cap", "timeout_seconds", "parallelism")


def folder(replicate, provider, model, scenario, arm, attempt):
    return os.path.join(provider, model, f"r{replicate}", scenario, f"{arm}-a{attempt}")


def plan(doc):
    """The units in run order: (replicate, provider, model, scenario)."""
    return [(r, m["provider"], m["model"], s) for r in range(1, doc["replicates"] + 1) for m in doc["models"]
            for s in doc["corpus"]["scenarios"]]


def check_corpus(root, frozen=FROZEN):
    """(the freeze's sha256, the scenario ids) when root holds the frozen corpus: freeze-scenarios.json whose sha256
    is frozen, and scenarios/ holding its files and no other, each of its sha256; Refused otherwise."""
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
    ids = sorted({p.split("/")[1] for p in want if p.count("/") == 2})
    return got, ids


def write_sums(root):
    files = sorted(os.path.relpath(os.path.join(d, n), root) for d, _, names in os.walk(root) for n in names
                   if os.path.join(d, n) != os.path.join(root, SUMS))
    with open(os.path.join(root, SUMS), "w", encoding="utf-8") as fh:
        fh.writelines(f"{runvens.sha256(os.path.join(root, p))}  {p}\n" for p in files)


def _attempt_folders(root):
    out = []
    for d, dirs, names in os.walk(root):
        if d == root:
            dirs[:] = [x for x in dirs if x != SCENARIOS]
        if "attempt.json" in names:
            out.append(d)
            dirs[:] = []
    return sorted(out)


def _cell(rj):
    return rj.get("replicate"), rj.get("provider"), rj.get("model"), rj.get("scenario"), rj.get("arm")


def _check(root, path, rj, doc, units):
    """Refused when an attempt's record is not one of this campaign's: another campaign, arm, commit, binary,
    freeze or input, a unit outside the plan, or a folder elsewhere than its record puts it."""
    arm = rj.get("arm")
    if rj.get("runner") != "scenarios" or arm not in ARMS:
        raise Refused(f"{path}: not a scenario runner's attempt of the before or the after")
    want = {"campaign": doc["campaign"], "vens_sha": doc["arms"][arm]["vens_sha"],
            "vens_binary_sha256": doc["arms"][arm]["binary_sha256"],
            "freeze_sha256": doc["corpus"]["freeze_sha256"], **{f: doc[f] for f in SAME}}
    for field, value in want.items():
        if rj.get(field) != value:
            raise Refused(f"{path}: attempt.json gives {field} {rj.get(field)!r}, campaign.json {value!r}")
    if _cell(rj)[:4] not in units:
        raise Refused(f"{path}: replicate, model or scenario outside campaign.json's plan")
    k = rj.get("attempt")
    if not isinstance(k, int) or not 1 <= k <= doc["retry_cap"]:
        raise Refused(f"{path}: attempt {k!r}, the retry cap {doc['retry_cap']}")
    if os.path.relpath(path, root) != folder(*_cell(rj)[:4], arm, k):
        raise Refused(f"{path}: not the folder its attempt.json names")


def _not_run(doc, cell, why):
    r, provider, model, scenario, arm = cell
    line = {"arm": arm, "model": model, "replicate": r, "vens_commit": doc["arms"][arm]["vens_sha"]}
    rec = attemptmod.not_downloaded(line, why, reason="not run")
    return {**rec, "what": {**rec["what"], "runner": "scenarios", "campaign": doc["campaign"], "provider": provider,
                            "scenario": scenario}}


def _read_cell(doc, cell, folders, ended, commits):
    """The attempts of one unit's arm, in order; Refused when they are not what the runner leaves."""
    where = "{4} of replicate {0} of {3} by {1}/{2}".format(*cell)
    if not folders:
        if ended:
            raise Refused(f"{where}: no attempt, yet the campaign ran to its end: a truncated archive")
        return [_not_run(doc, cell, f"{where}: not run, the campaign stopped before it")]
    ks = sorted(folders)
    if ks != list(range(1, len(ks) + 1)):
        raise Refused(f"{where}: attempts {ks}, numbered with a gap: a truncated archive")
    recs = [attemptmod.read_attempt(folders[k], commits=commits) for k in ks]
    for k, rec in zip(ks, recs):
        gen, last = rec["steps"]["generate"], k == ks[-1]
        if not last and gen.get("exit_status") == 0:
            raise Refused(f"{folders[k]}: a complete attempt, attempted again")
        at_cap = last and k == doc["retry_cap"] and gen.get("exit_status") != 0 \
            and gen.get("interrupted") != runvens.STOPPED
        if rec["retry_cap_reached"] and not at_cap:
            raise Refused(f"{folders[k]}: the retry cap reached, at attempt {k} of {doc['retry_cap']}, "
                          f"{'not the last' if not last else 'not a failed one'}")
        if ended and at_cap and not rec["retry_cap_reached"]:
            raise Refused(f"{folders[k]}: the last attempt the retry cap allows, failed, not marked as reaching it")
    gen = recs[-1]["steps"]["generate"]
    if ended and gen.get("exit_status") != 0 and ks[-1] < doc["retry_cap"]:
        raise Refused(f"{folders[ks[-1]]}: a failed attempt below the retry cap and none after it, yet the campaign "
                      f"ran to its end: a truncated archive")
    return recs


def read_campaign(root, commits=None):
    """Every attempt of a campaign in its plan's order, the before's then the after's for each unit, failed
    attempts included, and a record for each run the campaign stopped before; refused when the archive's corpus is
    not its freeze's, a record contradicts campaign.json, or an attempt the runner made is missing."""
    doc = load_object(os.path.join(root, CAMPAIGN))
    if doc.get("runner") != "scenarios":
        raise Refused(f"{root}: {CAMPAIGN} is not a scenario runner's")
    check_corpus(root, doc["corpus"]["freeze_sha256"])
    units, cells = plan(doc), {}
    unit_set = set(units)
    for path in _attempt_folders(root):
        rj = load_object(os.path.join(path, "attempt.json"))
        _check(root, path, rj, doc, unit_set)
        cells.setdefault(_cell(rj), {})[rj["attempt"]] = path
    ended = doc.get("ended_at") is not None and doc.get("stopped") is None
    return [rec for unit in units for arm in ARMS
            for rec in _read_cell(doc, (*unit, arm), cells.get((*unit, arm), {}), ended, commits)]
