"""One attempt's folder, complete or failed: what was run, how it ended and what it left.

Two runners leave such a folder. vens-demo's baseline.yml uploads one artefact per attempt,
baseline-<model>-<context>-r<replicate>-a<attempt>/, with the VEX, the enriched report, provenance.json, the
attestation and calls/, and, once its Score step writes them, attempt.json and vens's log, vens-<context>.log. The
scenario runner writes attempt.json, vens.log, calls/ and the VEX for each scenario run.

attempt.json, the attempt record, is written before `vens generate` runs and completed as the steps end:

    {"record": 1, "runner": "baseline.yml" | "scenarios", "arm": "before" | "after",
     "provider", "model", "llm_batch_size", "vens_ref", "vens_sha", "vens_binary_sha256",
     "run_id", "run_attempt", "job", "context", "replicate", "archived_scan", "config",      baseline.yml
     "scenario", "report", "config", "replicate", "attempt",                                  the scenario runner
     "generate": {"started_at", "ended_at", "exit_status", "timed_out"},
     "enrich": {"started_at", "ended_at", "exit_status"},                                    baseline.yml
     "archive_check": "success" | "failure" | "skipped" | "cancelled",                       baseline.yml
     "provenance": true | false}                                                             baseline.yml

A field not yet written is absent or null. Times are UTC, ISO 8601.
"""
import json
import os
import re

from chain import answers as answersmod
from chain import calls as callmod
from chain import cdx, cost, recovery, venslog

COMPLETE, FAILED = "complete", "failed"
SCORING, LATER_STEP, INTERRUPTED = "scoring", "later_step", "interrupted"
CONTEXTS = ("internet-facing", "internal", "internal-api")
NO_PROVENANCE = "no provenance.json: the job failed before writing it"
_UNTIMED = ("generate.started_at", "generate.ended_at", "enrich.started_at", "enrich.ended_at", "vens_binary_sha256")


class Refused(Exception):
    """A folder the reader will not read: a download it cannot tell from another, or one its dispatch log contradicts."""


def parse_name(name):
    """(model, context, replicate, attempt) of baseline-<model>-<context>-r<n>-a<k>, read from the end since model
    ids hold dashes; None when the name does not parse with a known context."""
    m = re.fullmatch(r"baseline-(.+)-r(\d+)-a(\d+)", name)
    if not m:
        return None
    ctx = [c for c in CONTEXTS if m.group(1).endswith("-" + c) and len(m.group(1)) > len(c) + 1]
    if len(ctx) != 1:
        return None
    return {"model": m.group(1)[:-len(ctx[0]) - 1], "context": ctx[0], "replicate": int(m.group(2)),
            "attempt": int(m.group(3))}


def _json(path):
    if path is None:
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _files(folder):
    names = os.listdir(folder)

    def one(pred, what):
        found = sorted(n for n in names if pred(n))
        if len(found) > 1:
            raise Refused(f"{folder}: {len(found)} {what}")
        return os.path.join(folder, found[0]) if found else None

    calls_dir = os.path.join(folder, "calls")
    run_dirs = callmod.run_folders(calls_dir) if os.path.isdir(calls_dir) else None
    answers = os.path.join(run_dirs[0], "answers.json") if run_dirs and len(run_dirs) == 1 else None
    return {
        "record": one(lambda n: n == "attempt.json", "records"),
        "provenance": one(lambda n: n == "provenance.json", "provenance files"),
        "vex": one(lambda n: n.startswith("vex") and n.endswith(".cdx.json")
                   and not n.endswith(".attestation.cdx.json"), "VEX files"),
        "attestation": one(lambda n: n.endswith(".attestation.cdx.json"), "attestations"),
        "log": one(lambda n: n.startswith("vens") and n.endswith(".log"), "logs"),
        "run_dirs": run_dirs,
        "answers": answers if answers and os.path.exists(answers) else None,
    }


def _pick(*values):
    return next((v for v in values if v is not None), None)


def run_meta(run):
    """What a baseline.yml run was dispatched with, from its run-name in run.json (the API's run object): provider,
    model, batch size, replicates, vens ref and the archived run, as dispatch metadata, not as an attestation."""
    m = re.fullmatch(r"baseline · (.+) · ([^/ ]+)/(.+) · batch (\d+) · x(\d+) · vens (\S+)",
                     run.get("display_title") or run.get("name") or "")
    if not m:
        return {"run_id": run.get("id")}
    return {"run_id": run.get("id"), "archived_run": m.group(1), "provider": m.group(2), "model": m.group(3),
            "batch_size": int(m.group(4)), "replicates": int(m.group(5)), "vens_ref": m.group(6)}


def _what(rj, prov, name, line, arm, meta=None):
    rj, prov, name, line, meta = rj or {}, prov or {}, name or {}, line or {}, meta or {}
    context = _pick(rj.get("context"), name.get("context"),
                    os.path.basename(prov["context"]).replace(".yaml", "") if prov.get("context") else None)
    in_run = _pick(name.get("replicate"), prov.get("replicate"), rj.get("replicate"))
    runner = _pick(rj.get("runner"), "baseline.yml" if name or prov else None)
    job = _pick(rj.get("job"), f"{context} · run {in_run}" if runner == "baseline.yml" and in_run else None)
    return {
        "runner": runner,
        "arm": _pick(arm, line.get("arm"), rj.get("arm")),
        "corpus": _pick(rj.get("archived_scan"), rj.get("report"), prov.get("archived_scan")),
        "config": _pick(rj.get("config"), prov.get("context")),
        "context": context,
        "scenario": rj.get("scenario"),
        "vens_ref": _pick(rj.get("vens_ref"), prov.get("vens_ref"), line.get("vens_ref"), meta.get("vens_ref")),
        "vens_commit": _pick(rj.get("vens_sha"), prov.get("vens_sha")),
        "vens_binary_sha256": rj.get("vens_binary_sha256"),
        "provider": _pick(rj.get("provider"), prov.get("provider"), line.get("provider"), meta.get("provider")),
        "model": _pick(rj.get("model"), prov.get("model"), line.get("model"), meta.get("model"), name.get("model")),
        "batch_size": _pick(rj.get("llm_batch_size"), prov.get("llm_batch_size"), line.get("batch_size"),
                            meta.get("batch_size")),
        "replicate": _pick(line.get("replicate"), rj.get("replicate"), prov.get("replicate"), name.get("replicate")),
        "replicate_in_run": in_run,
        "run_id": _pick(rj.get("run_id"), prov.get("run_id"), line.get("run_id"), meta.get("run_id")),
        "run_attempt": _pick(rj.get("run_attempt"), prov.get("run_attempt"), name.get("attempt"), rj.get("attempt")),
        "job": job,
    }


def _failure(kind, step, cause, source):
    return {"kind": kind, "step": step, "cause": cause, "cause_source": source if cause else None}


def _from_record(rj, provenance_present, job):
    """(outcome, failure, steps, unknown) from attempt.json: the first step that did not end with 0, in order."""
    conclusion = (job or {}).get("conclusion")
    by_job = (f"job {conclusion}", "jobs.json") if conclusion else (None, None)
    gen, enrich = rj.get("generate") or {}, rj.get("enrich") or {}
    steps = {"generate": gen, "enrich": enrich or None, "archive_check": rj.get("archive_check"),
             "provenance": provenance_present}
    unknown = [f"generate.{k}" for k in ("started_at", "ended_at", "exit_status") if gen.get(k) is None]
    unknown += [] if rj.get("vens_binary_sha256") else ["vens_binary_sha256"]
    if gen.get("exit_status") is None:
        cause = ("timeout", "attempt.json") if gen.get("timed_out") else by_job
        return FAILED, _failure(INTERRUPTED, "generate", *cause), steps, unknown
    if gen["exit_status"] != 0:
        return FAILED, _failure(SCORING, "generate", None, None), steps, unknown
    if rj.get("runner") != "baseline.yml":
        return COMPLETE, None, steps, unknown
    if enrich.get("exit_status") is None:
        return FAILED, _failure(LATER_STEP, "enrich", *by_job), steps, unknown + ["enrich.exit_status"]
    if enrich["exit_status"] != 0:
        return FAILED, _failure(LATER_STEP, "enrich", f"vens enrich exited {enrich['exit_status']}",
                                "attempt.json"), steps, unknown
    check = rj.get("archive_check")
    if check != "success":
        cause = (f"archive check {check}", "attempt.json") if check else by_job
        return FAILED, _failure(LATER_STEP, "archive_check", *cause), steps, unknown
    if not (rj.get("provenance") and provenance_present):
        return FAILED, _failure(LATER_STEP, "provenance", "provenance.json not written", "attempt.json"), steps, unknown
    return COMPLETE, None, steps, unknown


def _without_record(folder, files, failure_line):
    """(outcome, failure, steps, implied, unknown) for a download made before the record: provenance.json, written
    last, means every step passed (baseline.yml's order under set -euo pipefail); without it, the attempt failed
    at a step the download does not name."""
    if files["provenance"] is not None:
        steps = {"generate": {"exit_status": 0}, "enrich": {"exit_status": 0}, "archive_check": "success",
                 "provenance": True}
        implied = ["generate.exit_status", "enrich.exit_status", "archive_check"]
        return COMPLETE, None, steps, implied, list(_UNTIMED)
    if files["vex"] is not None:
        raise Refused(f"{folder}: a VEX but no provenance.json and no attempt.json; a truncated download is not a "
                      f"failed job")
    error = (failure_line or {}).get("error")
    failure = {**_failure(None, None, error, "failures.txt"), "reason": NO_PROVENANCE}
    steps = {"generate": None, "enrich": None, "archive_check": None, "provenance": False}
    unknown = list(_UNTIMED) + ["generate.exit_status", "enrich.exit_status", "archive_check", "failure.kind",
                                "failure.step"]
    return FAILED, failure, steps, [], unknown + ([] if error else ["failure.cause"])


def _run_failed(summary, outcome, failure):
    """Whether `vens generate` itself failed, None when nothing says: a later step's failure leaves a run that
    completed, whose summary's counters hold."""
    if summary is not None:
        return summary.get("failed")
    if outcome == COMPLETE or failure["kind"] == LATER_STEP:
        return False
    return True if failure["kind"] in (SCORING, INTERRUPTED) else None


def read_attempt(folder, *, arm=None, line=None, job=None, failure_line=None, meta=None):
    """The record of one attempt. arm: 'before' or 'after' when the caller knows it (the dispatch log's line gives
    it otherwise); line: the dispatch log's line for this attempt; job: its jobs.json entry; failure_line: the
    failures.txt entry for its job (downloads made before the record); meta: its run's dispatch metadata
    (run_meta), the last source of what was dispatched."""
    files = _files(folder)
    rj, prov = _json(files["record"]), _json(files["provenance"])
    name = parse_name(os.path.basename(os.path.normpath(folder)))
    if rj is None and prov is None and name is None:
        raise Refused(f"{folder}: no attempt.json, no provenance.json and not an artefact's name")
    what = _what(rj, prov, name, line, arm, meta)
    problems = []
    for source, value in (("argument", arm), ("dispatch log", (line or {}).get("arm")), ("attempt.json",
                                                                                         (rj or {}).get("arm"))):
        if value is not None and value != what["arm"]:
            problems.append(f"arm {value} from the {source}, {what['arm']} taken")
    if rj is not None:
        outcome, failure, steps, unknown = _from_record(rj, files["provenance"] is not None, job)
        implied = []
    else:
        outcome, failure, steps, implied, unknown = _without_record(folder, files, failure_line)

    recs = venslog.read(files["log"]) if files["log"] else None
    if recs is None:
        unknown += ["log", "summary"]
    summary = venslog.summary(recs) if recs is not None else None
    if failure is not None and failure["kind"] == SCORING and recs is not None:
        failure = {**failure, "cause": venslog.cause(recs), "cause_source": "vens log"}
    if failure is not None and failure["kind"] in (SCORING, INTERRUPTED) and recs is None and failure["cause"] is None:
        unknown += ["failure.cause"]

    run_dirs = files["run_dirs"]
    archived = callmod.load(run_dirs[0]) if run_dirs and len(run_dirs) == 1 else None
    if archived is None:
        unknown += ["calls"]
    kinds, why = callmod.classify(archived, what["arm"]) if archived is not None else (None, None)
    if why:
        problems.append(why)
    rec = recovery.breakdown(summary, recs, archived, kinds, _run_failed(summary, outcome, failure))
    problems += rec.pop("problems")
    estimate = cost.estimate(archived, kinds, what["model"])

    evidence = cdx.evidence(files["attestation"]) if files["attestation"] else None
    attested = sorted({(e.get("provider"), e.get("model")) for e in evidence}) if evidence is not None else None
    if evidence is not None and archived is not None:
        check = callmod.archive_check(run_dirs, archived, evidence, what["provider"], what["model"])
    else:
        check = (None, "no attestation or no archived calls")
    ratings, vex_problems = cdx.ratings(files["vex"]) if files["vex"] else (None, [])

    doc = answersmod.load(files["answers"]) if files["answers"] else None
    answers = None
    if doc is not None:
        rated, unrated = answersmod.entries(doc)
        found = answersmod.unrated_shape(doc) + (answersmod.check(doc, ratings) if ratings is not None else [])
        answers = {"rated": len(rated), "unrated": len(unrated), "counters": doc["counters"],
                   "defects": doc["defects"], "problems": found,
                   "per_cve": {vid: answersmod.per_cve(e) for vid, e in {**rated, **unrated}.items()}}
        if summary is not None and (summary["counters"], summary["defects"]) != (doc["counters"], doc["defects"]):
            problems.append("answers.json's counters or defects differ from the run summary's")

    incomplete = []
    if outcome == COMPLETE and what["arm"] == "after" and doc is None:
        incomplete.append("a complete run's VEX without its answers.json")
    if outcome == COMPLETE and ratings is None:
        incomplete.append("a complete attempt without a VEX")
    usable = (outcome == COMPLETE and ratings is not None and not vex_problems and check[0] is True
              and not incomplete)
    if outcome == COMPLETE and check[0] is not True:
        problems.append(f"archive check, restated: {check[1]}")
    return {
        "folder": folder, "record": "attempt.json" if rj is not None else None, "what": what,
        "models_attested": attested, "outcome": outcome, "failure": failure, "steps": steps,
        "implied": implied, "unknown": sorted(set(unknown)), "job": job, "summary": summary,
        "calls": {"archived": None if archived is None else len(archived),
                  "with_reply": None if archived is None else sum(1 for c in archived if c.response is not None),
                  "kinds": kinds},
        "recovery": rec, "cost_estimate": estimate, "archive_check": {"passed": check[0], "reason": check[1]},
        "answers": answers, "ratings": ratings, "vex_problems": vex_problems, "scores_usable": usable,
        "incomplete": incomplete, "problems": problems,
    }


def without_artefact(job, model, run_id):
    """An attempt jobs.json lists, failed or interrupted, with no artefact downloaded: its job's conclusion only."""
    m = re.fullmatch(r"(.+) · run (\d+)", job["name"])
    conclusion = job.get("conclusion")
    kind = INTERRUPTED if conclusion in ("cancelled", "timed_out") else None
    what = {"runner": "baseline.yml", "context": m.group(1) if m else None,
            "replicate_in_run": int(m.group(2)) if m else None, "model": model, "run_id": run_id,
            "run_attempt": job.get("run_attempt"), "job": job["name"]}
    return {"folder": None, "record": None, "what": what, "models_attested": None, "outcome": FAILED,
            "failure": _failure(kind, None, f"job {conclusion}", "jobs.json"),
            "steps": {"generate": None, "enrich": None, "archive_check": None, "provenance": False}, "implied": [],
            "unknown": ["artefact", "calls", "log", "summary"], "job": job, "summary": None,
            "calls": {"archived": None, "with_reply": None, "kinds": None}, "recovery": None, "cost_estimate": None,
            "archive_check": {"passed": None, "reason": "no artefact"}, "answers": None, "ratings": None,
            "vex_problems": [], "scores_usable": False, "incomplete": [], "problems": []}
