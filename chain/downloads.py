"""A baseline.yml campaign as downloaded: one folder per workflow run, `gh run download <id> -D <id>`, holding one
artefact folder per attempt, beside the run's run.json, jobs.json and artifacts.json from the GitHub API.
"""
import glob
import json
import os
import re

from chain import attempt as attemptmod
from chain import dispatch, venslog
from chain.attempt import Refused

INHERITED = ("provider", "model", "batch_size", "vens_commit", "run_id")
_FAILURE = re.compile(r"(?:run (\d+) \| )?attempt (\d+) \| job (\d+) \| (.+?) \| (.*)")
_JOB = re.compile(r"(.+) · run (\d+)")


def load_jobs(path):
    """Every job of every run attempt, as the API lists them or as 0B archived them, in one shape:
    {id, name, run_attempt, status, conclusion, started_at, completed_at, steps}."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    jobs = doc["jobs"] if isinstance(doc, dict) else doc
    return [{"id": j.get("id"), "name": j.get("name"), "run_attempt": j.get("run_attempt", j.get("attempt")),
             "status": j.get("status"), "conclusion": j.get("conclusion"), "started_at": j.get("started_at"),
             "completed_at": j.get("completed_at"), "steps": j.get("steps")} for j in jobs]


def load_failures(path):
    """failures.txt as 0B wrote it: per failed job, its run (phase 2 only), attempt, job id and name, and the
    error line taken from the job's log."""
    out = []
    if path is None or not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as fh:
        for text in fh:
            m = _FAILURE.fullmatch(text.rstrip("\n"))
            if not m:
                continue
            log = venslog.fields(m.group(5))
            out.append({"run_id": int(m.group(1)) if m.group(1) else None, "attempt": int(m.group(2)),
                        "job_id": int(m.group(3)), "job": m.group(4), "error": log.get("error"),
                        "line": m.group(5)})
    return out


def carried_over(job, jobs):
    """Whether a job of a rerun attempt is the copy GitHub lists of an earlier attempt's successful job: same name,
    same start and end. It did not run again; its artefact is the earlier attempt's."""
    return job["run_attempt"] > 1 and job["started_at"] is not None and any(
        other["name"] == job["name"] and other["run_attempt"] < job["run_attempt"] and other["conclusion"] == "success"
        and (other["started_at"], other["completed_at"]) == (job["started_at"], job["completed_at"])
        for other in jobs)


def _run(run_dir, folders):
    """(run id, the run's dispatch metadata from run.json): one id from the folder's name, run.json and every
    record, else Refused."""
    path = os.path.join(run_dir, "run.json")
    ids, meta = set(), {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            meta = attemptmod.run_meta(json.load(fh))
        ids.add(meta["run_id"])
    base = os.path.basename(os.path.normpath(run_dir))
    if base.isdigit():
        ids.add(int(base))
    for f in folders:
        for name in ("attempt.json", "provenance.json"):
            p = os.path.join(f, name)
            if os.path.exists(p):
                with open(p, encoding="utf-8") as fh:
                    rid = json.load(fh).get("run_id")
                if rid is not None:
                    ids.add(int(rid))
    if len(ids) != 1:
        raise Refused(f"{run_dir}: run ids {sorted(ids)}; one folder holds one workflow run")
    run_id = ids.pop()
    return run_id, {**meta, "run_id": run_id}


def _sources(folder, name):
    out = {"name": {"model": name["model"]}}
    for source in ("attempt.json", "provenance.json"):
        p = os.path.join(folder, source)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                doc = json.load(fh)
            out[source] = {"vens_sha": doc.get("vens_sha"), "model": doc.get("model")}
    return out


def _artefact(folder, run_id, meta, jobs, idx, arm, failures, commits):
    """One artefact folder of run run_id, mapped through the dispatch log index idx when there is one."""
    name = attemptmod.parse_name(os.path.basename(os.path.normpath(folder)))
    if name is None:
        raise Refused(f"{folder}: the name does not parse as baseline-<model>-<context>-r<n>-a<attempt>")
    job_name = f"{name['context']} · run {name['replicate']}"
    job = next((j for j in jobs if j["run_attempt"] == name["attempt"] and j["name"] == job_name
                and j["conclusion"] is not None), None)
    line = None
    if idx is not None:
        line = dispatch.line_for(idx, run_id, name["attempt"], folder)
        dispatch.check_folder(folder, line, _sources(folder, name))
    failure = next((f for f in failures if f["attempt"] == name["attempt"] and f["job"] == job_name
                    and f["run_id"] in (None, run_id) and (job is None or f["job_id"] == job["id"])), None)
    rec = attemptmod.read_attempt(folder, arm=arm, line=line, job=job, failure_line=failure, meta=meta,
                                  commits=commits)
    return rec, (name["context"], name["replicate"], name["attempt"])


def read_folder(folder, *, lines=None, arm=None, failures=(), commits=None):
    """One attempt folder read on its own. With a dispatch log, it must be a baseline.yml artefact the log maps,
    its run id from its parent folder or its records."""
    if lines is None:
        return attemptmod.read_attempt(folder, arm=arm, commits=commits)
    if attemptmod.parse_name(os.path.basename(os.path.normpath(folder))) is None:
        raise Refused(f"{folder}: a dispatch log maps baseline.yml artefacts, and this is not one")
    parent = os.path.dirname(os.path.normpath(folder))
    run_id, meta = _run(parent, [folder]) if os.path.basename(parent).isdigit() else _run(folder, [folder])
    jobs = load_jobs(os.path.join(parent, "jobs.json"))
    rec, _ = _artefact(folder, run_id, meta, jobs, dispatch.index(lines), arm, failures, commits)
    return rec


def read_run(run_dir, *, lines=None, arm=None, failures=(), commits=None):
    """Every attempt of one workflow run. lines: the dispatch log, when the campaign has one: each folder is then
    mapped through it, and refused when no line names its run or attempt, or when its record gives another commit
    or model. Without a log, the folders with provenance.json must agree on what was dispatched (0B's rule). A job
    with no artefact folder is a failed attempt whatever its conclusion, and a logged attempt with neither folder
    nor job is flagged."""
    folders = sorted(f for f in glob.glob(os.path.join(run_dir, "baseline-*")) if os.path.isdir(f))
    run_id, meta = _run(run_dir, folders)
    jobs = load_jobs(os.path.join(run_dir, "jobs.json"))
    idx = dispatch.index(lines) if lines is not None else None
    records, seen = [], set()
    for folder in folders:
        rec, where = _artefact(folder, run_id, meta, jobs, idx, arm, failures, commits)
        records.append(rec)
        seen.add(where)
    if idx is None:
        dispatched = {tuple(r["what"][k] for k in INHERITED) for r in records if r["steps"].get("provenance")}
        if len(dispatched) > 1:
            raise Refused(f"{run_dir}: the folders with provenance.json disagree on {', '.join(INHERITED)}: "
                          f"{sorted(dispatched, key=str)}")
    model = meta.get("model") or next((r["what"]["model"] for r in records), None)
    ran = [j for j in jobs if not carried_over(j, jobs)]
    for job in ran:
        m = _JOB.fullmatch(job["name"] or "")
        if not m or job["conclusion"] is None or (m.group(1), int(m.group(2)), job["run_attempt"]) in seen:
            continue
        line = dispatch.line_for(idx, run_id, job["run_attempt"], f"{run_dir} job {job['id']}") if idx else None
        records.append(attemptmod.without_artefact(job, model, run_id, line))
    for attempt, line in sorted((idx or {}).get(run_id, {}).items()):
        if not any(a == attempt for _, _, a in seen) and not any(j["run_attempt"] == attempt for j in ran):
            records.append(attemptmod.not_downloaded(
                line, f"run {run_id} attempt {attempt} is in the dispatch log, with no artefact folder and no job"))
    return records


def read_downloads(root, *, lines=None, arm=None, failures=(), commits=None):
    """Every workflow run under root, one numeric folder each; with a dispatch log, also every run it names that
    root does not hold, and every pending dispatch it never resolved, each flagged."""
    runs = sorted(d for d in os.listdir(root) if d.isdigit() and os.path.isdir(os.path.join(root, d)))
    records = [r for d in runs for r in read_run(os.path.join(root, d), lines=lines, arm=arm, failures=failures,
                                                 commits=commits)]
    if lines is None:
        return records
    held = {int(d) for d in runs}
    for run_id, attempts in sorted(dispatch.index(lines).items()):
        if run_id not in held:
            records += [attemptmod.not_downloaded(line, f"run {run_id} attempt {a} is in the dispatch log, its "
                                                        f"download is not") for a, line in sorted(attempts.items())]
    records += [attemptmod.not_downloaded(line, f"a pending dispatch of replicate {line['replicate']} of the "
                                                f"{line['arm']} the log never resolved")
                for line in dispatch.open_pending(lines)]
    return records
