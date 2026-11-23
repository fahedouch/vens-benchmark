"""A baseline.yml campaign as downloaded: one folder per workflow run, `gh run download <id> -D <id>`, holding one
artefact folder per attempt, beside the run's run.json, jobs.json and artifacts.json from the GitHub API.
"""
import glob
import os
import re

from chain import attempt as attemptmod
from chain import dispatch, venslog
from chain.errors import Refused, load_json, load_object

INHERITED = ("provider", "model", "batch_size", "vens_commit", "run_id")
_FAILURE = re.compile(r"(?:run (\d+) \| )?attempt (\d+) \| job (\d+) \| (.+?) \| (.*)")
_JOB = re.compile(r"(.+) · run (\d+)")


def load_jobs(path):
    """Every job of every run attempt, as the API lists them or as 0B archived them, in one shape:
    {id, name, run_attempt, status, conclusion, started_at, completed_at, steps}."""
    if not os.path.exists(path):
        return []
    doc = load_json(path)
    jobs = doc.get("jobs") if isinstance(doc, dict) else doc
    if not isinstance(jobs, list) or any(not isinstance(j, dict) for j in jobs):
        raise Refused(f"{path}: not a jobs listing")
    return [{"id": j.get("id"), "name": j.get("name"), "run_attempt": j.get("run_attempt", j.get("attempt")),
             "status": j.get("status"), "conclusion": j.get("conclusion"), "started_at": j.get("started_at"),
             "completed_at": j.get("completed_at"), "steps": j.get("steps")} for j in jobs]


def load_failures(path):
    """failures.txt as 0B wrote it: per failed job, its run (phase 2 only), attempt, job id and name, and the
    error line taken from the job's log."""
    out = []
    if path is None or not os.path.exists(path):
        return out
    try:
        with open(path, encoding="utf-8") as fh:
            texts = fh.read().splitlines()
    except UnicodeDecodeError as e:
        raise Refused(f"{path}: not UTF-8 text: {e}") from e
    for text in texts:
        m = _FAILURE.fullmatch(text)
        if not m:
            continue
        log = venslog.fields(m.group(5))
        out.append({"run_id": int(m.group(1)) if m.group(1) else None, "attempt": int(m.group(2)),
                    "job_id": int(m.group(3)), "job": m.group(4), "error": log.get("error"), "line": m.group(5)})
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
        meta = attemptmod.run_meta(load_object(path))
        if meta["run_id"] is not None:
            ids.add(meta["run_id"])
    base = os.path.basename(os.path.normpath(run_dir))
    if base.isdigit():
        ids.add(int(base))
    for f in folders:
        for name in ("attempt.json", "provenance.json"):
            p = os.path.join(f, name)
            if os.path.exists(p):
                rid = load_object(p).get("run_id")
                if rid is not None:
                    try:
                        ids.add(int(rid))
                    except (TypeError, ValueError) as e:
                        raise Refused(f"{p}: run_id {rid!r}, not a run id") from e
    if len(ids) != 1:
        raise Refused(f"{run_dir}: run ids {sorted(ids)}; one folder holds one workflow run")
    run_id = ids.pop()
    return run_id, {**meta, "run_id": run_id}


def check_dispatch_id(where, run_id, meta, idx):
    """Refused when the dispatch log names the run and the run's title, in its run.json, carries no dispatch id or
    another than the log's: the run is then not the one the log's line dispatched."""
    lines = idx.get(run_id)
    if not lines:
        return
    want, got = next(iter(lines.values()))["dispatch_id"], meta.get("dispatch_id")
    if got is None:
        raise Refused(f"{where}: no dispatch id in run {run_id}'s title, from its run.json; the dispatch log gives "
                      f"{want}")
    if got != want:
        raise Refused(f"{where}: run {run_id}'s title carries dispatch id {got}, the dispatch log {want}")


def _sources(folder, name):
    out = {"name": {"model": name["model"]}}
    for source in ("attempt.json", "provenance.json"):
        p = os.path.join(folder, source)
        if os.path.exists(p):
            doc = load_object(p)
            out[source] = {"vens_sha": doc.get("vens_sha"), "model": doc.get("model")}
    return out


def _artefact(folder, run_id, meta, jobs, idx, arm, failures, commits, rules=None):
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
                                  commits=commits, rules=rules)
    return rec, (name["context"], name["replicate"], name["attempt"])


def read_folder(folder, *, lines=None, arm=None, failures=(), commits=None, rules=None):
    """One attempt folder read on its own. A baseline.yml artefact is matched as read_run matches it, with its
    parent's run.json, jobs.json and the failures, and through the dispatch log when there is one; a scenario run's
    folder is read alone, and no dispatch log maps it."""
    if attemptmod.parse_name(os.path.basename(os.path.normpath(folder))) is None:
        if lines is not None:
            raise Refused(f"{folder}: a dispatch log maps baseline.yml artefacts, and this is not one")
        return attemptmod.read_attempt(folder, arm=arm, commits=commits, rules=rules)
    parent = os.path.dirname(os.path.normpath(folder))
    run_id, meta = _run(parent, [folder]) if is_run_dir(parent) else _run(folder, [folder])
    jobs = load_jobs(os.path.join(parent, "jobs.json"))
    idx = dispatch.index(lines) if lines is not None else None
    if idx is not None:
        check_dispatch_id(folder, run_id, meta, idx)
    rec, _ = _artefact(folder, run_id, meta, jobs, idx, arm, failures, commits, rules)
    return rec


def is_run_dir(path):
    """Whether path is one workflow run's download: a numeric name, or its run.json or jobs.json from the API."""
    return os.path.basename(os.path.normpath(path)).isdigit() or any(
        os.path.exists(os.path.join(path, n)) for n in ("run.json", "jobs.json"))


def _without_job(run_id, jobs, scoring, held, idx, arm, model):
    """Each attempt the dispatch log logs or jobs.json lists with no artefact folder and no job scoring a context,
    flagged: an attempt whose only job is plan is never dropped."""
    logged = (idx or {}).get(run_id, {})
    listed = {j["run_attempt"] for j in jobs if isinstance(j["run_attempt"], int)}
    out = []
    for attempt in sorted(set(logged) | listed):
        if attempt in held or attempt in scoring:
            continue
        others = ", ".join(f"{j['name']} {j['conclusion']}" for j in jobs if j["run_attempt"] == attempt)
        why = (f"run {run_id} attempt {attempt} is in {'the dispatch log' if attempt in logged else 'jobs.json'}, "
               f"with no artefact folder and no job") + (f" scoring a context, only {others}" if others else "")
        if idx is not None:
            line = dispatch.line_for(idx, run_id, attempt, f"run {run_id}, jobs.json")
        else:
            line = {"arm": arm, "model": model, "run_id": run_id, "run_attempt": attempt}
        out.append(attemptmod.not_downloaded(line, why, arm))
    return out


def _pending_rerun(line, arm=None):
    """A rerun the dispatch log asked for and never resolved: flagged, whether its attempt started unknown."""
    return attemptmod.not_downloaded(line, f"run {line['run_id']}: a rerun asking for attempt {line['run_attempt']}, "
                                           f"which the dispatch log never resolved: whether it started is unknown",
                                     arm, reason="a pending rerun")


def read_run(run_dir, *, lines=None, arm=None, failures=(), commits=None, rules=None):
    """Every attempt of one workflow run. lines: the dispatch log, when the campaign has one: each folder is then
    mapped through it, and refused when no line names its run or attempt, or when its record gives another commit
    or model, or when the run's title does not carry its line's dispatch id. Without a log, the folders with
    provenance.json must agree on what was dispatched (0B's rule). A job
    with no artefact folder is a failed attempt unless it succeeded, which a truncated download is refused for; an
    attempt logged or listed with neither folder nor a job scoring a context is flagged, and so is a rerun the log
    asked for and never resolved; a run that yields no attempt is refused."""
    folders = sorted(f for f in glob.glob(os.path.join(run_dir, "baseline-*")) if os.path.isdir(f))
    run_id, meta = _run(run_dir, folders)
    jobs = load_jobs(os.path.join(run_dir, "jobs.json"))
    idx = dispatch.index(lines) if lines is not None else None
    if idx is not None:
        check_dispatch_id(run_dir, run_id, meta, idx)
    records, seen = [], set()
    for folder in folders:
        rec, where = _artefact(folder, run_id, meta, jobs, idx, arm, failures, commits, rules)
        records.append(rec)
        seen.add(where)
    if idx is None:
        dispatched = {tuple(r["what"][k] for k in INHERITED) for r in records if r["steps"].get("provenance")}
        if len(dispatched) > 1:
            raise Refused(f"{run_dir}: the folders with provenance.json disagree on {', '.join(INHERITED)}: "
                          f"{sorted(dispatched, key=str)}")
    model = meta.get("model") or next((r["what"]["model"] for r in records), None)
    scoring = set()
    for job in (j for j in jobs if not carried_over(j, jobs)):
        m = _JOB.fullmatch(job["name"] or "")
        if not m:
            continue
        scoring.add(job["run_attempt"])
        if job["conclusion"] is None or (m.group(1), int(m.group(2)), job["run_attempt"]) in seen:
            continue
        if job["conclusion"] == "success":
            raise Refused(f"{run_dir}: job {job['id']} ({job['name']}, attempt {job['run_attempt']}) succeeded, yet "
                          f"its artefact is not in the download; a truncated download is not a failed job")
        line = dispatch.line_for(idx, run_id, job["run_attempt"], f"{run_dir} job {job['id']}") if idx else None
        records.append(attemptmod.without_artefact(job, model, run_id, line, arm))
    records += _without_job(run_id, jobs, scoring, {a for _, _, a in seen}, idx, arm, model)
    rerun = dispatch.open_reruns(lines).get(run_id) if lines is not None else None
    if rerun is not None:
        records.append(_pending_rerun(rerun, arm))
    if not records:
        raise Refused(f"{run_dir}: a workflow run with no attempt, no artefact folder and no job")
    return records


def read_downloads(root, *, lines=None, arm=None, failures=(), commits=None, rules=None):
    """Every workflow run under root, one numeric folder each; with a dispatch log, also every run it names that
    root does not hold, every pending rerun and every pending dispatch it never resolved, each flagged."""
    runs = sorted(d for d in os.listdir(root) if d.isdigit() and os.path.isdir(os.path.join(root, d)))
    records = [r for d in runs for r in read_run(os.path.join(root, d), lines=lines, arm=arm, failures=failures,
                                                 commits=commits, rules=rules)]
    if lines is None:
        return records
    held, reruns = {int(d) for d in runs}, dispatch.open_reruns(lines)
    for run_id, attempts in sorted(dispatch.index(lines).items()):
        if run_id not in held:
            records += [attemptmod.not_downloaded(line, f"run {run_id} attempt {a} is in the dispatch log, its "
                                                        f"download is not", arm)
                        for a, line in sorted(attempts.items())]
            records += [_pending_rerun(reruns[run_id], arm)] if run_id in reruns else []
    records += [attemptmod.not_downloaded(line, f"a pending dispatch of replicate {line['replicate']} of the "
                                                f"{line['arm']} the log never resolved", arm,
                                          reason="a pending dispatch") for line in dispatch.open_pending(lines)]
    return records
