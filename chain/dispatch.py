"""The dispatch script of the demo-scan campaigns that compare vens's two arms, and the reader of its log.

Each baseline.yml run of a campaign scores one replicate of one arm, so every run names its artefacts r1: the log
maps each run id, and each of its run attempts, to the arm, model and campaign replicate it measures. Per model,
replicate r of the before and replicate r of the after are dispatched together and run side by side; the next pair
starts once both runs have ended, and a run is rerun only before it.

Each dispatch declares its campaign's roster of arms; the log never sets it. By default the roster is both arms, as
above. With --one-arm it is the dispatched arm alone: replicate r goes once that arm's earlier replicates have run and
ended, no rerun of theirs pending, and the dispatch is refused while the campaign, under any provider or model, holds a
line of another arm.

dispatch-log.jsonl holds one JSON object per line, appended, never rewritten:

    {"campaign", "arm", "repo", "vens_ref", "vens_commit", "provider", "model", "batch_size", "archived_run",
     "dispatch_id", "replicate", "run_id", "run_attempt", "time", "action", "replaces", "conclusion"}

dispatch_id is made afresh for each dispatch and passed to baseline.yml, which puts it in the run's name: the run a
dispatch started is the one named with its id, whatever other run shares its inputs, a late run of an abandoned
dispatch included.

action is one of:
    pending          written before `gh workflow run`, run_id and run_attempt null: a run may exist no line names
    dispatch         the pending dispatch's run, read back from the API, run_attempt 1
    resolved         the pending dispatch's run attached by hand: its title, its run_attempt 1 and its creation after
                     the pending line checked; or, the same checks made, the late run of an abandoned dispatch whose
                     replicate was not dispatched again
    abandoned        a pending dispatch that started no run: at least 15 minutes old, and the run list, read back to
                     its time within GitHub's cap, holds no run of its title and no run the log does not name created
                     within two minutes of it. A run of its id that appears later blocks every new dispatch and
                     rerun until it is attached with resolve --run-id or recorded as a stray
    stray            the late run of an abandoned dispatch whose replicate was dispatched again, recorded once it has
                     ended, its title and creation checked against the abandoned dispatch: its calls count in the
                     spend, its scores are not its replicate's; conclusion, null on every other line, says how it ended
    rerun-pending    written before `gh run rerun --failed`, run_attempt the attempt it asks for
    rerun-failed     that attempt, read back from the API, replacing the attempt before it
    rerun-abandoned  a pending rerun that started no attempt: at least 15 minutes old, the run still at the attempt
                     before
The lines of one replicate, (campaign, arm, provider, model, replicate), agree on every field but run_id,
run_attempt, time, action, replaces and conclusion, and dispatch_id across an abandoned dispatch and the next. time is
UTC.
Every command holds an exclusive lock on LOG.lock while it reads the log, checks, calls gh and writes, so two
commands never act on the same state. This script writes the log; whoever runs the campaign owns it and commits it
with the campaign's archive.

    python3 -m chain.dispatch dispatch --log LOG --campaign NAME --arm after --vens-ref SHA --provider openai \
        --model gpt-5.4-mini-2026-03-17 --replicate 1 --max-side-by-side 2 [--one-arm]
    python3 -m chain.dispatch rerun --log LOG --run-id ID --retry-cap 4 --max-side-by-side 2
    python3 -m chain.dispatch resolve --log LOG --campaign NAME --arm after --provider openai \
        --model gpt-5.4-mini-2026-03-17 --replicate 1 (--run-id ID | --no-run)
    python3 -m chain.dispatch resolve --log LOG --campaign NAME --arm after --provider openai \
        --model gpt-5.4-mini-2026-03-17 --replicate 1 --stray --run-id ID
    python3 -m chain.dispatch resolve-rerun --log LOG --run-id ID [--no-rerun]
    python3 -m chain.dispatch check-late --log LOG

A campaign is archived only after check-late passes: no run of an abandoned dispatch is left out of its log.

gh is the executable --gh names, else $GH, else the one on PATH.
"""
import argparse
import contextlib
import datetime
import fcntl
import json
import os
import re
import secrets
import subprocess
import sys
import time

from chain.errors import Refused

FIELDS = ("campaign", "arm", "repo", "vens_ref", "vens_commit", "provider", "model", "batch_size", "archived_run",
          "dispatch_id", "replicate", "run_id", "run_attempt", "time", "action", "replaces", "conclusion")
KEY = ("campaign", "arm", "provider", "model", "replicate")
SAME = ("repo", "vens_ref", "vens_commit", "batch_size", "archived_run", "dispatch_id")
PENDING, DISPATCH, RESOLVED, ABANDONED = "pending", "dispatch", "resolved", "abandoned"
RERUN_PENDING, RERUN, RERUN_ABANDONED = "rerun-pending", "rerun-failed", "rerun-abandoned"
STRAY = "stray"
STARTS = (DISPATCH, RESOLVED)
ARMS = ("before", "after")
WORKFLOW = "baseline.yml"
# baseline.yml's name: GitHub gives a new run this title until its run-name renders.
WORKFLOW_NAME = "baseline"
POLLS, POLL_SECONDS = 20, 3
PER_PAGE, MAX_PAGES = 100, 20
# GitHub lists at most 1,000 runs of a filtered search (event=...); the pages past it come back empty.
LISTING_CAP = 1000
SETTLE = datetime.timedelta(minutes=15)
SKEW = datetime.timedelta(minutes=2)


class DispatchError(Exception):
    pass


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def _stamp(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(stamp):
    return datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def key(line):
    return tuple(line[k] for k in KEY)


@contextlib.contextmanager
def locked(log):
    """An exclusive lock on LOG.lock for the whole of one command."""
    os.makedirs(os.path.dirname(os.path.abspath(log)), exist_ok=True)
    with open(log + ".lock", "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def load(path):
    """The log's lines, checked: every field present and every action known; a dispatch, resolved or abandoned line
    closing its replicate's pending line on the same fields; a pending rerun asking for the attempt after its run's
    last one, on its run's fields, and closed by that attempt or abandoned; a stray line naming the run of an
    abandoned dispatch dispatched again since, on its fields, and never rerun; each run id one line's and each
    (run id, run attempt) logged once."""
    if not os.path.exists(path):
        return []
    lines, pending, started, attempts, owner, reruns, abandoned = [], {}, {}, {}, {}, {}, {}
    gone = {}  # dispatch id: {"line": its abandoned line, "again": its replicate dispatched again since}
    with open(path, encoding="utf-8") as fh:
        for n, text in enumerate(fh, 1):
            if not text.strip():
                continue
            where = f"{path}:{n}"
            try:
                line = json.loads(text)
            except ValueError as e:
                raise DispatchError(f"{where}: not a JSON line, cut short or corrupted: {e}") from e
            if not isinstance(line, dict):
                raise DispatchError(f"{where}: a JSON {type(line).__name__}, not a line of the log")
            missing = [f for f in FIELDS if f not in line]
            if missing:
                raise DispatchError(f"{where}: missing {missing}")
            k, action = key(line), line["action"]
            if action == PENDING:
                if k in pending or k in started:
                    raise DispatchError(f"{where}: a second dispatch of replicate {line['replicate']} of {line['arm']}")
                pending[k] = line
                abandoned.pop(k, None)
                for g in gone.values():
                    g["again"] = g["again"] or key(g["line"]) == k
            elif action in STARTS + (ABANDONED,):
                # A resolved line may also attach the late run of the replicate's abandoned dispatch.
                before = pending.get(k) or (abandoned.get(k) if action == RESOLVED else None)
                if before is None:
                    raise DispatchError(f"{where}: a {action} line with no pending dispatch before it")
                changed = [f for f in SAME if line[f] != before[f]]
                if changed:
                    raise DispatchError(f"{where}: a {action} line changes {changed} of its pending dispatch")
                pending.pop(k, None)
                abandoned.pop(k, None)
                gone.pop(line["dispatch_id"], None)
                if action == ABANDONED:
                    abandoned[k] = line
                    gone[line["dispatch_id"]] = {"line": line, "again": False}
                else:
                    _start(line, where, owner, attempts)
                    started[k] = line
            elif action == STRAY:
                _stray_line(line, where, gone.pop(line["dispatch_id"], None), owner)
            elif action in (RERUN_PENDING, RERUN, RERUN_ABANDONED):
                first = owner.get(line["run_id"])
                if first is None:
                    raise DispatchError(f"{where}: a {action} line for run {line['run_id']}, which no dispatch names")
                if first["action"] == STRAY:
                    raise DispatchError(f"{where}: a {action} line for run {line['run_id']}, a stray run")
                changed = [f for f in KEY + SAME if line[f] != first[f]]
                if changed:
                    raise DispatchError(f"{where}: a rerun changes {changed} of run {line['run_id']}")
                if line["replaces"] != line["run_attempt"] - 1:
                    raise DispatchError(f"{where}: a rerun replaces the attempt before it")
                asked = reruns.get(line["run_id"])
                if action == RERUN_PENDING:
                    if asked is not None:
                        raise DispatchError(f"{where}: a second pending rerun of run {line['run_id']}")
                    if line["run_attempt"] != attempts[line["run_id"]] + 1:
                        raise DispatchError(f"{where}: a rerun of run {line['run_id']} without its attempt before")
                    reruns[line["run_id"]] = line
                else:
                    if asked is None or asked["run_attempt"] != line["run_attempt"]:
                        raise DispatchError(f"{where}: a {action} line with no pending rerun of that attempt before")
                    del reruns[line["run_id"]]
                    if action == RERUN:
                        attempts[line["run_id"]] = line["run_attempt"]
            else:
                raise DispatchError(f"{where}: unknown action {action!r}")
            lines.append(line)
    return lines


def _stray_line(line, where, g, owner):
    if g is None or not g["again"]:
        raise DispatchError(f"{where}: a stray line whose dispatch id is of no abandoned dispatch dispatched "
                            f"again since")
    changed = [f for f in KEY + SAME if line[f] != g["line"][f]]
    if changed:
        raise DispatchError(f"{where}: a stray line changes {changed} of its abandoned dispatch")
    if not (isinstance(line["run_id"], int) and isinstance(line["run_attempt"], int) and line["run_attempt"] >= 1
            and line["replaces"] is None and line["conclusion"]):
        raise DispatchError(f"{where}: a stray line names a run, its attempt and how it ended, and replaces nothing")
    if line["run_id"] in owner:
        raise DispatchError(f"{where}: run {line['run_id']} is already another line's")
    owner[line["run_id"]] = line


def _start(line, where, owner, attempts):
    if line["run_attempt"] != 1 or line["replaces"] is not None or not isinstance(line["run_id"], int):
        raise DispatchError(f"{where}: a run starts at attempt 1 with a run id and replaces nothing")
    if line["run_id"] in owner:
        raise DispatchError(f"{where}: run {line['run_id']} is already another replicate's")
    owner[line["run_id"]] = line
    attempts[line["run_id"]] = 1


def index(lines):
    """{run id: {run attempt: line}}, from the lines that name a run's attempt; a stray line names each attempt of
    its run up to the one it recorded."""
    out = {}
    for line in lines:
        if line["action"] in STARTS + (RERUN,):
            out[line["run_id"]] = {**out.get(line["run_id"], {}), line["run_attempt"]: line}
        elif line["action"] == STRAY:
            out[line["run_id"]] = {n: line for n in range(1, line["run_attempt"] + 1)}
    return out


def open_pending(lines):
    """The pending dispatches no later line closes: each may have started a run the log does not name."""
    out = {}
    for line in lines:
        if line["action"] == PENDING:
            out[key(line)] = line
        elif line["action"] in STARTS + (ABANDONED,):
            out.pop(key(line), None)
    return list(out.values())


def open_reruns(lines):
    """{run id: pending rerun} no later line closes: each may have started an attempt the log does not name."""
    out = {}
    for line in lines:
        if line["action"] == RERUN_PENDING:
            out[line["run_id"]] = line
        elif line["action"] in (RERUN, RERUN_ABANDONED):
            out.pop(line["run_id"], None)
    return out


def abandoned_dispatch(lines, k):
    """The pending line of replicate k's last dispatch when that dispatch was abandoned and nothing came after; a
    stray line, the late run of an earlier abandoned dispatch, leaves it recoverable."""
    mine = [l for l in lines if key(l) == k and l["action"] != STRAY]
    if not mine or mine[-1]["action"] != ABANDONED:
        return None
    return next(l for l in reversed(mine) if l["action"] == PENDING and l["dispatch_id"] == mine[-1]["dispatch_id"])


def line_for(idx, run_id, attempt, folder):
    """The line of a downloaded attempt; Refused for a run no line names or an attempt no line logs."""
    if run_id not in idx:
        raise Refused(f"{folder}: no line of the dispatch log names run {run_id}")
    if attempt not in idx[run_id]:
        raise Refused(f"{folder}: run {run_id}'s attempt {attempt} is not in the dispatch log")
    return idx[run_id][attempt]


def check_folder(folder, line, sources):
    """Refused when the folder's attempt.json, provenance.json or name gives another vens commit or model than its
    line. sources: {source name: {"vens_sha", "model"}} as each gives them."""
    for source, values in sources.items():
        commit, model = values.get("vens_sha"), values.get("model")
        if commit is not None and commit != line["vens_commit"]:
            raise Refused(f"{folder}: {source} gives vens {commit}, the dispatch log {line['vens_commit']}")
        if model is not None and model != line["model"]:
            raise Refused(f"{folder}: {source} gives model {model}, the dispatch log {line['model']}")


def title(archived_run, provider, model, batch, commit, dispatch_id=None):
    """baseline.yml's run-name for a one-replicate run pinned to a commit, ending with its dispatch id when it has
    one."""
    name = f"baseline · {archived_run} · {provider}/{model} · batch {batch} · x1 · vens {commit}"
    return f"{name} · dispatch {dispatch_id}" if dispatch_id else name


def new_dispatch_id():
    return secrets.token_hex(6)


def dispatch_id_of(run):
    """The dispatch id a run's title ends with, None when it has none."""
    m = re.search(r" · dispatch (\S+)$", run.get("display_title") or "")
    return m.group(1) if m else None


def inputs(a, commit, dispatch_id):
    """The workflow inputs of one dispatch, as `gh workflow run -f` passes them."""
    return {"archived-run": a.archived_run, "provider": a.provider, "model": a.model, "batch-size": str(a.batch_size),
            "replicates": "1", "vens-ref": commit, "arm": a.arm, "dispatch-id": dispatch_id}


def _gh(gh, *args):
    try:
        r = subprocess.run([gh, *args], capture_output=True, text=True)
    except OSError as e:
        raise DispatchError(f"gh: {e}") from e
    if r.returncode != 0:
        raise DispatchError(f"gh {' '.join(args[:3])}: exit {r.returncode}: {r.stderr.strip()[-300:]}")
    return r.stdout + r.stderr


def _api(gh, path):
    return json.loads(_gh(gh, "api", path))


def _append(path, line):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({f: line[f] for f in FIELDS}) + "\n")


def runs_since(gh, repo, since, pages=None):
    """The workflow_dispatch runs of baseline.yml created from since on, clock skew allowed, newest first, and
    whether the listing reached since: it stops at an older run or at the list's end, and falls short when the pages
    run out first or GitHub's cap on a filtered listing is met, whose next page is empty whatever is older."""
    floor, out, listed = since - SKEW, [], 0
    for page in range(1, (pages or MAX_PAGES) + 1):
        runs = _api(gh, f"repos/{repo}/actions/workflows/{WORKFLOW}/runs?event=workflow_dispatch&per_page="
                        f"{PER_PAGE}&page={page}").get("workflow_runs") or []
        listed += len(runs)
        out += [r for r in runs if _parse(r["created_at"]) >= floor]
        if any(_parse(r["created_at"]) < floor for r in runs):
            return out, True
        if listed >= LISTING_CAP:
            return out, False
        if len(runs) < PER_PAGE:
            return out, True
    return out, False


def _titled(runs, want_title, known):
    return sorted(r["id"] for r in runs if r.get("display_title") == want_title and r["id"] not in known)


def _find_run(gh, repo, want_title, since, known, sleep):
    for _ in range(POLLS):
        runs, _ = runs_since(gh, repo, since)
        found = _titled(runs, want_title, known)
        if len(found) > 1:
            raise DispatchError(f"{len(found)} new runs titled {want_title!r}: {found}")
        if found:
            return found[0]
        sleep(POLL_SECONDS)
    raise DispatchError(f"no new run titled {want_title!r} after {POLLS} polls")


def _rendered(gh, repo, run_id, sleep):
    """The run as the API gives it, read again while its title is still the bare workflow name GitHub shows before
    the run-name renders; after POLLS reads, the run as last read, for the caller to check."""
    path = f"repos/{repo}/actions/runs/{run_id}"
    run = _api(gh, path)
    for _ in range(POLLS - 1):
        if run.get("display_title") != WORKFLOW_NAME:
            break
        sleep(POLL_SECONDS)
        run = _api(gh, path)
    return run


class _Status:
    """Each logged run's status from the API, asked once."""

    def __init__(self, gh, lines):
        self.gh, self.repo, self.seen = gh, {l["run_id"]: l["repo"] for l in lines if l["action"] in STARTS}, {}

    def __call__(self, run_id):
        if run_id not in self.seen:
            self.seen[run_id] = _api(self.gh, f"repos/{self.repo[run_id]}/actions/runs/{run_id}")["status"]
        return self.seen[run_id]


def _check_cap(lines, status, cap):
    if not isinstance(cap, int) or cap < 1:
        raise DispatchError("--max-side-by-side must be a positive number")
    running = {l["run_id"] for l in lines if l["action"] in STARTS and status(l["run_id"]) != "completed"}
    running |= set(open_reruns(lines))
    waiting = open_pending(lines)
    if len(running) + len(waiting) >= cap:
        raise Refused(f"{len(running)} runs not ended or asked to rerun {sorted(running)} and {len(waiting)} pending "
                      f"dispatches, at the cap of {cap} side by side")


def _check_late_runs(gh, lines):
    """Refused while a run the log does not name carries the dispatch id of an abandoned dispatch, whatever its end:
    GitHub started it late, it may have made calls, and a new dispatch or rerun could pay for its replicate twice.
    Each repository's run list is read back to its oldest abandoned dispatch; refused when it cannot be."""
    abandoned = [l for l in lines if l["action"] == ABANDONED]
    if not abandoned:
        return
    ids = {l["dispatch_id"] for l in abandoned}
    asked = {l["dispatch_id"]: _parse(l["time"]) for l in lines if l["action"] == PENDING and l["dispatch_id"] in ids}
    known, late = set(index(lines)), []
    for repo in sorted({l["repo"] for l in abandoned}):
        since = min(asked[l["dispatch_id"]] for l in abandoned if l["repo"] == repo)
        runs, reached = runs_since(gh, repo, since)
        if not reached:
            raise Refused(f"the run list of {repo} did not reach {_stamp(since)}, the oldest abandoned dispatch, "
                          f"within GitHub's cap of {LISTING_CAP} runs and {MAX_PAGES} pages: a late run of it may "
                          f"exist")
        late += [r["id"] for r in runs if r["id"] not in known and dispatch_id_of(r) in ids]
    if late:
        raise Refused(f"runs {sorted(late)} carry the dispatch id of an abandoned dispatch: attach each with resolve "
                      f"--run-id, or once it has ended and its replicate was dispatched again record it with resolve "
                      f"--stray --run-id")


def check_late(a, gh):
    """The late-run check alone, under the lock; Refused while a run the log does not name carries an abandoned
    dispatch's id."""
    with locked(a.log):
        lines = load(a.log)
        _check_late_runs(gh, lines)
        return {"log": a.log, "abandoned": sorted({l["dispatch_id"] for l in lines if l["action"] == ABANDONED}),
                "late_runs": []}


def _dispatched(lines, campaign, provider, model):
    """The replicates of one campaign and model a run or an open pending dispatch holds: {(arm, replicate)}."""
    same = lambda l: (l["campaign"], l["provider"], l["model"]) == (campaign, provider, model)
    return ({(l["arm"], l["replicate"]) for l in lines if same(l) and l["action"] in STARTS}
            | {(l["arm"], l["replicate"]) for l in open_pending(lines) if same(l)})


def roster(a):
    """The arms of the dispatch's campaign, as the dispatch declares them: the arm it dispatches alone with
    --one-arm, else both."""
    return (a.arm,) if a.one_arm else ARMS


def _check_roster(lines, campaign, arms):
    """Refused when the campaign, under any provider or model, holds a line of an arm outside its roster."""
    others = sorted({l["arm"] for l in lines if l["campaign"] == campaign and l["arm"] not in arms})
    if others:
        raise Refused(f"campaign {campaign} holds lines of the {' and the '.join(others)}, an arm outside its roster "
                      f"{list(arms)}")


def _check_pairing(lines, a, status, arms):
    """Replicate r of an arm goes once the earlier replicates of every arm of the roster have run and ended, no rerun
    of theirs pending, and never after a later replicate: in a two-arm campaign, both arms' earlier replicates."""
    if a.replicate < 1:
        raise Refused("replicates count from 1")
    later = sorted(r for _, r in _dispatched(lines, a.campaign, a.provider, a.model) if r > a.replicate)
    if later:
        raise Refused(f"replicate {later[0]} of {a.campaign} is already dispatched")
    mine = [l for l in lines if (l["campaign"], l["provider"], l["model"]) == (a.campaign, a.provider, a.model)]
    starts = {(l["arm"], l["replicate"]): l["run_id"] for l in mine if l["action"] in STARTS}
    earlier = [(arm, r) for r in range(1, a.replicate) for arm in arms]
    turn = "the pair goes" if len(arms) > 1 else "it goes"
    for arm, r in earlier:
        if (arm, r) not in starts:
            raise Refused(f"replicate {r} of the {arm} is not dispatched: {turn} before replicate {a.replicate}")
    reruns = open_reruns(lines)
    for arm, r in earlier:
        if starts[(arm, r)] in reruns:
            raise Refused(f"replicate {r} of the {arm}, run {starts[(arm, r)]}, has a pending rerun")
        if status(starts[(arm, r)]) != "completed":
            raise Refused(f"replicate {r} of the {arm}, run {starts[(arm, r)]}, has not ended")


def dispatch(a, gh, now=utc_now, sleep=time.sleep):
    with locked(a.log):
        return _dispatch(a, gh, now, sleep)


def _dispatch(a, gh, now, sleep):
    lines = load(a.log)
    status = _Status(gh, lines)
    k = (a.campaign, a.arm, a.provider, a.model, a.replicate)
    pending = {key(l): l for l in open_pending(lines)}
    if k in pending:
        raise Refused(f"replicate {a.replicate} of the {a.arm} has a pending dispatch since {pending[k]['time']}: "
                      f"resolve it first")
    started = [l for l in lines if key(l) == k and l["action"] in STARTS]
    if started:
        raise Refused(f"replicate {a.replicate} of the {a.arm} is already run {started[0]['run_id']}; rerun it instead")
    arms = roster(a)
    _check_roster(lines, a.campaign, arms)
    _check_pairing(lines, a, status, arms)
    _check_cap(lines, status, a.max_side_by_side)
    _check_late_runs(gh, lines)
    commit = _api(gh, f"repos/venslabs/vens/commits/{a.vens_ref}")["sha"]
    did = new_dispatch_id()
    want = title(a.archived_run, a.provider, a.model, a.batch_size, commit, did)
    since = now()
    base = {"campaign": a.campaign, "arm": a.arm, "repo": a.repo, "vens_ref": a.vens_ref, "vens_commit": commit,
            "provider": a.provider, "model": a.model, "batch_size": a.batch_size, "archived_run": a.archived_run,
            "dispatch_id": did, "replicate": a.replicate, "time": _stamp(since), "replaces": None,
            "conclusion": None}
    # Logged before the call: a run the API never names back still blocks this replicate until resolved.
    _append(a.log, {**base, "run_id": None, "run_attempt": None, "action": PENDING})
    fields = [x for k, v in inputs(a, commit, did).items() for x in ("-f", f"{k}={v}")]
    out = _gh(gh, "workflow", "run", WORKFLOW, "-R", a.repo, "--ref", a.workflow_ref, *fields)
    m = re.search(rf"/{re.escape(a.repo)}/actions/runs/(\d+)", out)
    known = set(index(lines))
    run_id = int(m.group(1)) if m else _find_run(gh, a.repo, want, since, known, sleep)
    run = _rendered(gh, a.repo, run_id, sleep)
    if run.get("display_title") != want or run.get("run_attempt") != 1:
        raise DispatchError(f"run {run_id} is {run.get('display_title')!r} attempt {run.get('run_attempt')}, not the "
                            f"dispatch {want!r}; its pending line stays until resolved")
    line = {**base, "run_id": run_id, "run_attempt": 1, "action": DISPATCH}
    _append(a.log, line)
    return line


def resolve(a, gh, now=utc_now):
    """Closes a pending dispatch: attaches the run it started, its title, its run_attempt 1 and its creation after
    the pending line checked; or, with no_run, records that it started none, no sooner than 15 minutes after it and
    only when the run list, read back to its time, holds no run of its title and no run the log does not name
    created since it, whatever its title: GitHub may create the run minutes after the request, under any title.
    With a run id and no pending dispatch, attaches the late run of the replicate's abandoned dispatch, the same
    checks made, when the replicate was not dispatched again."""
    with locked(a.log):
        lines = load(a.log)
        if a.stray:
            return _stray(a, gh, now, lines)
        k = (a.campaign, a.arm, a.provider, a.model, a.replicate)
        pending = next((l for l in open_pending(lines) if key(l) == k), None)
        if pending is None and not a.no_run:
            pending = abandoned_dispatch(lines, k)
        if pending is None:
            raise Refused(f"replicate {a.replicate} of the {a.arm} has no pending dispatch")
        want = title(pending["archived_run"], pending["provider"], pending["model"], pending["batch_size"],
                     pending["vens_commit"], pending["dispatch_id"])
        since, known = _parse(pending["time"]), set(index(lines))
        if a.no_run:
            if now() - since < SETTLE:
                raise Refused(f"a pending dispatch is abandoned no sooner than {SETTLE} after it, {pending['time']}")
            runs, reached = runs_since(gh, pending["repo"], since)
            if not reached:
                raise Refused(f"the run list did not reach {pending['time']} within GitHub's cap of {LISTING_CAP} runs "
                              f"and {MAX_PAGES} pages: nothing abandoned")
            found = _titled(runs, want, known)
            if found:
                raise Refused(f"runs {found} carry the pending dispatch's title: resolve it with --run-id")
            unlogged = sorted(r["id"] for r in runs
                              if r["id"] not in known and _parse(r["created_at"]) >= since - SKEW)
            if unlogged:
                raise Refused(f"runs {unlogged}, which no line of the log names, were created since the pending "
                              f"dispatch of {pending['time']}: nothing abandoned while one of them may be its run")
            line = {**pending, "time": _stamp(now()), "action": ABANDONED}
        else:
            if a.run_id in known:
                raise Refused(f"run {a.run_id} is already in the log")
            run = _api(gh, f"repos/{pending['repo']}/actions/runs/{a.run_id}")
            if run.get("display_title") != want or run.get("run_attempt") != 1:
                raise Refused(f"run {a.run_id} is {run.get('display_title')!r} attempt {run.get('run_attempt')}, not "
                              f"the pending dispatch {want!r} at attempt 1")
            if not run.get("created_at") or _parse(run["created_at"]) < since - SKEW:
                raise Refused(f"run {a.run_id} was created at {run.get('created_at')}, before the pending dispatch "
                              f"of {pending['time']}")
            line = {**pending, "run_id": a.run_id, "run_attempt": 1, "action": RESOLVED}
        _append(a.log, line)
        return line


def _stray(a, gh, now, lines):
    """Records the late run of the replicate's abandoned dispatch once its replicate was dispatched again: its title
    the abandoned dispatch's, created after it was asked for, and ended."""
    k = (a.campaign, a.arm, a.provider, a.model, a.replicate)
    if a.run_id in index(lines):
        raise Refused(f"run {a.run_id} is already in the log")
    abandoned = [l for l in lines if l["action"] == ABANDONED and key(l) == k]
    if not abandoned:
        raise Refused(f"replicate {a.replicate} of the {a.arm} has no abandoned dispatch")
    run = _api(gh, f"repos/{abandoned[0]['repo']}/actions/runs/{a.run_id}")
    gone = next((l for l in abandoned if l["dispatch_id"] == dispatch_id_of(run)), None)
    if gone is None:
        raise Refused(f"run {a.run_id} is {run.get('display_title')!r}, of no abandoned dispatch of replicate "
                      f"{a.replicate} of the {a.arm}")
    asked = next(l for l in lines if l["action"] == PENDING and l["dispatch_id"] == gone["dispatch_id"])
    want = title(asked["archived_run"], asked["provider"], asked["model"], asked["batch_size"], asked["vens_commit"],
                 asked["dispatch_id"])
    if run.get("display_title") != want:
        raise Refused(f"run {a.run_id} is {run.get('display_title')!r}, not the abandoned dispatch {want!r}")
    if not run.get("created_at") or _parse(run["created_at"]) < _parse(asked["time"]) - SKEW:
        raise Refused(f"run {a.run_id} was created at {run.get('created_at')}, before the abandoned dispatch of "
                      f"{asked['time']}")
    if run.get("status") != "completed":
        raise Refused(f"run {a.run_id} is {run.get('status')}: a stray run is recorded once it has ended")
    if not any(l["action"] == PENDING and key(l) == k for l in lines[lines.index(gone) + 1:]):
        raise Refused(f"replicate {a.replicate} of the {a.arm} was not dispatched again: attach run {a.run_id} with "
                      f"resolve --run-id")
    line = {**asked, "run_id": a.run_id, "run_attempt": run.get("run_attempt"), "time": _stamp(now()),
            "action": STRAY, "replaces": None, "conclusion": run.get("conclusion")}
    _append(a.log, line)
    return line


def rerun(a, gh, now=utc_now, sleep=time.sleep):
    with locked(a.log):
        return _rerun(a, gh, now, sleep)


def _rerun(a, gh, now, sleep):
    lines = load(a.log)
    idx = index(lines)
    if a.run_id not in idx:
        raise Refused(f"run {a.run_id} is not in {a.log}")
    if idx[a.run_id][min(idx[a.run_id])]["action"] == STRAY:
        raise Refused(f"run {a.run_id} is a stray run: never rerun")
    if a.run_id in open_reruns(lines):
        raise Refused(f"run {a.run_id} has a pending rerun: resolve it with resolve-rerun first")
    attempts = idx[a.run_id]
    last, first = max(attempts), attempts[min(attempts)]
    if last + 1 > a.retry_cap:
        raise Refused(f"run {a.run_id} is at attempt {last}, the retry cap is {a.retry_cap} attempts")
    later = sorted(r for _, r in _dispatched(lines, first["campaign"], first["provider"], first["model"])
                   if r > first["replicate"])
    if later:
        raise Refused(f"replicate {later[0]} is already dispatched: replicate {first['replicate']} is not rerun after")
    status = _Status(gh, lines)
    _check_cap(lines, status, a.max_side_by_side)
    _check_late_runs(gh, lines)
    path = f"repos/{first['repo']}/actions/runs/{a.run_id}"
    run = _api(gh, path)
    if run.get("run_attempt") != last:
        raise DispatchError(f"run {a.run_id} is at attempt {run.get('run_attempt')}, the log at {last}")
    if run.get("status") != "completed" or run.get("conclusion") == "success":
        raise Refused(f"run {a.run_id} is {run.get('status')}, {run.get('conclusion')}: nothing to rerun")
    pending = {**first, "run_attempt": last + 1, "time": _stamp(now()), "action": RERUN_PENDING, "replaces": last}
    # Logged before the call: an attempt the API never names back still blocks this run until resolve-rerun.
    _append(a.log, pending)
    _gh(gh, "run", "rerun", str(a.run_id), "--failed", "-R", first["repo"])
    for _ in range(POLLS):
        if _api(gh, path).get("run_attempt") == last + 1:
            break
        sleep(POLL_SECONDS)
    else:
        raise DispatchError(f"run {a.run_id} did not reach attempt {last + 1}; its pending rerun stays until "
                            f"resolve-rerun")
    line = {**pending, "action": RERUN}
    _append(a.log, line)
    return line


def resolve_rerun(a, gh, now=utc_now):
    """Closes a pending rerun without asking for another: logs the attempt it asked for once the API shows the run at
    it, or, with no_rerun, records that it started none, no sooner than 15 minutes after it and only while the run
    is still at the attempt before."""
    with locked(a.log):
        lines = load(a.log)
        pending = open_reruns(lines).get(a.run_id)
        if pending is None:
            raise Refused(f"run {a.run_id} has no pending rerun")
        at = _api(gh, f"repos/{pending['repo']}/actions/runs/{a.run_id}").get("run_attempt")
        if a.no_rerun:
            if now() - _parse(pending["time"]) < SETTLE:
                raise Refused(f"a pending rerun is abandoned no sooner than {SETTLE} after it, {pending['time']}")
            if at != pending["replaces"]:
                raise Refused(f"run {a.run_id} is at attempt {at}: the pending rerun of attempt "
                              f"{pending['run_attempt']} is not abandoned")
            line = {**pending, "time": _stamp(now()), "action": RERUN_ABANDONED}
        else:
            if at != pending["run_attempt"]:
                raise Refused(f"run {a.run_id} is at attempt {at}, not the {pending['run_attempt']} its pending rerun "
                              f"asked for")
            line = {**pending, "action": RERUN}
        _append(a.log, line)
        return line


def positive(text):
    n = int(text)
    if n < 1:
        raise argparse.ArgumentTypeError("must be a positive number")
    return n


def _replicate_args(p):
    p.add_argument("--log", required=True)
    p.add_argument("--campaign", required=True)
    p.add_argument("--arm", required=True, choices=ARMS)
    p.add_argument("--provider", required=True, choices=("openai", "anthropic"))
    p.add_argument("--model", required=True)
    p.add_argument("--replicate", required=True, type=positive)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m chain.dispatch")
    ap.add_argument("--gh", default=os.environ.get("GH", "gh"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("dispatch")
    _replicate_args(d)
    d.add_argument("--vens-ref", required=True)
    d.add_argument("--max-side-by-side", required=True, type=positive)
    d.add_argument("--batch-size", type=positive, default=1)
    d.add_argument("--archived-run", default="2026-09-23")
    d.add_argument("--repo", default="venslabs/vens-demo")
    d.add_argument("--workflow-ref", default="main")
    d.add_argument("--one-arm", action="store_true")
    r = sub.add_parser("rerun")
    r.add_argument("--log", required=True)
    r.add_argument("--run-id", required=True, type=int)
    r.add_argument("--retry-cap", required=True, type=positive)
    r.add_argument("--max-side-by-side", required=True, type=positive)
    s = sub.add_parser("resolve")
    _replicate_args(s)
    how = s.add_mutually_exclusive_group(required=True)
    how.add_argument("--run-id", type=int)
    how.add_argument("--no-run", action="store_true")
    s.add_argument("--stray", action="store_true")
    rr = sub.add_parser("resolve-rerun")
    rr.add_argument("--log", required=True)
    rr.add_argument("--run-id", required=True, type=int)
    rr.add_argument("--no-rerun", action="store_true")
    c = sub.add_parser("check-late")
    c.add_argument("--log", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "resolve" and a.stray and a.run_id is None:
        ap.error("--stray needs --run-id")
    commands = {"dispatch": dispatch, "rerun": rerun, "resolve": resolve, "resolve-rerun": resolve_rerun,
                "check-late": check_late}
    try:
        line = commands[a.cmd](a, a.gh)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    except DispatchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps(line))
    return 0


if __name__ == "__main__":
    sys.exit(main())
