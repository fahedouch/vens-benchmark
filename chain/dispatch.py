"""The dispatch script of the demo-scan campaigns that compare vens's two arms, and the reader of its log.

Each baseline.yml run of a campaign scores one replicate of one arm, so every run names its artefacts r1: the log
maps each run id, and each of its run attempts, to the arm, model and campaign replicate it measures. Per model,
replicate r of the before and replicate r of the after are dispatched together and run side by side; the next pair
starts once both runs have ended, and a run is rerun only before it.

dispatch-log.jsonl holds one JSON object per line, appended, never rewritten:

    {"campaign", "arm", "repo", "vens_ref", "vens_commit", "provider", "model", "batch_size", "archived_run",
     "replicate", "run_id", "run_attempt", "time", "action", "replaces"}

action is one of:
    pending          written before `gh workflow run`, run_id and run_attempt null: a run may exist no line names
    dispatch         the pending dispatch's run, read back from the API, run_attempt 1
    resolved         the pending dispatch's run attached by hand: its title, its run_attempt 1 and its creation after
                     the pending line checked
    abandoned        a pending dispatch that started no run: at least 15 minutes old, and the run list, read back to
                     its time within GitHub's cap, holds no run of its title and no run the log does not name created
                     within two minutes of it
    rerun-pending    written before `gh run rerun --failed`, run_attempt the attempt it asks for
    rerun-failed     that attempt, read back from the API, replacing the attempt before it
    rerun-abandoned  a pending rerun that started no attempt: at least 15 minutes old, the run still at the attempt
                     before
The lines of one replicate, (campaign, arm, provider, model, replicate), agree on every field but run_id,
run_attempt, time, action and replaces. time is UTC. Every command holds an exclusive lock on LOG.lock while it reads
the log, checks, calls gh and writes, so two commands never act on the same state. This script writes the log;
whoever runs the campaign owns it and commits it with the campaign's archive.

    python3 -m chain.dispatch dispatch --log LOG --campaign NAME --arm after --vens-ref SHA --provider openai \
        --model gpt-5.4-mini-2026-03-17 --replicate 1 --max-side-by-side 2
    python3 -m chain.dispatch rerun --log LOG --run-id ID --retry-cap 4 --max-side-by-side 2
    python3 -m chain.dispatch resolve --log LOG --campaign NAME --arm after --provider openai \
        --model gpt-5.4-mini-2026-03-17 --replicate 1 (--run-id ID | --no-run)
    python3 -m chain.dispatch resolve-rerun --log LOG --run-id ID [--no-rerun]

gh is the executable --gh names, else $GH, else the one on PATH.
"""
import argparse
import contextlib
import datetime
import fcntl
import json
import os
import re
import subprocess
import sys
import time

from chain.errors import Refused

FIELDS = ("campaign", "arm", "repo", "vens_ref", "vens_commit", "provider", "model", "batch_size", "archived_run",
          "replicate", "run_id", "run_attempt", "time", "action", "replaces")
KEY = ("campaign", "arm", "provider", "model", "replicate")
SAME = ("repo", "vens_ref", "vens_commit", "batch_size", "archived_run")
PENDING, DISPATCH, RESOLVED, ABANDONED = "pending", "dispatch", "resolved", "abandoned"
RERUN_PENDING, RERUN, RERUN_ABANDONED = "rerun-pending", "rerun-failed", "rerun-abandoned"
STARTS = (DISPATCH, RESOLVED)
ARMS = ("before", "after")
WORKFLOW = "baseline.yml"
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
    last one, on its run's fields, and closed by that attempt or abandoned; each run id one replicate's and each
    (run id, run attempt) logged once."""
    if not os.path.exists(path):
        return []
    lines, pending, started, attempts, owner, reruns = [], {}, {}, {}, {}, {}
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
            elif action in STARTS + (ABANDONED,):
                if k not in pending:
                    raise DispatchError(f"{where}: a {action} line with no pending dispatch before it")
                changed = [f for f in SAME if line[f] != pending[k][f]]
                if changed:
                    raise DispatchError(f"{where}: a {action} line changes {changed} of its pending dispatch")
                del pending[k]
                if action != ABANDONED:
                    _start(line, where, owner, attempts)
                    started[k] = line
            elif action in (RERUN_PENDING, RERUN, RERUN_ABANDONED):
                first = owner.get(line["run_id"])
                if first is None:
                    raise DispatchError(f"{where}: a {action} line for run {line['run_id']}, which no dispatch names")
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


def _start(line, where, owner, attempts):
    if line["run_attempt"] != 1 or line["replaces"] is not None or not isinstance(line["run_id"], int):
        raise DispatchError(f"{where}: a run starts at attempt 1 with a run id and replaces nothing")
    if line["run_id"] in owner:
        raise DispatchError(f"{where}: run {line['run_id']} is already another replicate's")
    owner[line["run_id"]] = line
    attempts[line["run_id"]] = 1


def index(lines):
    """{run id: {run attempt: line}}, from the lines that name a run's attempt."""
    out = {}
    for line in lines:
        if line["action"] in STARTS + (RERUN,):
            out[line["run_id"]] = {**out.get(line["run_id"], {}), line["run_attempt"]: line}
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


def title(archived_run, provider, model, batch, commit):
    """baseline.yml's run-name for a one-replicate run pinned to a commit."""
    return f"baseline · {archived_run} · {provider}/{model} · batch {batch} · x1 · vens {commit}"


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


def _dispatched(lines, campaign, provider, model):
    """The replicates of one campaign and model a run or an open pending dispatch holds: {(arm, replicate)}."""
    same = lambda l: (l["campaign"], l["provider"], l["model"]) == (campaign, provider, model)
    return ({(l["arm"], l["replicate"]) for l in lines if same(l) and l["action"] in STARTS}
            | {(l["arm"], l["replicate"]) for l in open_pending(lines) if same(l)})


def _check_pairing(lines, a, status):
    """Replicate r of either arm goes once both arms' earlier replicates have run and ended, no rerun of theirs
    pending, and never after a later replicate."""
    if a.replicate < 1:
        raise Refused("replicates count from 1")
    later = sorted(r for _, r in _dispatched(lines, a.campaign, a.provider, a.model) if r > a.replicate)
    if later:
        raise Refused(f"replicate {later[0]} of {a.campaign} is already dispatched")
    mine = [l for l in lines if (l["campaign"], l["provider"], l["model"]) == (a.campaign, a.provider, a.model)]
    starts = {(l["arm"], l["replicate"]): l["run_id"] for l in mine if l["action"] in STARTS}
    earlier = [(arm, r) for r in range(1, a.replicate) for arm in ARMS]
    for arm, r in earlier:
        if (arm, r) not in starts:
            raise Refused(f"replicate {r} of the {arm} is not dispatched: the pair goes before replicate "
                          f"{a.replicate}")
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
    _check_pairing(lines, a, status)
    _check_cap(lines, status, a.max_side_by_side)
    commit = _api(gh, f"repos/venslabs/vens/commits/{a.vens_ref}")["sha"]
    want = title(a.archived_run, a.provider, a.model, a.batch_size, commit)
    since = now()
    base = {"campaign": a.campaign, "arm": a.arm, "repo": a.repo, "vens_ref": a.vens_ref, "vens_commit": commit,
            "provider": a.provider, "model": a.model, "batch_size": a.batch_size, "archived_run": a.archived_run,
            "replicate": a.replicate, "time": _stamp(since), "replaces": None}
    # Logged before the call: a run the API never names back still blocks this replicate until resolved.
    _append(a.log, {**base, "run_id": None, "run_attempt": None, "action": PENDING})
    out = _gh(gh, "workflow", "run", WORKFLOW, "-R", a.repo, "--ref", a.workflow_ref,
              "-f", f"archived-run={a.archived_run}", "-f", f"provider={a.provider}", "-f", f"model={a.model}",
              "-f", f"batch-size={a.batch_size}", "-f", "replicates=1", "-f", f"vens-ref={commit}")
    m = re.search(rf"/{re.escape(a.repo)}/actions/runs/(\d+)", out)
    known = set(index(lines))
    run_id = int(m.group(1)) if m else _find_run(gh, a.repo, want, since, known, sleep)
    run = _api(gh, f"repos/{a.repo}/actions/runs/{run_id}")
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
    created since it, whatever its title: GitHub may create the run minutes after the request, under any title."""
    with locked(a.log):
        lines = load(a.log)
        k = (a.campaign, a.arm, a.provider, a.model, a.replicate)
        pending = next((l for l in open_pending(lines) if key(l) == k), None)
        if pending is None:
            raise Refused(f"replicate {a.replicate} of the {a.arm} has no pending dispatch")
        want = title(pending["archived_run"], pending["provider"], pending["model"], pending["batch_size"],
                     pending["vens_commit"])
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


def rerun(a, gh, now=utc_now, sleep=time.sleep):
    with locked(a.log):
        return _rerun(a, gh, now, sleep)


def _rerun(a, gh, now, sleep):
    lines = load(a.log)
    idx = index(lines)
    if a.run_id not in idx:
        raise Refused(f"run {a.run_id} is not in {a.log}")
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
    rr = sub.add_parser("resolve-rerun")
    rr.add_argument("--log", required=True)
    rr.add_argument("--run-id", required=True, type=int)
    rr.add_argument("--no-rerun", action="store_true")
    a = ap.parse_args(argv)
    commands = {"dispatch": dispatch, "rerun": rerun, "resolve": resolve, "resolve-rerun": resolve_rerun}
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
