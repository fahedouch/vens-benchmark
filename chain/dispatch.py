"""The dispatch script of the demo-scan campaigns that compare vens's two arms, and the reader of its log.

Each baseline.yml run of a campaign scores one replicate of one arm, so every run names its artefacts r1: the log
maps each run id, and each of its run attempts, to the arm, model and campaign replicate it measures. Per model,
replicate r of the before and replicate r of the after are dispatched together and run side by side; the next pair
starts once both runs have ended, and a run is rerun only before it.

dispatch-log.jsonl holds one JSON object per line, appended, never rewritten:

    {"campaign", "arm", "repo", "vens_ref", "vens_commit", "provider", "model", "batch_size", "archived_run",
     "replicate", "run_id", "run_attempt", "time", "action", "replaces"}

action is one of:
    pending       written before `gh workflow run`, run_id and run_attempt null: a run may exist that no line names
    dispatch      the pending dispatch's run, read back from the API, run_attempt 1
    resolved      the pending dispatch's run attached by hand, its title and run_attempt 1 checked
    abandoned     a pending dispatch that started no run, checked against the run list
    rerun-failed  `gh run rerun --failed`, run_attempt the new attempt, replaces the attempt before it
The lines of one replicate, (campaign, arm, provider, model, replicate), agree on every field but run_id,
run_attempt, time, action and replaces. time is UTC. This script writes the log; whoever runs the campaign owns it and
commits it with the campaign's archive.

    python3 -m chain.dispatch dispatch --log LOG --campaign NAME --arm after --vens-ref SHA --provider openai \
        --model gpt-5.4-mini-2026-03-17 --replicate 1 --max-side-by-side 2
    python3 -m chain.dispatch rerun --log LOG --run-id ID --retry-cap 4 --max-side-by-side 2
    python3 -m chain.dispatch resolve --log LOG --campaign NAME --arm after --provider openai \
        --model gpt-5.4-mini-2026-03-17 --replicate 1 (--run-id ID | --no-run)

gh is the executable --gh names, else $GH, else the one on PATH.
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time

from chain.attempt import Refused

FIELDS = ("campaign", "arm", "repo", "vens_ref", "vens_commit", "provider", "model", "batch_size", "archived_run",
          "replicate", "run_id", "run_attempt", "time", "action", "replaces")
KEY = ("campaign", "arm", "provider", "model", "replicate")
SAME = ("repo", "vens_ref", "vens_commit", "batch_size", "archived_run")
PENDING, DISPATCH, RESOLVED, ABANDONED, RERUN = "pending", "dispatch", "resolved", "abandoned", "rerun-failed"
STARTS = (DISPATCH, RESOLVED)
ARMS = ("before", "after")
WORKFLOW = "baseline.yml"
POLLS, POLL_SECONDS = 20, 3


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


def load(path):
    """The log's lines, checked: every field present and every action known; a dispatch, resolved or abandoned line
    closing its replicate's pending line, on the same fields; a rerun following its run's attempt before, on its
    run's fields; each run id one replicate's and each (run id, run attempt) logged once."""
    if not os.path.exists(path):
        return []
    lines, pending, started, attempts, owner = [], {}, {}, set(), {}
    with open(path, encoding="utf-8") as fh:
        for n, text in enumerate(fh, 1):
            if not text.strip():
                continue
            line = json.loads(text)
            where = f"{path}:{n}"
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
            elif action == RERUN:
                first = owner.get(line["run_id"])
                if first is None or (line["run_id"], line["run_attempt"] - 1) not in attempts:
                    raise DispatchError(f"{where}: a rerun of run {line['run_id']} without its attempt before")
                if line["replaces"] != line["run_attempt"] - 1:
                    raise DispatchError(f"{where}: a rerun replaces the attempt before it")
                changed = [f for f in KEY + SAME if line[f] != first[f]]
                if changed:
                    raise DispatchError(f"{where}: a rerun changes {changed} of run {line['run_id']}")
                _attempt(line, where, attempts)
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
    _attempt(line, where, attempts)


def _attempt(line, where, attempts):
    pair = (line["run_id"], line["run_attempt"])
    if pair in attempts:
        raise DispatchError(f"{where}: run {pair[0]} attempt {pair[1]} logged twice")
    attempts.add(pair)


def index(lines):
    """{run id: {run attempt: line}}, from the lines that name a run."""
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


def _new_runs(gh, repo, want_title, since, known):
    runs = json.loads(_gh(gh, "run", "list", "-R", repo, "--workflow", WORKFLOW, "--event", "workflow_dispatch",
                          "--json", "databaseId,createdAt,displayTitle", "--limit", "50"))
    return sorted(r["databaseId"] for r in runs if r["displayTitle"] == want_title and r["databaseId"] not in known
                  and _parse(r["createdAt"]) >= since - datetime.timedelta(minutes=2))


def _find_run(gh, repo, want_title, since, known, sleep):
    for _ in range(POLLS):
        found = _new_runs(gh, repo, want_title, since, known)
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
    running = [l["run_id"] for l in lines if l["action"] in STARTS and status(l["run_id"]) != "completed"]
    waiting = open_pending(lines)
    if len(running) + len(waiting) >= cap:
        raise Refused(f"{len(running)} runs not ended {running} and {len(waiting)} pending dispatches, at the cap of "
                      f"{cap} side by side")


def _dispatched(lines, campaign, provider, model):
    """The replicates of one campaign and model a run or an open pending dispatch holds: {(arm, replicate)}."""
    same = lambda l: (l["campaign"], l["provider"], l["model"]) == (campaign, provider, model)
    return ({(l["arm"], l["replicate"]) for l in lines if same(l) and l["action"] in STARTS}
            | {(l["arm"], l["replicate"]) for l in open_pending(lines) if same(l)})


def _check_pairing(lines, a, status):
    """Replicate r of either arm goes once both arms' earlier replicates have run and ended, and never after a
    later replicate."""
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
    for arm, r in earlier:
        if status(starts[(arm, r)]) != "completed":
            raise Refused(f"replicate {r} of the {arm}, run {starts[(arm, r)]}, has not ended")


def dispatch(a, gh, now=utc_now, sleep=time.sleep):
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
    """Closes a pending dispatch: attaches the run it started, its title and run_attempt 1 checked, or with no_run
    records that it started none, once the run list holds no run of its title since it was written."""
    lines = load(a.log)
    k = (a.campaign, a.arm, a.provider, a.model, a.replicate)
    pending = next((l for l in open_pending(lines) if key(l) == k), None)
    if pending is None:
        raise Refused(f"replicate {a.replicate} of the {a.arm} has no pending dispatch")
    want = title(pending["archived_run"], pending["provider"], pending["model"], pending["batch_size"],
                 pending["vens_commit"])
    known = set(index(lines))
    if a.no_run:
        found = _new_runs(gh, pending["repo"], want, _parse(pending["time"]), known)
        if found:
            raise Refused(f"runs {found} carry the pending dispatch's title: resolve it with --run-id")
        line = {**pending, "time": _stamp(now()), "action": ABANDONED}
    else:
        if a.run_id in known:
            raise Refused(f"run {a.run_id} is already in the log")
        run = _api(gh, f"repos/{pending['repo']}/actions/runs/{a.run_id}")
        if run.get("display_title") != want or run.get("run_attempt") != 1:
            raise Refused(f"run {a.run_id} is {run.get('display_title')!r} attempt {run.get('run_attempt')}, not "
                          f"the pending dispatch {want!r} at attempt 1")
        line = {**pending, "run_id": a.run_id, "run_attempt": 1, "action": RESOLVED}
    _append(a.log, line)
    return line


def rerun(a, gh, now=utc_now, sleep=time.sleep):
    lines = load(a.log)
    idx = index(lines)
    if a.run_id not in idx:
        raise Refused(f"run {a.run_id} is not in {a.log}")
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
    at = now()
    _gh(gh, "run", "rerun", str(a.run_id), "--failed", "-R", first["repo"])
    for _ in range(POLLS):
        if _api(gh, path).get("run_attempt") == last + 1:
            break
        sleep(POLL_SECONDS)
    else:
        raise DispatchError(f"run {a.run_id} did not reach attempt {last + 1}")
    line = {**first, "run_attempt": last + 1, "time": _stamp(at), "action": RERUN, "replaces": last}
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
    a = ap.parse_args(argv)
    try:
        line = {"dispatch": dispatch, "rerun": rerun, "resolve": resolve}[a.cmd](a, a.gh)
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
