"""The dispatch script of step 5's demo-scan campaigns and the reader of its log (venslabs/vens#310 step 4, Q8).

Each baseline.yml run of a campaign scores one replicate of one arm, so every run names its artefacts r1: the log
maps each run id, and each of its run attempts, to the arm, model and campaign replicate it measures.

dispatch-log.jsonl holds one JSON object per dispatch or rerun:

    {"campaign", "arm", "repo", "vens_ref", "vens_commit", "provider", "model", "batch_size", "archived_run",
     "replicate", "run_id", "run_attempt", "time", "action": "dispatch" | "rerun-failed", "replaces"}

`replaces` is the run attempt a rerun replaces, null on a dispatch; `time` is UTC. This script writes it; whoever runs
the campaign owns it and commits it with the campaign's archive.

    python3 -m chain.dispatch dispatch --log LOG --campaign NAME --arm after --vens-ref SHA --provider openai \
        --model gpt-5.4-mini-2026-03-17 --replicate 1 [--max-side-by-side N]
    python3 -m chain.dispatch rerun --log LOG --run-id ID --retry-cap 4

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
DISPATCH, RERUN = "dispatch", "rerun-failed"
WORKFLOW = "baseline.yml"
POLLS, POLL_SECONDS = 20, 3


class DispatchError(Exception):
    pass


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def _stamp(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path):
    """The log's lines, checked: every field present, the actions known, each rerun after its run's dispatch and
    replacing the attempt before it, each (run id, run attempt) logged once."""
    if not os.path.exists(path):
        return []
    lines, seen = [], {}
    with open(path, encoding="utf-8") as fh:
        for n, text in enumerate(fh, 1):
            if not text.strip():
                continue
            line = json.loads(text)
            missing = [f for f in FIELDS if f not in line]
            if missing:
                raise DispatchError(f"{path}:{n}: missing {missing}")
            key = (line["run_id"], line["run_attempt"])
            if key in seen:
                raise DispatchError(f"{path}:{n}: run {key[0]} attempt {key[1]} logged twice")
            if line["action"] == DISPATCH and (line["run_attempt"] != 1 or line["replaces"] is not None):
                raise DispatchError(f"{path}:{n}: a dispatch is attempt 1 and replaces nothing")
            if line["action"] == RERUN and (line["run_id"], line["run_attempt"] - 1) not in seen:
                raise DispatchError(f"{path}:{n}: a rerun of run {line['run_id']} without its attempt before")
            if line["action"] == RERUN and line["replaces"] != line["run_attempt"] - 1:
                raise DispatchError(f"{path}:{n}: a rerun replaces the attempt before it")
            if line["action"] not in (DISPATCH, RERUN):
                raise DispatchError(f"{path}:{n}: unknown action {line['action']!r}")
            seen[key] = n
            lines.append(line)
    return lines


def index(lines):
    """{run id: {run attempt: line}}."""
    out = {}
    for line in lines:
        out[line["run_id"]] = {**out.get(line["run_id"], {}), line["run_attempt"]: line}
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


def _find_run(gh, repo, want_title, since, known, sleep):
    for _ in range(POLLS):
        runs = json.loads(_gh(gh, "run", "list", "-R", repo, "--workflow", WORKFLOW, "--event", "workflow_dispatch",
                              "--json", "databaseId,createdAt,displayTitle", "--limit", "30"))
        found = [r["databaseId"] for r in runs if r["displayTitle"] == want_title and r["databaseId"] not in known
                 and datetime.datetime.fromisoformat(r["createdAt"].replace("Z", "+00:00"))
                 >= since - datetime.timedelta(minutes=2)]
        if len(found) > 1:
            raise DispatchError(f"{len(found)} new runs titled {want_title!r}: {sorted(found)}; log one by hand")
        if found:
            return found[0]
        sleep(POLL_SECONDS)
    raise DispatchError(f"no new run titled {want_title!r} after {POLLS} polls")


def dispatch(a, gh, now=utc_now, sleep=time.sleep):
    lines = load(a.log)
    same = [l for l in lines if l["action"] == DISPATCH and (l["campaign"], l["arm"], l["provider"], l["model"],
                                                               l["replicate"]) == (a.campaign, a.arm, a.provider,
                                                                                   a.model, a.replicate)]
    if same:
        raise Refused(f"replicate {a.replicate} of {a.arm} is already run {same[0]['run_id']}; rerun it instead")
    if a.max_side_by_side:
        open_runs = [l["run_id"] for l in lines if l["action"] == DISPATCH and l["campaign"] == a.campaign
                     and _api(gh, f"repos/{l['repo']}/actions/runs/{l['run_id']}")["status"] != "completed"]
        if len(open_runs) >= a.max_side_by_side:
            raise Refused(f"{len(open_runs)} runs of {a.campaign} not completed: {open_runs}")
    commit = _api(gh, f"repos/venslabs/vens/commits/{a.vens_ref}")["sha"]
    want = title(a.archived_run, a.provider, a.model, a.batch_size, commit)
    since = now()
    out = _gh(gh, "workflow", "run", WORKFLOW, "-R", a.repo, "--ref", a.workflow_ref,
              "-f", f"archived-run={a.archived_run}", "-f", f"provider={a.provider}", "-f", f"model={a.model}",
              "-f", f"batch-size={a.batch_size}", "-f", "replicates=1", "-f", f"vens-ref={commit}")
    m = re.search(rf"/{re.escape(a.repo)}/actions/runs/(\d+)", out)
    known = {l["run_id"] for l in lines}
    run_id = int(m.group(1)) if m else _find_run(gh, a.repo, want, since, known, sleep)
    run = _api(gh, f"repos/{a.repo}/actions/runs/{run_id}")
    if run.get("display_title") != want or run.get("run_attempt") != 1:
        raise DispatchError(f"run {run_id} is {run.get('display_title')!r} attempt {run.get('run_attempt')}, not the "
                            f"dispatch {want!r}")
    line = {"campaign": a.campaign, "arm": a.arm, "repo": a.repo, "vens_ref": a.vens_ref, "vens_commit": commit,
            "provider": a.provider, "model": a.model, "batch_size": a.batch_size, "archived_run": a.archived_run,
            "replicate": a.replicate, "run_id": run_id, "run_attempt": 1, "time": _stamp(since),
            "action": DISPATCH, "replaces": None}
    _append(a.log, line)
    return line


def rerun(a, gh, now=utc_now, sleep=time.sleep):
    idx = index(load(a.log))
    if a.run_id not in idx:
        raise Refused(f"run {a.run_id} is not in {a.log}")
    attempts = idx[a.run_id]
    last, first = max(attempts), attempts[min(attempts)]
    if last + 1 > a.retry_cap:
        raise Refused(f"run {a.run_id} is at attempt {last}, the retry cap is {a.retry_cap} attempts")
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


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m chain.dispatch")
    ap.add_argument("--gh", default=os.environ.get("GH", "gh"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("dispatch")
    d.add_argument("--log", required=True)
    d.add_argument("--campaign", required=True)
    d.add_argument("--arm", required=True, choices=("before", "after"))
    d.add_argument("--vens-ref", required=True)
    d.add_argument("--provider", required=True, choices=("openai", "anthropic"))
    d.add_argument("--model", required=True)
    d.add_argument("--replicate", required=True, type=int)
    d.add_argument("--batch-size", type=int, default=1)
    d.add_argument("--archived-run", default="2026-09-23")
    d.add_argument("--repo", default="venslabs/vens-demo")
    d.add_argument("--workflow-ref", default="main")
    d.add_argument("--max-side-by-side", type=int, default=0)
    r = sub.add_parser("rerun")
    r.add_argument("--log", required=True)
    r.add_argument("--run-id", required=True, type=int)
    r.add_argument("--retry-cap", required=True, type=int)
    a = ap.parse_args(argv)
    try:
        line = dispatch(a, a.gh) if a.cmd == "dispatch" else rerun(a, a.gh)
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
