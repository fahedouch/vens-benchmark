"""The scenario runner: each scenario of the frozen corpus scored by vens's two arms, the before (main) and the after
(310-step3), on the models given, replicate by replicate, every attempt recorded, failed ones included
(venslabs/vens#310 step 4).

    python3 ctx_runner.py --campaign NAME --out DIR \\
        --before BIN --before-commit SHA --after BIN --after-commit SHA \\
        --model PROVIDER/MODEL [--model ...] [--undated MODEL ...] \\
        --replicates N --retry-cap N --timeout SECONDS --parallel N [--scenario ID ...] [--root DIR]

A unit is one scenario, model and replicate: the before's run, then the after's, back to back. The units go
replicate by replicate, model by model, scenario by scenario, --parallel of them side by side. Each run is `vens
generate` at batch 1 with --attest and a --debug-dir of its own, with baseline.yml's flags and each provider's default
sampling: no --llm-temperature and no --llm-seed. An attempt that exits non-zero, or that the runner kills at
--timeout seconds, is followed by another, up to --retry-cap attempts in all; the last one, failed, records the
retry cap reached.

The corpus is the frozen one: scenarios/ under --root (the repository by default) must hold freeze-scenarios.json's
files and no other, and the freeze must be the one the corpus was frozen with (chain/campaign.py, FROZEN); both are
copied into DIR and vens runs on the copy. --before and --before-commit, --after and --after-commit give each arm's
binary and the full commit it was built from; campaign.json and every attempt record name the commit and the
binary's sha256, and the runner stops when a binary changes under it.

A model is given by its dated id where its provider dates its snapshots (gpt-5.4-mini-2026-03-17,
claude-haiku-4-5-20251001); --undated names a model its provider gives no dated id (claude-sonnet-4-6), recorded as
such. Each arm runs on its own key per provider, from OPENAI_API_KEY_BEFORE, OPENAI_API_KEY_AFTER,
ANTHROPIC_API_KEY_BEFORE and ANTHROPIC_API_KEY_AFTER, given to vens as OPENAI_API_KEY or ANTHROPIC_API_KEY and cut
out of its log; a key missing, or one key for both arms, stops the runner before any call, and a key found in an
attempt's files after it stops the campaign. Only PATH, HOME, TZ=UTC, the model and the key reach vens. mock/mock is
vens's own mock LLM, no key and nothing paid; VENS_MOCK_LLM_FAIL, VENS_MOCK_LLM_SKIP and VENS_MOCK_LLM_CANNOT_TELL
reach it from the runner's environment and are recorded.

DIR must not exist; it becomes the campaign's archive (chain/campaign.py), which `python3 -m chain.read DIR` reads.
Exit 0 when every run has a complete attempt, 3 when some reached the retry cap without one, 1 when the runner
refused or stopped on an error, 130 or 143 when SIGINT or SIGTERM stopped it; a stop kills the attempts running and
records them interrupted.
"""
import argparse
import concurrent.futures as cf
import os
import re
import shutil
import signal
import sys
import threading
from dataclasses import dataclass

from chain import campaign, runvens, venslog
from chain.errors import Refused
from chain.javarun import own_commit

ROOT = os.path.dirname(os.path.abspath(__file__))
ARMS = campaign.ARMS
# provider: (vens's model variable, vens's key variable, the suffix of a dated id)
PROVIDERS = {
    "openai": ("OPENAI_MODEL", "OPENAI_API_KEY", re.compile(r"-\d{4}-\d{2}-\d{2}$")),
    "anthropic": ("ANTHROPIC_MODEL", "ANTHROPIC_API_KEY", re.compile(r"-\d{8}$")),
    "mock": (None, None, None),
}
MOCK_ENV = ("VENS_MOCK_LLM_FAIL", "VENS_MOCK_LLM_SKIP", "VENS_MOCK_LLM_CANNOT_TELL")
COMMIT = re.compile(r"[0-9a-f]{40}")
NAME = re.compile(r"[A-Za-z0-9._-]+")
COMPLETE, CAP_REACHED = "complete", "retry_cap_reached"
EXIT_CAP_REACHED = 3


class RunnerError(Exception):
    """What stops a campaign once it has started: vens that does not start, a binary that changed, a log not
    written whole, a key found in an attempt's files."""


class Terminated(BaseException):
    """SIGTERM, raised in the main thread so that the runner stops as on SIGINT."""


def key_variable(provider, arm):
    return f"{PROVIDERS[provider][1]}_{arm.upper()}"


def parse_models(given, undated):
    """[{provider, model, dated}]: each model its provider's dated id, unless --undated names it; Refused
    otherwise."""
    out = []
    for text in given:
        provider, sep, model = text.partition("/")
        if not sep or provider not in PROVIDERS or not NAME.fullmatch(model):
            raise Refused(f"--model {text}: give PROVIDER/MODEL, the provider one of {', '.join(PROVIDERS)}")
        suffix = PROVIDERS[provider][2]
        if suffix is None and model != "mock":
            raise Refused(f"--model {text}: vens's mock is mock/mock")
        if suffix is not None and not suffix.search(model) and model not in undated:
            raise Refused(f"--model {text}: not a dated id; give the dated snapshot, or --undated {model} when "
                          f"{provider} gives this model none")
        out.append({"provider": provider, "model": model,
                    "dated": None if suffix is None else bool(suffix.search(model))})
    if len({(m["provider"], m["model"]) for m in out}) < len(out):
        raise Refused("a model given twice")
    stray = sorted(set(undated) - {m["model"] for m in out})
    if stray:
        raise Refused(f"--undated {', '.join(stray)}: no --model names it")
    return out


def parse_arms(a):
    """{arm: {binary, vens_sha, binary_sha256, signature}}; Refused when a commit is not a full one, a binary is not
    an executable file, or the two arms share a binary or a commit."""
    out = {}
    for arm in ARMS:
        binary, commit = getattr(a, arm), getattr(a, f"{arm}_commit")
        if not COMMIT.fullmatch(commit):
            raise Refused(f"--{arm}-commit {commit}: give the full commit the binary was built from")
        if not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
            raise Refused(f"--{arm} {binary}: not an executable file")
        out[arm] = {"binary": os.path.abspath(binary), "vens_sha": commit, "binary_sha256": runvens.sha256(binary),
                    "signature": _signature(binary)}
    for field, what in (("binary_sha256", "binary"), ("vens_sha", "commit")):
        if out["before"][field] == out["after"][field]:
            raise Refused(f"the before and the after are one {what}")
    return out


def _signature(path):
    st = os.stat(path)
    return st.st_ino, st.st_size, st.st_mtime_ns


def parse_keys(models, environ):
    """{(provider, arm): (variable, key)} for each provider that takes a key; Refused, before any call, when one is
    missing or the two arms share one."""
    out = {}
    for provider in sorted({m["provider"] for m in models if PROVIDERS[m["provider"]][1]}):
        pair = {arm: (key_variable(provider, arm), environ.get(key_variable(provider, arm), "")) for arm in ARMS}
        for variable, key in pair.values():
            if not key:
                raise Refused(f"{variable} is not set: each arm runs on its own key")
        if pair["before"][1] == pair["after"][1]:
            raise Refused(f"{pair['before'][0]} and {pair['after'][0]} hold one key: each arm runs on its own, so "
                          f"that its spend shows apart")
        out.update({(provider, arm): pair[arm] for arm in ARMS})
    return out


def inputs(scenario):
    """The scenario's config and report, relative to the campaign folder."""
    corpus = os.path.join(campaign.SCENARIOS, scenario)
    return os.path.join(corpus, "config.yaml"), os.path.join(corpus, "report.json")


def command(provider, scenario, folder):
    """vens generate's arguments for one attempt, its paths relative to the campaign folder."""
    config, report = inputs(scenario)
    return ["generate", "--config-file", config, "--llm", provider, "--llm-batch-size", "1", "--input-format",
            "trivy", "--sbom-serial-number", runvens.SERIAL, "--sbom-version", "1", "--attest", "--debug-dir",
            os.path.join(folder, "calls"), report, os.path.join(folder, "vex.cdx.json")]


@dataclass(frozen=True)
class Context:
    root: str
    out: str
    doc: dict
    arms: dict
    keys: dict
    mock_env: dict
    base_env: dict
    stop: threading.Event
    lock: threading.Lock


def prepare(a, environ):
    """Every check the runner makes before it writes anything or calls a model."""
    if os.path.exists(a.out):
        raise Refused(f"{a.out} exists: a campaign is written into a folder of its own")
    if not NAME.fullmatch(a.campaign):
        raise Refused(f"--campaign {a.campaign}: letters, digits, '.', '_' and '-' only")
    models = parse_models(a.model, a.undated)
    arms = parse_arms(a)
    keys = parse_keys(models, environ)
    freeze_sha, ids = campaign.check_corpus(a.root)
    unknown = sorted(set(a.scenario) - set(ids))
    if unknown:
        raise Refused(f"--scenario {', '.join(unknown)}: not in the corpus")
    mock = any(m["provider"] == "mock" for m in models)
    mock_env = {k: environ[k] for k in MOCK_ENV if mock and environ.get(k)}
    placeholder = os.path.join("<provider>", "<model>", "r<replicate>", "<scenario>", "<arm>-a<attempt>")
    doc = {
        "record": 1, "runner": "scenarios", "campaign": a.campaign, "vens_benchmark": own_commit(),
        "started_at": None, "ended_at": None, "stopped": None,
        "corpus": {"freeze": campaign.FREEZE, "freeze_sha256": freeze_sha,
                   "scenarios": [i for i in ids if not a.scenario or i in a.scenario]},
        "arms": {arm: {"vens_ref": v["vens_sha"], "vens_sha": v["vens_sha"], "binary_sha256": v["binary_sha256"],
                       "keys": {p: var for (p, k), (var, _) in sorted(keys.items()) if k == arm}}
                 for arm, v in arms.items()},
        "models": models, "replicates": a.replicates, "llm_batch_size": 1,
        "sampling": "each provider's default: no --llm-temperature and no --llm-seed",
        "retry_cap": a.retry_cap, "timeout_seconds": a.timeout, "parallelism": a.parallel, "mock_env": mock_env,
        "order": "replicate, then model, then scenario; each unit the before's run then the after's, back to back",
        "command": ["vens", *command("<provider>", "<scenario>", placeholder)],
    }
    base_env = {"PATH": environ.get("PATH", ""), "HOME": environ.get("HOME", ""), "TZ": "UTC"}
    return Context(os.path.abspath(a.root), os.path.abspath(a.out), doc, arms, keys, mock_env, base_env,
                   threading.Event(), threading.Lock())


def leaks(folder, key):
    """The files under folder that hold the key."""
    secret, found = key.encode(), []
    for d, _, names in os.walk(folder):
        for n in names:
            with open(os.path.join(d, n), "rb") as fh:
                if secret in fh.read():
                    found.append(os.path.relpath(os.path.join(d, n), folder))
    return sorted(found)


def _say(ctx, rel, rec):
    gen = rec["generate"]
    if gen["exit_status"] == 0:
        text = "complete"
    elif gen["interrupted"]:
        text = f"interrupted: {gen['interrupted']}"
    else:
        cause = venslog.cause(venslog.read(os.path.join(ctx.out, rel, "vens.log")))
        text = f"failed, exit {gen['exit_status']}" + (f": {cause}" if cause else "")
    if rec.get("retry_cap_reached"):
        text += "; the retry cap reached"
    with ctx.lock:
        print(f"{rel}: {text}", flush=True)


def attempt(ctx, unit, arm, k):
    """One attempt of one unit's arm, its record completed; RunnerError when the campaign must stop."""
    replicate, provider, model, scenario = unit
    doc, info = ctx.doc, ctx.arms[arm]
    rel = campaign.folder(replicate, provider, model, scenario, arm, k)
    args, (config, report) = command(provider, scenario, rel), inputs(scenario)
    variable, key = ctx.keys.get((provider, arm), (None, None))
    model_var, key_var, _ = PROVIDERS[provider]
    env = {**ctx.base_env, **({model_var: model} if model_var else {}), **({key_var: key} if key else {}),
           **(ctx.mock_env if provider == "mock" else {})}
    rec = {"record": 1, "runner": "scenarios", "campaign": doc["campaign"], "arm": arm, "provider": provider,
           "model": model, "llm_batch_size": 1, "vens_ref": info["vens_sha"], "vens_sha": info["vens_sha"],
           "vens_binary_sha256": info["binary_sha256"], "scenario": scenario, "config": config, "report": report,
           "freeze_sha256": doc["corpus"]["freeze_sha256"], "replicate": replicate, "attempt": k,
           "retry_cap": doc["retry_cap"], "timeout_seconds": doc["timeout_seconds"],
           "parallelism": doc["parallelism"], "key_env": variable,
           "mock_env": ctx.mock_env if provider == "mock" else None, "command": ["vens", *args],
           "setup_error": None, "retry_cap_reached": False}
    if _signature(info["binary"]) != info["signature"]:
        raise RunnerError(f"{info['binary']} changed since the runner hashed it")
    folder = os.path.join(ctx.out, rel)
    try:
        rec = runvens.run([info["binary"], *args], folder, rec, env=env, cwd=ctx.out,
                          timeout=doc["timeout_seconds"], key=key, stop=ctx.stop)
    except OSError as e:
        raise RunnerError(f"{rel}: vens did not start: {e}") from e
    found = leaks(folder, key) if key else []
    if found:
        raise RunnerError(f"{rel}: {variable}'s key is in {', '.join(found)}; remove it before anything is archived")
    gen = rec["generate"]
    if not gen["log_complete"]:
        raise RunnerError(f"{rel}: vens's log was not written whole")
    if gen["exit_status"] != 0 and k == doc["retry_cap"] and gen["interrupted"] != runvens.STOPPED:
        rec = {**rec, "retry_cap_reached": True}
        runvens.write_json(os.path.join(folder, "attempt.json"), rec)
    _say(ctx, rel, rec)
    return rec


def run_unit(ctx, unit):
    """The unit's before then its after, each attempted until one completes or the retry cap is reached:
    [(arm, complete | retry_cap_reached)], short of an arm the runner was stopped in."""
    out = []
    try:
        for arm in ARMS:
            for k in range(1, ctx.doc["retry_cap"] + 1):
                if ctx.stop.is_set():
                    return out
                rec = attempt(ctx, unit, arm, k)
                if rec["generate"]["exit_status"] == 0:
                    out.append((arm, COMPLETE))
                    break
                if rec["retry_cap_reached"]:
                    out.append((arm, CAP_REACHED))
    except BaseException:
        # set here, not only by the main thread: this worker takes the next unit as soon as this one raises
        ctx.stop.set()
        raise
    return out


def _results(futures):
    """Each unit's result as it ends, a unit's error raised at once; it waits a second at a time, so that a signal
    reaches the main thread."""
    pending = set(futures)
    while pending:
        done, pending = cf.wait(pending, timeout=1.0, return_when=cf.FIRST_EXCEPTION)
        for f in done:
            yield f.result()


def _why(error):
    if isinstance(error, KeyboardInterrupt):
        return "interrupted: SIGINT"
    if isinstance(error, Terminated):
        return "interrupted: SIGTERM"
    return f"runner error: {error}" if isinstance(error, RunnerError) else f"runner error: {error!r}"


def run_campaign(ctx):
    """The campaign, its folder laid out and every unit run; returns the results of the units it ran. An error or
    a signal stops it: the attempts running are killed and recorded interrupted, campaign.json says why, and the
    error is raised again once SHA256SUMS is written."""
    os.makedirs(ctx.out)
    shutil.copytree(os.path.join(ctx.root, campaign.SCENARIOS), os.path.join(ctx.out, campaign.SCENARIOS))
    shutil.copy2(os.path.join(ctx.root, campaign.FREEZE), os.path.join(ctx.out, campaign.FREEZE))
    campaign.check_corpus(ctx.out)
    doc = {**ctx.doc, "started_at": runvens.utc()}
    path = os.path.join(ctx.out, campaign.CAMPAIGN)
    runvens.write_json(path, doc)
    results, error = [], None
    with cf.ThreadPoolExecutor(max_workers=doc["parallelism"]) as ex:
        futures = [ex.submit(run_unit, ctx, unit) for unit in campaign.plan(doc)]
        try:
            for done in _results(futures):
                results += done
        except BaseException as e:
            ctx.stop.set()
            for f in futures:
                f.cancel()
            error = e
    runvens.write_json(path, {**doc, "ended_at": runvens.utc(), "stopped": None if error is None else _why(error)})
    campaign.write_sums(ctx.out)
    if error is not None:
        raise error
    return results


def _terminate(signum, frame):
    raise Terminated()


def _positive(text):
    try:
        n = int(text)
    except ValueError:
        n = 0
    if n < 1:
        raise argparse.ArgumentTypeError(f"{text}: a positive integer")
    return n


def main(argv=None, environ=None):
    ap = argparse.ArgumentParser(prog="python3 ctx_runner.py", description="The scenario runner.")
    ap.add_argument("--campaign", required=True)
    ap.add_argument("--out", required=True)
    for arm in ARMS:
        ap.add_argument(f"--{arm}", required=True, help=f"the {arm}'s vens binary")
        ap.add_argument(f"--{arm}-commit", required=True, help="the full commit it was built from")
    ap.add_argument("--model", action="append", required=True, help="PROVIDER/MODEL, its dated id")
    ap.add_argument("--undated", action="append", default=[], help="a model its provider gives no dated id")
    ap.add_argument("--replicates", required=True, type=_positive)
    ap.add_argument("--retry-cap", required=True, type=_positive, help="attempts per run, the first included")
    ap.add_argument("--timeout", required=True, type=_positive, help="seconds per attempt")
    ap.add_argument("--parallel", required=True, type=_positive, help="units side by side")
    ap.add_argument("--scenario", action="append", default=[], help="run these only (default: every scenario)")
    ap.add_argument("--root", default=ROOT, help="where scenarios/ and freeze-scenarios.json are")
    a = ap.parse_args(argv)
    try:
        ctx = prepare(a, os.environ if environ is None else environ)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    previous = signal.signal(signal.SIGTERM, _terminate)
    try:
        results = run_campaign(ctx)
    except (Refused, RunnerError) as e:
        print(f"stopped: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("stopped: SIGINT", file=sys.stderr)
        return 130
    except Terminated:
        print("stopped: SIGTERM", file=sys.stderr)
        return 143
    finally:
        signal.signal(signal.SIGTERM, previous)
    capped = sum(1 for _, outcome in results if outcome == CAP_REACHED)
    print(f"{len(results)} runs, {len(results) - capped} complete, {capped} at the retry cap without a complete "
          f"attempt; the archive is {a.out}")
    return EXIT_CAP_REACHED if capped else 0


if __name__ == "__main__":
    sys.exit(main())
