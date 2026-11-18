"""The scenario runner: each scenario of the frozen corpus scored by vens's two arms, the before (main) and the after
(310-step3), on the models given, replicate by replicate, every attempt recorded, failed ones included
(venslabs/vens#310 step 4).

    python3 ctx_runner.py --campaign NAME --out DIR \\
        --before BIN --before-commit SHA --after BIN --after-commit SHA \\
        --model PROVIDER/MODEL [--model ...] [--undated MODEL ...] [--key-suffix SUFFIX] \\
        --replicates N --retry-cap N --timeout SECONDS --parallel N [--scenario ID ...] [--root DIR]

A unit is one scenario, model and replicate: the before's run, then the after's, back to back. The units go
replicate by replicate, model by model, scenario by scenario, --parallel of them side by side. Each run is `vens
generate` at batch 1 with --attest and a --debug-dir of its own, with baseline.yml's flags and each provider's default
sampling: no --llm-temperature and no --llm-seed. An attempt completes when vens exits 0 and leaves a complete record
(the VEX, the attestation, answers.json for the after, every call archived from the dispatched model); one that does
not, or that the runner kills at --timeout seconds, is followed by another, up to --retry-cap attempts in all, the last
one, failed, recording the retry cap reached. Every attempt stays in the archive with its cause.

The corpus is the frozen one: scenarios/ under --root (the repository by default) must hold freeze-scenarios.json's
files and no other, and the freeze must be the one the corpus was frozen with (chain/campaign.py, FROZEN). Both are
copied into DIR, made read-only, and vens runs on the copy; a config or report whose sha256 changes during an attempt
stops the campaign. --before and --before-commit, --after and --after-commit give each arm's binary and the full
commit it was built from; campaign.json and every attempt record name the commit and the binary's sha256, and the
runner stops when a binary changes under it.

A model is given by its dated id where its provider dates its snapshots (gpt-5.4-mini-2026-03-17,
claude-haiku-4-5-20251001); --undated names one of the models known to have no dated id (UNDATED), recorded as such.
Each arm runs on its own key per provider: OPENAI_API_KEY_BEFORE, OPENAI_API_KEY_AFTER, ANTHROPIC_API_KEY_BEFORE,
ANTHROPIC_API_KEY_AFTER, each with _SUFFIX appended under --key-suffix. A scenario campaign runs on keys of its own
(--key-suffix SCENARIOS reads OPENAI_API_KEY_BEFORE_SCENARIOS, ...), or on the campaign keys on days no other run uses
them, so that each key's and day's usage export is one campaign's arm. vens gets the key as OPENAI_API_KEY or
ANTHROPIC_API_KEY, and nothing else but PATH, HOME, TZ=UTC and the model; a key missing, or one key for both arms,
stops the runner before any call. The key's forms (chain/runvens.py, secret_pattern) are cut out of vens's log as it
is written; one found in an attempt's files is cut out of them too, recorded, and stops the campaign. mock/mock is
vens's own mock LLM, no key and nothing paid; VENS_MOCK_LLM_FAIL, VENS_MOCK_LLM_SKIP and VENS_MOCK_LLM_CANNOT_TELL
reach it from the runner's environment and are recorded.

DIR must not exist; it becomes the campaign's archive (chain/campaign.py), which `python3 -m chain.read DIR` reads;
commit it with the campaign's measurements. Exit 0 when every run has a complete attempt, 3 when some reached the
retry cap without one, 1 when the runner refused or stopped on an error, 128 + the signal's number when SIGINT, SIGTERM
or SIGHUP stopped it. A stop, a signal or an error, kills every vens running, records each attempt interrupted, and
seals the archive: campaign.json says why, failures.jsonl lists each failed attempt with its cause, every key's forms
are swept out of every file (one found then stops the campaign too) and SHA256SUMS is written last; a signal during
the stop changes nothing. A SIGKILL of the runner cannot run any of that: each vens's guard kills its group then
(chain/runvens.py), and the archive is left without its end, its failures.jsonl and its SHA256SUMS.
"""
import argparse
import concurrent.futures as cf
import os
import re
import shutil
import signal
import stat
import sys
import threading
from dataclasses import dataclass, field

from chain import attempt as attemptmod
from chain import campaign, runvens, venslog
from chain.errors import Refused, load_object
from chain.javarun import own_commit

ROOT = os.path.dirname(os.path.abspath(__file__))
ARMS = campaign.ARMS
# provider: (vens's model variable, vens's key variable, the suffix of a dated id)
PROVIDERS = {
    "openai": ("OPENAI_MODEL", "OPENAI_API_KEY", re.compile(r"-\d{4}-\d{2}-\d{2}$")),
    "anthropic": ("ANTHROPIC_MODEL", "ANTHROPIC_API_KEY", re.compile(r"-\d{8}$")),
    "mock": (None, None, None),
}
# models whose provider gives no dated id
UNDATED = ("claude-sonnet-4-6",)
MOCK_ENV = ("VENS_MOCK_LLM_FAIL", "VENS_MOCK_LLM_SKIP", "VENS_MOCK_LLM_CANNOT_TELL")
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
COMMIT = re.compile(r"[0-9a-f]{40}")
NAME = re.compile(r"[A-Za-z0-9._-]+")
SUFFIX = re.compile(r"[A-Z0-9_]+")
COMPLETE, CAP_REACHED = "complete", "retry_cap_reached"
EXIT_CAP_REACHED = 3


class RunnerError(Exception):
    """What stops a campaign once it has started: vens that does not start, a binary or an input that changed, a
    log not written whole, a key found in an attempt's files."""


class Terminated(BaseException):
    """SIGINT, SIGTERM or SIGHUP, raised in the main thread."""

    def __init__(self, signum):
        super().__init__(signal.Signals(signum).name)
        self.signum = signum


class OnSignal:
    """The handler of SIGINT, SIGTERM and SIGHUP: each sets the stop, so that no worker starts another attempt and
    each kills the one it runs; the first also raises Terminated in the main thread, the next ones do not, so that
    the stop they would cut runs to its end."""

    def __init__(self, stop):
        self.stop, self.raised = stop, False

    def __call__(self, signum, frame):
        self.stop.set()
        if not self.raised:
            self.raised = True
            raise Terminated(signum)

    def hush(self):
        """No raise from here on: the units are over and what is left is finishing the archive."""
        self.raised = True


def key_variable(provider, arm, suffix=""):
    return f"{PROVIDERS[provider][1]}_{arm.upper()}" + (f"_{suffix}" if suffix else "")


def parse_models(given, undated):
    """[{provider, model, dated}]: each model its provider's dated id, or one of UNDATED that --undated names;
    Refused otherwise."""
    out = []
    for name in undated:
        if name not in UNDATED:
            raise Refused(f"--undated {name}: not a model known to have no dated id ({', '.join(UNDATED)}); give "
                          f"its dated id")
    for text in given:
        provider, sep, model = text.partition("/")
        if not sep or provider not in PROVIDERS or not NAME.fullmatch(model):
            raise Refused(f"--model {text}: give PROVIDER/MODEL, the provider one of {', '.join(PROVIDERS)}")
        suffix = PROVIDERS[provider][2]
        if suffix is None and model != "mock":
            raise Refused(f"--model {text}: vens's mock is mock/mock")
        if suffix is not None and not suffix.search(model) and model not in undated:
            raise Refused(f"--model {text}: not a dated id; give the dated snapshot"
                          + (f", or --undated {model}" if model in UNDATED else ""))
        out.append({"provider": provider, "model": model,
                    "dated": None if suffix is None else bool(suffix.search(model))})
    if len({(m["provider"], m["model"]) for m in out}) < len(out):
        raise Refused("a model given twice")
    stray = sorted(set(undated) - {m["model"] for m in out})
    if stray:
        raise Refused(f"--undated {', '.join(stray)}: no --model names it")
    return out


def _signature(path):
    st = os.stat(path)
    return st.st_ino, st.st_size, st.st_mtime_ns


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
    for name, what in (("binary_sha256", "binary"), ("vens_sha", "commit")):
        if out["before"][name] == out["after"][name]:
            raise Refused(f"the before and the after are one {what}")
    return out


def parse_keys(models, environ, suffix):
    """{(provider, arm): (variable, key)} for each provider that takes a key; Refused, before any call, when one is
    missing or the two arms share one."""
    out = {}
    for provider in sorted({m["provider"] for m in models if PROVIDERS[m["provider"]][1]}):
        pair = {arm: (key_variable(provider, arm, suffix), environ.get(key_variable(provider, arm, suffix), ""))
                for arm in ARMS}
        for variable, key in pair.values():
            if not key:
                raise Refused(f"{variable} is not set: each arm runs on its own key")
        if pair["before"][1] == pair["after"][1]:
            raise Refused(f"{pair['before'][0]} and {pair['after'][0]} hold one key: each arm runs on its own, so "
                          f"that its spend shows apart")
        out.update({(provider, arm): pair[arm] for arm in ARMS})
    return out


@dataclass(frozen=True)
class Context:
    root: str
    out: str
    doc: dict
    arms: dict
    keys: dict
    patterns: dict
    files: dict
    mock_env: dict
    base_env: dict
    stop: threading.Event
    lock: threading.Lock
    redacted: list = field(default_factory=list)


def prepare(a, environ, stop):
    """Every check the runner makes before it writes anything or calls a model."""
    if os.path.exists(a.out):
        raise Refused(f"{a.out} exists: a campaign is written into a folder of its own")
    if not NAME.fullmatch(a.campaign):
        raise Refused(f"--campaign {a.campaign}: letters, digits, '.', '_' and '-' only")
    if a.key_suffix and not SUFFIX.fullmatch(a.key_suffix):
        raise Refused(f"--key-suffix {a.key_suffix}: capitals, digits and '_' only")
    models = parse_models(a.model, a.undated)
    arms = parse_arms(a)
    keys = parse_keys(models, environ, a.key_suffix)
    files, ids = campaign.check_corpus(a.root)
    unknown = sorted(set(a.scenario) - set(ids))
    if unknown:
        raise Refused(f"--scenario {', '.join(unknown)}: not in the corpus")
    mock = any(m["provider"] == "mock" for m in models)
    mock_env = {k: environ[k] for k in MOCK_ENV if mock and environ.get(k)}
    placeholder = campaign.folder("<replicate>", "<provider>", "<model>", "<scenario>", "<arm>", "<attempt>")
    doc = {
        "record": 1, "runner": "scenarios", "campaign": a.campaign, "vens_benchmark": own_commit(),
        "started_at": None, "ended_at": None, "stopped": None, "redacted": [],
        "corpus": {"freeze": campaign.FREEZE, "freeze_sha256": campaign.FROZEN,
                   "scenarios": [i for i in ids if not a.scenario or i in a.scenario]},
        "arms": {arm: {"vens_ref": v["vens_sha"], "vens_sha": v["vens_sha"], "binary_sha256": v["binary_sha256"],
                       "keys": {p: var for (p, k), (var, _) in sorted(keys.items()) if k == arm}}
                 for arm, v in arms.items()},
        "models": models, "replicates": a.replicates, "llm_batch_size": 1,
        "sampling": "each provider's default: no --llm-temperature and no --llm-seed",
        "retry_cap": a.retry_cap, "timeout_seconds": a.timeout, "parallelism": a.parallel, "mock_env": mock_env,
        "order": "replicate, then model, then scenario; each unit the before's run then the after's, back to back",
        "command": ["vens", *campaign.command("<provider>", "<scenario>", placeholder)],
    }
    patterns = {pair: runvens.secret_pattern(key) for pair, (_, key) in keys.items()}
    base_env = {"PATH": environ.get("PATH", ""), "HOME": environ.get("HOME", ""), "TZ": "UTC"}
    return Context(os.path.abspath(a.root), os.path.abspath(a.out), doc, arms, keys, patterns, files, mock_env,
                   base_env, stop, threading.Lock())


def _say(ctx, rel, rec):
    gen, check = rec["generate"], rec.get("record_check") or {}
    if campaign.done(rec):
        text = "complete"
    elif gen["interrupted"]:
        text = f"interrupted: {gen['interrupted']}"
    elif gen["exit_status"] == 0:
        text = f"failed, the record check: {check.get('cause')}"
    else:
        cause = venslog.cause(venslog.read(os.path.join(ctx.out, rel, "vens.log")))
        text = f"failed, exit {gen['exit_status']}" + (f": {cause}" if cause else "")
    if rec.get("retry_cap_reached"):
        text += "; the retry cap reached"
    with ctx.lock:
        print(f"{rel}: {text}", flush=True)


def _changed_inputs(ctx, scenario):
    return [p for p in campaign.inputs(scenario) if runvens.sha256(os.path.join(ctx.out, p)) != ctx.files[p]]


def attempt(ctx, unit, arm, k):
    """One attempt of one unit's arm, its record completed; RunnerError when the campaign must stop."""
    replicate, provider, model, scenario = unit
    doc, info = ctx.doc, ctx.arms[arm]
    rel = campaign.folder(replicate, provider, model, scenario, arm, k)
    args, (config, report) = campaign.command(provider, scenario, rel), campaign.inputs(scenario)
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
           "setup_error": None, "record_check": None, "retry_cap_reached": False, "redacted": []}
    if _signature(info["binary"]) != info["signature"]:
        raise RunnerError(f"{info['binary']} changed since the runner hashed it")
    folder = os.path.join(ctx.out, rel)
    path = os.path.join(folder, "attempt.json")
    try:
        rec = runvens.run([info["binary"], *args], folder, rec, env=env, cwd=ctx.out,
                          timeout=doc["timeout_seconds"], key=key, stop=ctx.stop)
    except OSError as e:
        written = load_object(path)
        why = written.get("setup_error") or (written.get("generate") or {}).get("interrupted") or str(e)
        raise RunnerError(f"{rel}: {why}") from e

    def stop_on(cause, **fields):
        """The attempt failed by cause, kept in its record before the campaign stops on it."""
        runvens.write_json(path, {**rec, **fields, "record_check": {"passed": False, "cause": cause}})
        raise RunnerError(f"{rel}: {cause}")

    found = runvens.scrub(folder, ctx.patterns[(provider, arm)]) if key else []
    if found:
        with ctx.lock:
            ctx.redacted.extend(os.path.join(rel, f) for f in found)
        stop_on(f"a form of {variable}'s key was in {', '.join(found)}, now cut out", redacted=found)
    gen = rec["generate"]
    if not gen["log_complete"]:
        stop_on("vens's log was not written whole: a write failed, or a process out of vens's group kept its "
                "stderr open")
    changed = _changed_inputs(ctx, scenario)
    if changed:
        stop_on(f"{', '.join(changed)} changed during the attempt, no longer the frozen corpus's")
    if gen["exit_status"] == 0:
        gaps = attemptmod.record_gaps(folder, arm, provider, model)
        rec = {**rec, "record_check": {"passed": not gaps, "cause": "; ".join(gaps) or None}}
    if not campaign.done(rec) and k == doc["retry_cap"] and gen["interrupted"] != runvens.STOPPED:
        rec = {**rec, "retry_cap_reached": True}
    runvens.write_json(path, rec)
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
                if campaign.done(rec):
                    out.append((arm, COMPLETE))
                    break
                if rec["retry_cap_reached"]:
                    out.append((arm, CAP_REACHED))
    except BaseException:
        # set here, not only by the main thread: this worker takes the next unit as soon as this one raises
        ctx.stop.set()
        raise
    return out


def _results(futures, hush):
    """Each unit's result as it ends; a unit's error is raised at once, after hush, so that no signal cuts the stop
    it starts. It waits a second at a time, so that a signal reaches the main thread."""
    pending = set(futures)
    while pending:
        done, pending = cf.wait(pending, timeout=1.0, return_when=cf.FIRST_EXCEPTION)
        for f in done:
            if f.exception() is not None:
                hush()
            yield f.result()


def _why(error):
    if isinstance(error, Terminated):
        return f"interrupted: {error}"
    return f"runner error: {error}" if isinstance(error, RunnerError) else f"runner error: {error!r}"


def _snapshot(ctx):
    """The frozen corpus copied into the campaign folder and checked there, its files read-only."""
    shutil.copytree(os.path.join(ctx.root, campaign.SCENARIOS), os.path.join(ctx.out, campaign.SCENARIOS))
    shutil.copy2(os.path.join(ctx.root, campaign.FREEZE), os.path.join(ctx.out, campaign.FREEZE))
    campaign.check_corpus(ctx.out)
    read_only = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    for d, _, names in os.walk(os.path.join(ctx.out, campaign.SCENARIOS)):
        for n in names:
            os.chmod(os.path.join(d, n), read_only)
    os.chmod(os.path.join(ctx.out, campaign.FREEZE), read_only)


def _sweep(ctx):
    """Every key's forms cut out of every file of the archive: the files each was in."""
    found = set()
    for pattern in ctx.patterns.values():
        found.update(runvens.scrub(ctx.out, pattern))
    return sorted(found)


def _seal(ctx, doc, error):
    """The archive finished, whatever stopped the campaign: campaign.json with its end, why it stopped and the files
    a key was cut out of; failures.jsonl; every key's forms swept out of every file, campaign.json included, a form
    found then stopping the campaign; SHA256SUMS last, written even when finishing fails. Returns the error the
    campaign ends on."""
    path = os.path.join(ctx.out, campaign.CAMPAIGN)
    try:
        runvens.write_json(path, {**doc, "ended_at": runvens.utc(), "redacted": sorted(set(ctx.redacted)),
                                  "stopped": None if error is None else _why(error)})
        campaign.write_failures(ctx.out)
        # the second sweep reads what the first one's marks rewrote; the marks never hold a key, only paths
        for _ in range(2):
            found = _sweep(ctx)
            if not found:
                break
            error = error or RunnerError(f"a form of a key was in {', '.join(found)}, now cut out")
            sealed = load_object(path)
            runvens.write_json(path, {**sealed, "redacted": sorted(set(sealed.get("redacted") or []) | set(found)),
                                      "stopped": sealed.get("stopped") or _why(error)})
    finally:
        campaign.write_sums(ctx.out)
    return error


def run_campaign(ctx, hush=lambda: None):
    """The campaign, its folder laid out and every unit run; returns the results of the units it ran. An error or
    a signal stops it: hush is called so that no signal cuts the stop, the units not started are dropped, every vens
    still running is killed and its attempt recorded interrupted, and the archive is sealed (_seal) before the error
    is raised again."""
    os.makedirs(ctx.out)
    _snapshot(ctx)
    doc = {**ctx.doc, "started_at": runvens.utc()}
    runvens.write_json(os.path.join(ctx.out, campaign.CAMPAIGN), doc)
    results, error = [], None
    ex = cf.ThreadPoolExecutor(max_workers=doc["parallelism"])
    try:
        futures = [ex.submit(run_unit, ctx, unit) for unit in campaign.plan(doc)]
        for done in _results(futures, hush):
            results += done
    except BaseException as e:
        error = e
    finally:
        hush()
        ctx.stop.set()
        try:
            ex.shutdown(wait=True, cancel_futures=True)
        except BaseException as e:
            # a signal that landed before the hush: kept, and the workers still joined
            error = error or e
            ex.shutdown(wait=True, cancel_futures=True)
        runvens.kill_live()
    error = _seal(ctx, doc, error)
    if error is not None:
        raise error
    return results


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
    ap.add_argument("--undated", action="append", default=[], help=f"one of {', '.join(UNDATED)}")
    ap.add_argument("--key-suffix", default="", help="read each key from its variable with _SUFFIX appended")
    ap.add_argument("--replicates", required=True, type=_positive)
    ap.add_argument("--retry-cap", required=True, type=_positive, help="attempts per run, the first included")
    ap.add_argument("--timeout", required=True, type=_positive, help="seconds per attempt")
    ap.add_argument("--parallel", required=True, type=_positive, help="units side by side")
    ap.add_argument("--scenario", action="append", default=[], help="run these only (default: every scenario)")
    ap.add_argument("--root", default=ROOT, help="where scenarios/ and freeze-scenarios.json are")
    a = ap.parse_args(argv)
    stop = threading.Event()
    handler = OnSignal(stop)
    previous = {s: signal.signal(s, handler) for s in SIGNALS}
    try:
        ctx = prepare(a, os.environ if environ is None else environ, stop)
        results = run_campaign(ctx, handler.hush)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    except RunnerError as e:
        print(f"stopped: {e}", file=sys.stderr)
        return 1
    except Terminated as e:
        print(f"stopped: {e}", file=sys.stderr)
        return 128 + e.signum
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)
    capped = sum(1 for _, outcome in results if outcome == CAP_REACHED)
    print(f"{len(results)} runs, {len(results) - capped} complete, {capped} at the retry cap without a complete "
          f"attempt; the archive is {a.out}")
    return EXIT_CAP_REACHED if capped else 0


if __name__ == "__main__":
    sys.exit(main())
