"""One `vens generate` laid out as an attempt folder: attempt.json written before vens starts and completed when it
ends, vens's whole log, the debug folder and the VEX. The scenario runner's layout; the tests and the Java run use it
on vens's mock.
"""
import contextlib
import datetime
import hashlib
import json
import os
import signal
import subprocess
import threading
import time

SERIAL = "urn:uuid:00000000-0000-0000-0000-000000000001"
MARKER = "schema_version: 2\n"
TIMEOUT, STOPPED = "timeout", "the runner was stopped"
POLL = 0.2


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def add_marker(src, dst):
    """A copy of a schema-1 config with the schema-2 marker as its first line, every other byte kept; a config
    that declares its schema already is copied as it is."""
    with open(src, encoding="utf-8") as fh:
        text = fh.read()
    declared = any(line.startswith("schema_version:") for line in text.splitlines())
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(text if declared else MARKER + text)
    return dst


def write_json(path, doc):
    """Written whole through a file of its own, so a kill mid-write leaves the file as it was."""
    tmp = f"{path}.{os.getpid()}-{threading.get_ident()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    os.replace(tmp, path)


def _copy(src, dst, key, done):
    """vens's stderr into its log as it comes, the key cut out of each line before it is written; the pipe is read
    to its end even when a write fails, so that vens never blocks on it."""
    whole = True
    for line in iter(src.readline, b""):
        if whole:
            try:
                dst.write(line.replace(key, b"***") if key else line)
                dst.flush()
            except OSError:
                whole = False
    done.append(whole)


def _end(proc, timeout, stop):
    """(vens's exit status, None), or (None, why) when the runner killed it: at its timeout, or once stop is set."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return proc.wait(timeout=max(0.0, min(POLL, deadline - time.monotonic()))), None
        except subprocess.TimeoutExpired:
            pass
        why = TIMEOUT if time.monotonic() >= deadline else STOPPED if stop is not None and stop.is_set() else None
        if why is None:
            continue
        # vens runs in a session of its own: the kill takes its whole group, and no terminal signal reaches it.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        status = proc.wait()
        # a vens that ended on its own just before the kill keeps its exit status
        return (None, why) if status == -signal.SIGKILL else (status, None)


def run(cmd, folder, rec, *, env, cwd=None, timeout=600, key=None, stop=None):
    """Runs cmd, a vens command, into folder, which must not exist, and returns the attempt record completed.

    rec is written to folder/attempt.json before vens starts, then completed on the runner's clock: generate's
    start and end, its exit status, or, when the runner killed it, none and timed_out or interrupted saying why;
    log_complete, whether vens's stderr reached folder/vens.log whole. key, the API key vens gets, is cut out of the
    log. vens's stdout is dropped: it writes nothing there. A vens that does not start leaves setup_error and no
    start, and the OSError is raised."""
    os.makedirs(folder)
    path = os.path.join(folder, "attempt.json")
    gen = {"started_at": None, "ended_at": None, "exit_status": None, "timed_out": False, "interrupted": None,
           "log_complete": None}
    rec = {**rec, "generate": gen}
    write_json(path, rec)
    secret = key.encode() if key else None
    with open(os.path.join(folder, "vens.log"), "wb") as log:
        started = utc()
        write_json(path, {**rec, "generate": {**gen, "started_at": started}})
        try:
            proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE, start_new_session=True)
        except OSError as e:
            write_json(path, {**rec, "setup_error": f"vens did not start: {e}"})
            raise
        done = []
        copier = threading.Thread(target=_copy, args=(proc.stderr, log, secret, done), daemon=True)
        copier.start()
        status, why = _end(proc, timeout, stop)
        ended = utc()
        copier.join()
        proc.stderr.close()
    rec = {**rec, "generate": {**gen, "started_at": started, "ended_at": ended, "exit_status": status,
                               "timed_out": why == TIMEOUT, "interrupted": why, "log_complete": done == [True]}}
    write_json(path, rec)
    return rec


def generate(binary, config, report, folder, *, record=None, batch=1, llm="mock", env_extra=None, strict=False,
             timeout=600):
    """Runs vens generate into folder, which must not exist, and returns the attempt record it wrote. Only PATH,
    HOME and env_extra reach vens: no API key does."""
    rec = {"record": 1, "runner": "scenarios", **(record or {}), "provider": llm,
           "model": (record or {}).get("model", llm), "llm_batch_size": batch,
           "vens_binary_sha256": sha256(binary), "config": config, "report": report}
    cmd = [binary, "generate", "--llm", llm, "--config-file", config, "--llm-batch-size", str(batch),
           "--sbom-serial-number", SERIAL, "--attest", "--debug-dir", os.path.join(folder, "calls"), report,
           os.path.join(folder, "vex.cdx.json")]
    if strict:
        cmd.insert(2, "--strict")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), **(env_extra or {})}
    return run(cmd, folder, rec, env=env, timeout=timeout)
