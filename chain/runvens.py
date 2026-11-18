"""One `vens generate` laid out as an attempt folder: attempt.json written before vens starts and completed when it
ends, vens's whole log, the debug folder and the VEX. The scenario runner's layout; the tests and the Java run use it
on vens's mock.

vens runs in a session of its own, so that no terminal signal reaches it and its whole group can be killed. Every
group not yet seen to end is in a registry that kill_live() kills, which this module runs at exit and the runner on
any stop. A SIGKILL of the runner runs nothing, and macOS has no parent-death signal: a watch process per vens,
blocked on a pipe only this process can write to, sees the pipe close when this process dies and kills the group.
"""
import atexit
import base64
import contextlib
import datetime
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

SERIAL = "urn:uuid:00000000-0000-0000-0000-000000000001"
MARKER = "schema_version: 2\n"
TIMEOUT, STOPPED = "timeout", "the runner was stopped"
POLL = 0.2
# seconds vens's stderr may stay open once vens has ended and its group was killed; then a second kill, and as long
DRAIN = 5.0
WATCH = """import os, signal, sys
pid = int(sys.argv[1])
os.read(0, 1)
try:
    if os.getpgid(pid) == pid:
        os.killpg(pid, signal.SIGKILL)
except OSError:
    pass
"""

_LIVE, _LOCK, _LIFELINE = set(), threading.Lock(), []


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


def secret_pattern(key):
    """What the log and the archive are cleaned of for one API key: the key; its base64, standard and URL-safe, at
    each of the three byte alignments it can take inside a longer encoded text; and its first 8 and last 4
    characters around what an SDK shows of a key it masks (sk-...XXXX). None for no key."""
    if not key:
        return None
    raw, forms = key.encode(), {key.encode()}
    for pad in range(3):
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            coded = encode(b"\0" * pad + raw)
            # the characters that encode the key's bytes alone
            part = coded[(pad * 8 + 5) // 6:((pad + len(raw)) * 8) // 6]
            if len(part) >= 8:
                forms.add(part)
    alternatives = [re.escape(f) for f in sorted(forms, key=len, reverse=True)]
    if len(raw) >= 12:
        alternatives.append(re.escape(raw[:8]) + rb"[^\s\"']{0,%d}" % len(raw) + re.escape(raw[-4:]))
    return re.compile(b"|".join(alternatives))


def scrub(folder, pattern):
    """The files under folder that held a form of the key, each rewritten with *** in its place."""
    found = []
    for d, _, names in os.walk(folder):
        for n in names:
            path = os.path.join(d, n)
            with open(path, "rb") as fh:
                data = fh.read()
            clean = pattern.sub(b"***", data)
            if clean != data:
                tmp = f"{path}.{os.getpid()}-{threading.get_ident()}.tmp"
                with open(tmp, "wb") as fh:
                    fh.write(clean)
                os.replace(tmp, path)
                found.append(os.path.relpath(path, folder))
    return sorted(found)


def _killpg(pgid):
    with contextlib.suppress(OSError):
        os.killpg(pgid, signal.SIGKILL)


def kill_live():
    """Kills every vens group this process started and has not seen end."""
    with _LOCK:
        groups = sorted(_LIVE)
    for pgid in groups:
        _killpg(pgid)


atexit.register(kill_live)


def _watch(pid):
    """WATCH over vens's group, its stdin the read end of this process's lifeline, whose write end this process holds
    until it dies."""
    with _LOCK:
        if not _LIFELINE:
            _LIFELINE.extend(os.pipe())
        lifeline = _LIFELINE[0]
    return subprocess.Popen([sys.executable, "-S", "-c", WATCH, str(pid)], stdin=lifeline,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={}, start_new_session=True)


def _copy(src, dst, pattern, done):
    """vens's stderr into its log as it comes, each form of the key cut out of each line before it is written; the
    pipe is read to its end even when a write fails, so that vens never blocks on it."""
    whole = True
    for line in iter(src.readline, b""):
        if whole:
            try:
                dst.write(pattern.sub(b"***", line) if pattern else line)
                dst.flush()
            except OSError:
                whole = False
    done.append(whole)


def _drain(src, dst, pattern, done):
    copier = threading.Thread(target=_copy, args=(src, dst, pattern, done), daemon=True)
    copier.start()
    return copier


def _end(proc, timeout, stop):
    """(vens's exit status, None), or (None, why) when the runner killed its group: at the timeout, or once stop is
    set. A killed vens has no exit status of its own."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return proc.wait(timeout=max(0.0, min(POLL, deadline - time.monotonic()))), None
        except subprocess.TimeoutExpired:
            pass
        why = TIMEOUT if time.monotonic() >= deadline else STOPPED if stop is not None and stop.is_set() else None
        if why is not None:
            _killpg(proc.pid)
            proc.wait()
            return None, why


def _drained(pgid, copier, done):
    """Whether vens's stderr reached its log whole. What vens left in its group could hold the pipe open past its
    end: the group is killed, the copier given DRAIN seconds, then killed again and given as long."""
    for _ in range(2):
        _killpg(pgid)
        copier.join(DRAIN)
        if not copier.is_alive():
            return done == [True]
    return False


def run(cmd, folder, rec, *, env, cwd=None, timeout=600, key=None, stop=None):
    """Runs cmd, a vens command, into folder, which must not exist, and returns the attempt record completed.

    rec is written to folder/attempt.json before vens starts, then completed on the runner's clock: generate's
    start and end, its exit status, or, when the runner killed it, none and interrupted saying why (timed_out for the
    timeout); log_complete, whether vens's stderr reached folder/vens.log whole. key, the API key vens gets, is cut out
    of the log in each of its forms (secret_pattern). vens's stdout is dropped: it writes nothing there. A vens that
    does not start leaves setup_error and no start, and the OSError is raised; any error once it has started kills
    its group, is recorded and is raised."""
    os.makedirs(folder)
    path = os.path.join(folder, "attempt.json")
    gen = {"started_at": None, "ended_at": None, "exit_status": None, "timed_out": False, "interrupted": None,
           "log_complete": None}
    rec = {**rec, "generate": gen}
    write_json(path, rec)
    pattern = secret_pattern(key)
    with open(os.path.join(folder, "vens.log"), "wb") as log:
        started = utc()
        write_json(path, {**rec, "generate": {**gen, "started_at": started}})
        try:
            proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE, start_new_session=True)
        except OSError as e:
            write_json(path, {**rec, "setup_error": f"vens did not start: {e}"})
            raise
        with _LOCK:
            _LIVE.add(proc.pid)
        watch = None
        try:
            watch = _watch(proc.pid)
            done = []
            copier = _drain(proc.stderr, log, pattern, done)
            status, why = _end(proc, timeout, stop)
            ended = utc()
            whole = _drained(proc.pid, copier, done)
        except BaseException as e:
            _killpg(proc.pid)
            proc.wait()
            with contextlib.suppress(Exception):
                write_json(path, {**rec, "generate": {**gen, "started_at": started, "ended_at": utc(),
                                                      "interrupted": f"the runner failed: {e!r}"}})
            raise
        finally:
            with _LOCK:
                _LIVE.discard(proc.pid)
            if watch is not None:
                watch.kill()
                watch.wait()
    rec = {**rec, "generate": {**gen, "started_at": started, "ended_at": ended, "exit_status": status,
                               "timed_out": why == TIMEOUT, "interrupted": why, "log_complete": whole}}
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
