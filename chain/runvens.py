"""One `vens generate` laid out as an attempt folder: attempt.json written before vens starts, vens's whole log,
the debug folder and the VEX. The scenario runner's layout; the tests and the Java run use it on vens's mock.
"""
import datetime
import hashlib
import json
import os
import subprocess

SERIAL = "urn:uuid:00000000-0000-0000-0000-000000000001"
MARKER = "schema_version: 2\n"


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


def _write(path, doc):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")


def generate(binary, config, report, folder, *, record=None, batch=1, llm="mock", env_extra=None, strict=False,
             timeout=600):
    """Runs vens generate into folder, which must not exist, and returns the attempt record it wrote. Only PATH,
    HOME and env_extra reach vens: no API key does."""
    os.makedirs(folder)
    rec = {"record": 1, "runner": "scenarios", **(record or {}), "provider": llm,
           "model": (record or {}).get("model", llm), "llm_batch_size": batch,
           "vens_binary_sha256": sha256(binary), "config": config, "report": report,
           "generate": {"started_at": utc(), "ended_at": None, "exit_status": None, "timed_out": False}}
    _write(os.path.join(folder, "attempt.json"), rec)
    cmd = [binary, "generate", "--llm", llm, "--config-file", config, "--llm-batch-size", str(batch),
           "--sbom-serial-number", SERIAL, "--attest", "--debug-dir", os.path.join(folder, "calls"), report,
           os.path.join(folder, "vex.cdx.json")]
    if strict:
        cmd.insert(2, "--strict")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""), **(env_extra or {})}
    with open(os.path.join(folder, "vens.log"), "wb") as log:
        try:
            r = subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=log, timeout=timeout)
            gen = {**rec["generate"], "ended_at": utc(), "exit_status": r.returncode}
        except subprocess.TimeoutExpired:
            gen = {**rec["generate"], "ended_at": utc(), "timed_out": True}
    rec = {**rec, "generate": gen}
    _write(os.path.join(folder, "attempt.json"), rec)
    return rec
