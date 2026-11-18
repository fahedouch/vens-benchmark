"""Read attempts and print one JSON object per attempt, complete or failed.

    python3 -m chain.read [--dispatch-log LOG] [--commit before=SHA --commit after=SHA] [--arm before|after]
                          [--failures FILE] DIR...

DIR is an attempt folder (it holds attempt.json or provenance.json), one workflow run's download (it holds
baseline-* folders) or a campaign's downloads (one numeric folder per run). With --dispatch-log, every artefact is
mapped through it, a folder given on its own included; without it, a download's campaign replicate is its
artefacts' r<n>. --commit refuses an attempt whose vens commit is not its arm's.
"""
import argparse
import glob
import json
import os
import sys

from chain import attempt, dispatch, downloads


def read_any(path, lines=None, arm=None, failures=(), commits=None):
    if any(os.path.exists(os.path.join(path, f)) for f in ("attempt.json", "provenance.json")) or \
            attempt.parse_name(os.path.basename(os.path.normpath(path))):
        return [downloads.read_folder(path, lines=lines, arm=arm, failures=failures, commits=commits)]
    if glob.glob(os.path.join(path, "baseline-*")):
        return downloads.read_run(path, lines=lines, arm=arm, failures=failures, commits=commits)
    return downloads.read_downloads(path, lines=lines, arm=arm, failures=failures, commits=commits)


def _commit(text):
    arm, sep, sha = text.partition("=")
    if arm not in dispatch.ARMS or not sep or not sha:
        raise argparse.ArgumentTypeError("give ARM=SHA, ARM before or after")
    return arm, sha


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m chain.read")
    ap.add_argument("--dispatch-log")
    ap.add_argument("--commit", action="append", type=_commit, default=[])
    ap.add_argument("--arm", choices=dispatch.ARMS)
    ap.add_argument("--failures", action="append", default=[])
    ap.add_argument("dirs", nargs="+")
    a = ap.parse_args(argv)
    lines = dispatch.load(a.dispatch_log) if a.dispatch_log else None
    failures = [f for path in a.failures for f in downloads.load_failures(path)]
    commits = dict(a.commit) or None
    try:
        for path in a.dirs:
            for rec in read_any(path, lines, a.arm, failures, commits):
                print(json.dumps(rec, sort_keys=True))
    except attempt.Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
