"""Read attempts and print one JSON object per attempt, complete or failed.

    python3 -m chain.read [--dispatch-log LOG] [--arm before|after] [--failures FILE] DIR...

DIR is an attempt folder (it holds attempt.json or provenance.json), one workflow run's download (it holds
baseline-* folders) or a campaign's downloads (one numeric folder per run). Without --dispatch-log, a download's
campaign replicate is its artefacts' r<n>.
"""
import argparse
import glob
import json
import os
import sys

from chain import attempt, dispatch, downloads


def read_any(path, lines=None, arm=None, failures=()):
    if any(os.path.exists(os.path.join(path, f)) for f in ("attempt.json", "provenance.json")) or \
            attempt.parse_name(os.path.basename(os.path.normpath(path))):
        return [attempt.read_attempt(path, arm=arm)]
    if glob.glob(os.path.join(path, "baseline-*")):
        return downloads.read_run(path, lines=lines, arm=arm, failures=failures)
    return downloads.read_downloads(path, lines=lines, arm=arm, failures=failures)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m chain.read")
    ap.add_argument("--dispatch-log")
    ap.add_argument("--arm", choices=("before", "after"))
    ap.add_argument("--failures", action="append", default=[])
    ap.add_argument("dirs", nargs="+")
    a = ap.parse_args(argv)
    lines = dispatch.load(a.dispatch_log) if a.dispatch_log else None
    failures = [f for path in a.failures for f in downloads.load_failures(path)]
    try:
        for path in a.dirs:
            for rec in read_any(path, lines, a.arm, failures):
                print(json.dumps(rec, sort_keys=True))
    except attempt.Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
