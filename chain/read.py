"""Read attempts and print one JSON object per attempt, complete or failed.

    python3 -m chain.read [--dispatch-log LOG] [--commit before=SHA --commit after=SHA] [--arm before|after]
                          [--failures FILE] DIR...

DIR is an attempt folder (it holds attempt.json or provenance.json), one workflow run's download (it holds
baseline-* folders), a campaign's downloads (one numeric folder per run) or a scenario campaign (it holds
campaign.json, chain/campaign.py). With --dispatch-log, every artefact is mapped through it, a folder given on its
own included; without it, a download's campaign replicate is its artefacts' r<n>. A scenario campaign's records name
their arm and replicate: no dispatch log, --arm or --failures applies to it. --commit refuses an attempt whose vens
commit is not its arm's.
"""
import argparse
import glob
import json
import os
import sys

from chain import attempt, campaign, dispatch, downloads
from chain.errors import Refused


def read_any(path, lines=None, arm=None, failures=(), commits=None):
    """An attempt folder, a workflow run's download (its artefact folders, or its run.json or jobs.json from the API
    even with no artefact), or a campaign's downloads; never nothing."""
    if os.path.exists(os.path.join(path, campaign.CAMPAIGN)):
        if lines is not None or arm is not None or failures:
            raise Refused(f"{path}: a scenario campaign, whose records name their arm and replicate: no dispatch "
                          f"log, --arm or --failures applies to it")
        return campaign.read_campaign(path, commits=commits)
    kw = {"lines": lines, "arm": arm, "failures": failures, "commits": commits}
    if any(os.path.exists(os.path.join(path, f)) for f in ("attempt.json", "provenance.json")) or \
            attempt.parse_name(os.path.basename(os.path.normpath(path))):
        return [downloads.read_folder(path, **kw)]
    runs = [d for d in os.listdir(path) if d.isdigit() and os.path.isdir(os.path.join(path, d))]
    if glob.glob(os.path.join(path, "baseline-*")) or (downloads.is_run_dir(path) and not runs):
        return downloads.read_run(path, **kw)
    records = downloads.read_downloads(path, **kw)
    if not records:
        raise Refused(f"{path}: no attempt, no workflow run and no dispatch log line read there")
    return records


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
    commits = dict(a.commit) or None
    try:
        failures = [f for path in a.failures for f in downloads.load_failures(path)]
        lines = dispatch.load(a.dispatch_log) if a.dispatch_log else None
        for path in a.dirs:
            for rec in read_any(path, lines, a.arm, failures, commits):
                print(json.dumps(rec, sort_keys=True))
    except (Refused, dispatch.DispatchError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
