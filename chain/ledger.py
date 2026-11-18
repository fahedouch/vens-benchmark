"""Per cell: every attempt and failed attempt by cause, the calls by kind, the recovery calls, and their estimated
cost, beside the scores, which read complete runs only.

The recovery calls are every call a run makes beyond the planned ones, asked_again + 2 x splits, by kind: an
ask-again after an omission, one after an unreadable reply, a split half (chain/recovery.py). The cost here is an
estimate per attempt from its archived prompts and replies (chain/cost.py), never added to the measured totals,
which only the providers' usage exports give (chain/usage.py). A figure an attempt does not give stays unknown and
is counted as such, never read as 0.
"""
import collections
from datetime import datetime

from chain import attempt as attemptmod
from chain import calls as callmod

COUNTS = ("llm_calls", "planned", "adjustment", "again_omission", "again_unreadable", "split_halves",
          "recovery_calls", "asked_again", "splits")
CAUSE_WIDTH = 160


def cause(rec):
    """The failed attempt's cause, as the reader gives it: the step it failed at, where known, and its error line."""
    f = rec.get("failure") or {}
    text = f.get("cause") or f.get("reason") or "cause unknown"
    return (f"{f['kind']}: {text}" if f.get("kind") else text)[:CAUSE_WIDTH]


def tally(c):
    """One cell's ledger."""
    out = {"attempts": len(c["attempts"]), "complete": 0, "runs": len(c["runs"]), "unusable": len(c["unusable"]),
           "failed": collections.Counter(), "stray": 0, "not_read": 0, "reply_unreadable": 0,
           "counts": collections.Counter(), "unknown": collections.Counter(), "estimate": collections.Counter(),
           "estimate_unknown": 0, "retry_cap_reached": 0}
    for rec in c["attempts"]:
        out["stray"] += rec["excluded"] is not None
        if rec["outcome"] == attemptmod.COMPLETE:
            out["complete"] += 1
        elif rec["outcome"] == attemptmod.FAILED:
            out["failed"][cause(rec)] += 1
        else:
            out["not_read"] += 1
        out["retry_cap_reached"] += bool(rec.get("retry_cap_reached"))
        rcv = rec.get("recovery") or {}
        for name in COUNTS:
            if rcv.get(name) is None:
                out["unknown"][name] += 1
            else:
                out["counts"][name] += rcv[name]
        out["reply_unreadable"] += ((rec.get("summary") or {}).get("defects") or {}).get("reply_unreadable", 0)
        by_kind = (rec.get("cost_estimate") or {}).get("by_kind")
        if by_kind is None:
            out["estimate_unknown"] += 1
        else:
            out["estimate"].update(by_kind)
    return out


def ledgers(cells):
    return {k: tally(c) for k, c in sorted(cells.items(), key=lambda kv: str(kv[0]))}


def recovery_cost(ledger):
    """The estimated cost of the recovery calls: the ask-agains and the split halves."""
    return sum(ledger["estimate"].get(k, 0.0) for k in callmod.RECOVERY)


def wall_seconds(rec):
    """vens generate's wall time from the attempt record, None without both times."""
    gen = (rec.get("steps") or {}).get("generate") or {}
    start, end = gen.get("started_at"), gen.get("ended_at")
    if not start or not end:
        return None
    parse = lambda t: datetime.fromisoformat(t.replace("Z", "+00:00"))
    return (parse(end) - parse(start)).total_seconds()
