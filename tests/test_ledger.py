"""The attempts, their calls and the cost per cell, and the measured usage exports, on synthetic records."""
import os
import tempfile
import unittest

from chain import ledger, report, usage
from chain import cells as cellmod
from tests import records as r
from tests import support as s

CTX = "internal"
HEADER = ",".join(usage.FIELDS)


def counts(**kw):
    out = {k: 0 for k in ledger.COUNTS}
    out.update(kw)
    return out


class TestLedger(unittest.TestCase):
    def cell(self):
        recs = [r.record("after", CTX, 1, r.scored([1]), summary={"defects": {"reply_unreadable": 1}},
                         recovery=counts(llm_calls=12, planned=10, adjustment=1, again_omission=1, again_unreadable=1,
                                         recovery_calls=2, asked_again=2),
                         cost={"by_kind": {"planned": 0.10, "again_omission": 0.01, "again_unreadable": 0.02}},
                         steps={"generate": {"started_at": "2026-11-20T10:00:00Z",
                                             "ended_at": "2026-11-20T10:02:30Z"}}),
                r.record("after", CTX, 2, None, outcome="failed",
                         failure={"kind": "scoring", "cause": "model returned no answer to Motive (M)"},
                         recovery=counts(llm_calls=3, planned=2, again_omission=1, recovery_calls=1, asked_again=1),
                         cost={"by_kind": {"planned": 0.02, "again_omission": 0.01}}),
                r.record("after", CTX, 3, r.scored([1]), excluded="a stray run",
                         recovery={k: None for k in ledger.COUNTS}),
                r.record("after", CTX, 4, None, outcome=None)]
        (c,) = cellmod.group(recs).values()
        return c, recs

    def test_tally(self):
        c, _ = self.cell()
        got = ledger.tally(c)
        self.assertEqual((got["attempts"], got["complete"], got["runs"], got["stray"], got["not_read"]),
                         (4, 2, 1, 1, 1))
        self.assertEqual(dict(got["failed"]), {"scoring: model returned no answer to Motive (M)": 1})
        self.assertEqual((got["counts"]["llm_calls"], got["counts"]["recovery_calls"]), (15, 3))
        # neither the stray run nor the attempt not read gives a count
        self.assertEqual(got["unknown"]["llm_calls"], 2)
        self.assertEqual((got["reply_unreadable"], got["estimate_unknown"]), (1, 2))
        self.assertAlmostEqual(ledger.recovery_cost(got), 0.04)
        self.assertAlmostEqual(sum(got["estimate"].values()), 0.16)

    def test_a_count_no_attempt_gives_is_not_zero(self):
        c, _ = self.cell()
        led = ledger.tally(c)
        self.assertEqual(report._count(led, "llm_calls"), "15 (+2 unknown)")
        led["unknown"]["splits"] = led["attempts"]
        self.assertEqual(report._count(led, "splits"), report.NA)

    def test_wall_time(self):
        _, recs = self.cell()
        self.assertEqual(ledger.wall_seconds(recs[0]), 150.0)
        self.assertIsNone(ledger.wall_seconds(recs[1]))

    def test_a_cell_without_any_estimate_is_na_not_zero(self):
        recs = [r.record("after", CTX, 1, r.scored([1])), r.record("after", CTX, 2, None, outcome="failed")]
        text = "\n".join(report.estimated({"ledgers": ledger.ledgers(cellmod.group(recs))}))
        self.assertIn(f"| None · after · openai/{s.MODEL} · {CTX} | n/a | n/a | n/a | 2 |", text)

    def test_a_cause_without_its_step(self):
        rec = r.record("before", CTX, 1, None, outcome="failed",
                       failure={"kind": None, "cause": None, "reason": "no provenance.json: the job failed"})
        self.assertEqual(ledger.cause(rec), "no provenance.json: the job failed")


class TestUsage(unittest.TestCase):
    def load(self, *lines):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "usage.csv")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            return usage.load(path)

    def test_totals_keep_a_missing_number_missing(self):
        rows = self.load(HEADER,
                         "c1,2026-11-20,openai,key-before,before,gpt-5.4-mini-2026-03-17,74,100,0,10,0.05",
                         "c1,2026-11-20,openai,key-after,after,gpt-5.4-mini-2026-03-17,694,900,0,90,0.40",
                         "c1,2026-11-21,anthropic,key-after-a,after,claude-sonnet-4-6,,1000,,50,")
        self.assertEqual(usage.by_arm(rows), (rows, {}))
        by_model = usage.totals(rows, ("provider", "model"))
        self.assertEqual(by_model[("openai", "gpt-5.4-mini-2026-03-17")]["input_tokens"], 1000.0)
        self.assertAlmostEqual(by_model[("openai", "gpt-5.4-mini-2026-03-17")]["usd"], 0.45)
        self.assertIsNone(by_model[("anthropic", "claude-sonnet-4-6")]["usd"])
        by_arm = usage.totals(rows, ("arm",))
        self.assertEqual((by_arm[("after",)]["output_tokens"], by_arm[("after",)]["days"]),
                         (140.0, ["2026-11-20", "2026-11-21"]))

    def test_a_key_both_arms_share_gives_no_arm_total(self):
        rows = self.load(HEADER, "c1,2026-11-20,openai,k,before,m,1,10,0,1,0.01",
                         "c1,2026-11-21,openai,k,after,m,1,10,0,1,0.01",
                         "c1,2026-11-20,anthropic,k2,after,m2,1,10,0,1,")
        kept, hidden = usage.by_arm(rows)
        self.assertEqual(hidden, {("c1", "openai"): "key k carries after, before"})
        self.assertEqual([r["provider"] for r in kept], ["anthropic"])

    def test_a_key_day_and_model_twice_is_refused(self):
        row = "c1,2026-11-20,openai,k,after,m,1,10,0,1,0.01"
        why = r"usage\.csv:3: openai key k on 2026-11-20 for m is line 2's already, campaign c1"
        for again in (row, "c2,2026-11-20,openai,k,after,m,1,10,0,1,0.01"):
            with self.subTest(again=again), self.assertRaisesRegex(usage.UsageError, why):
                self.load(HEADER, row, again)
        self.assertEqual(len(self.load(HEADER, row, "c1,2026-11-20,openai,k,after,m2,1,10,0,1,0.01")), 2)

    def test_refused_rows(self):
        for bad in ("c1,2026-11-20,openai,k,both,m,1,1,1,1,1", "c1,20/11/2026,openai,k,,m,1,1,1,1,1",
                    "c1,2026-11-20,openai,k,,m,-1,1,1,1,1", "c1,2026-11-20,openai,k,,m,x,1,1,1,1",
                    "c1,2026-11-20,,k,,m,1,1,1,1,1", ",2026-11-20,openai,k,,m,1,1,1,1,1",
                    "c1,2026-11-20,openai,k,,m,nan,1,1,1,1", "c1,2026-11-20,openai,k,,m,1,inf,1,1,1"):
            with self.subTest(row=bad), self.assertRaises(usage.UsageError):
                self.load(HEADER, bad)
        with self.assertRaises(usage.UsageError):
            self.load("day,provider,key,model,usd", "2026-11-20,openai,k,m,1")


if __name__ == "__main__":
    unittest.main()
