"""The measured cost: the providers' usage exports, by day, key and model, copied into one CSV.

vens records no provider usage at either measured commit, so the exports are the only measured source. Each
provider's console exports usage by day and key; the rows are copied as exported into:

    day,provider,key,arm,model,requests,input_tokens,cached_input_tokens,output_tokens,usd
    2026-11-20,openai,key-after,after,gpt-5.4-mini-2026-03-17,694,1250000,0,61000,0.42

day is the UTC day (YYYY-MM-DD); arm is before or after for a key one arm used alone, empty for a key shared with
other runs, whose rows count in the campaign's total only; an empty number is one the export does not give (an
Anthropic export gives tokens, not dollars), never 0. Per arm totals exist only with a key per arm and provider. The
CSV holds key names, never key values; the exports themselves stay outside the repository.
"""
import collections
import csv
import re

FIELDS = ("day", "provider", "key", "arm", "model", "requests", "input_tokens", "cached_input_tokens",
          "output_tokens", "usd")
NUMBERS = FIELDS[5:]
ARMS = ("before", "after", "")
_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")


class UsageError(Exception):
    pass


def _number(text, where):
    if text is None or text.strip() == "":
        return None
    try:
        value = float(text)
    except ValueError as e:
        raise UsageError(f"{where}: {text!r} is not a number") from e
    if value < 0:
        raise UsageError(f"{where}: {text!r} is negative")
    return value


def load(path):
    """The rows, each checked: a day, a provider, a key, an arm or none, a model, numbers or empty."""
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise UsageError(f"{path}: its header is not {','.join(FIELDS)}")
        rows = []
        for n, row in enumerate(reader, 2):
            where = f"{path}:{n}"
            if not _DAY.fullmatch(row["day"] or "") or not row["provider"] or not row["key"] or not row["model"]:
                raise UsageError(f"{where}: a row needs a day (YYYY-MM-DD), a provider, a key and a model")
            if row["arm"] not in ARMS:
                raise UsageError(f"{where}: arm {row['arm']!r}, not before, after or empty")
            rows.append({**{k: row[k] for k in FIELDS[:5]}, **{k: _number(row[k], where) for k in NUMBERS}})
    return rows


def totals(rows, by):
    """{key: {field: sum, or None when a row lacks it; "rows": n; "days": [...]}} grouped by the fields in by."""
    out = collections.OrderedDict()
    for row in sorted(rows, key=lambda r: tuple(r[f] for f in by) + (r["day"],)):
        k = tuple(row[f] for f in by)
        t = out.setdefault(k, {**{f: 0.0 for f in NUMBERS}, "rows": 0, "days": []})
        t["rows"] += 1
        if row["day"] not in t["days"]:
            t["days"].append(row["day"])
        for f in NUMBERS:
            t[f] = None if t[f] is None or row[f] is None else t[f] + row[f]
    return dict(out)
