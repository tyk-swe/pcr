#!/usr/bin/env python3
import datetime as dt
import json
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: verify-qualification.py WORKFLOW_RUNS.json")

with open(sys.argv[1], encoding="utf-8") as source:
    payload = json.load(source)

days = set()
for run in payload.get("workflow_runs", []):
    if run.get("conclusion") != "success":
        continue
    if run.get("event") not in {"schedule", "workflow_dispatch"}:
        continue
    created = run.get("created_at", "")
    try:
        days.add(dt.datetime.fromisoformat(created.replace("Z", "+00:00")).date())
    except ValueError:
        continue

today = dt.datetime.now(dt.timezone.utc).date()
eligible_ends = [today, today - dt.timedelta(days=1)]
for end in eligible_ends:
    expected = {end - dt.timedelta(days=offset) for offset in range(30)}
    if expected <= days:
        print(f"qualification has 30 consecutive successful UTC days through {end}")
        break
else:
    ordered = sorted(days, reverse=True)[:30]
    raise SystemExit(
        "qualification does not have 30 consecutive successful UTC days; "
        f"most recent successful days: {', '.join(map(str, ordered))}"
    )
