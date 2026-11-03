#!/usr/bin/env python3
"""Safe, targeted repair of historical unverified vacancy notification state.

Do NOT purge all 'seen' jobs: historic delivered emails cannot reliably be
reconstructed from cache. Only reopen jobs that are currently still missing
required evidence and were first recorded in the specified incident window.
"""
from __future__ import annotations
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from send_email import email_rejection_reasons

STATE = Path(os.getenv("IAM_SEEN_STATE_FILE", ".iam_state/seen_jobs.json"))
RESULTS = Path(os.getenv("IAM_RESULTS_FILE", "uk_iam_results.csv"))
START = datetime(2026, 10, 23, tzinfo=timezone.utc)
END = datetime(2026, 11, 3, tzinfo=timezone.utc)


def repair(state, rows):
    from uk_iam_hunter import job_state_identity
    records = state.get("jobs", {})
    if not isinstance(records, dict):
        raise ValueError("Invalid seen-job state")
    changed, skipped = [], 0
    for row in rows:
        key = str(row.get("state_id") or "") or job_state_identity(row)
        record = records.get(key)
        if not isinstance(record, dict):
            continue
        if record.get("notification_pending") or record.get("notification_sent_at"):
            continue
        date_value = str(record.get("first_seen") or "")
        try:
            seen = datetime.fromisoformat(date_value.replace("Z", "+00:00"))
            if seen.tzinfo is None:
                seen = seen.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if not START <= seen.astimezone(timezone.utc) < END:
            continue
        reasons = email_rejection_reasons(row)
        if not reasons:
            # The record might already have been emailed before sent_at existed;
            # never re-arm a previously eligible vacancy with uncertain history.
            skipped += 1
            continue
        # Reopen only missing-evidence false negatives, not definite
        # non-permanent, foreign-only, stale, irrelevant or blocked listings.
        admissible = {
            "permanent employment not evidenced",
            "original posting date missing and no verified upcoming closing date",
            "substantive job description not verified",
        }
        if not reasons or any(reason not in admissible for reason in reasons):
            skipped += 1
            continue
        record["notification_pending"] = True
        record["notification_reopened_reason"] = "historical incomplete-evidence case"
        changed.append(key)
    return changed, skipped


def main():
    if not STATE.exists() or not RESULTS.exists():
        print("STATE RECONCILE | state/results absent; no changes")
        return
    with STATE.open(encoding="utf-8") as handle:
        state = json.load(handle)
    with RESULTS.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    changed, skipped = repair(state, rows)
    print(f"STATE RECONCILE | reopened_missing_evidence={len(changed)} | skipped={skipped}")
    if "--audit-only" in sys.argv or not changed:
        return
    temporary = STATE.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, ensure_ascii=False, sort_keys=True)
    os.replace(temporary, STATE)


if __name__ == "__main__":
    main()
