#!/usr/bin/env python3
"""Send one daily UK IAM digest set after ANY completed scheduled scan.

GitHub schedule events may be delayed or one cron entry may be dropped.
The first successfully completed schedule run per Europe/London calendar day
sends verified jobs and the independently-labelled needs-review email.
A state marker is written only after both commands complete successfully.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

UK_ZONE = ZoneInfo("Europe/London")
STATE_DIR = Path(os.getenv("IAM_STATE_DIR", ".iam_state"))
MARKER = STATE_DIR / "daily_digest_delivery.json"


def run():
    today = datetime.now(UK_ZONE).date().isoformat()
    if MARKER.exists():
        try:
            state = json.loads(MARKER.read_text(encoding="utf-8"))
            if state.get("delivered_uk_date") == today:
                print(f"DAILY DIGEST | already successfully processed {today}; suppress repeat")
                return
        except (ValueError, OSError):
            print("DAILY DIGEST | invalid marker; retrying rather than skipping")

    env = dict(os.environ)
    env["IAM_EMAIL_RESULTS_FILE"] = "uk_iam_results.csv"
    # Notify only when verified roles exist, but always attempt the independent
    # manual-check email. A failed Brevo request stops the workflow and retries.
    subprocess.run([sys.executable, "send_email.py"], check=True, env=env)
    subprocess.run([sys.executable, "iam_review_digest.py", "--daily"], check=True, env=env)

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    temporary = MARKER.with_suffix(".tmp")
    temporary.write_text(json.dumps({
        "delivered_uk_date": today,
        "completed_at": datetime.now(UK_ZONE).isoformat(),
    }, indent=2), encoding="utf-8")
    temporary.replace(MARKER)
    print(f"DAILY DIGEST | completed delivery set for UK date {today}")


if __name__ == "__main__":
    run()
