#!/usr/bin/env python3
"""
Email UK IAM Job Hunter V5.3 results through Brevo.

Required environment variables:
    BREVO_API_KEY
    REPORT_EMAIL
    BREVO_SENDER_EMAIL

Expected input:
    uk_iam_results.csv
"""

from __future__ import annotations

import csv
import html
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import requests


RESULT_CSV = Path("uk_iam_results.csv")
BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"
REQUEST_TIMEOUT = 30
MAX_EMAIL_ROWS = 100


def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(
            f"Required environment variable {name} is missing or empty."
        )
    return value


def read_jobs(path: Path = RESULT_CSV) -> List[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} was not found. Run uk_iam_hunter.py before send_email.py."
        )

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return [
            {
                str(key): str(value or "").strip()
                for key, value in row.items()
                if key is not None
            }
            for row in reader
        ]


def safe(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def build_html(jobs: List[Dict[str, str]]) -> str:
    generated = datetime.now(timezone.utc).strftime("%d %B %Y %H:%M UTC")

    core_count = sum(
        1 for job in jobs if job.get("match_type", "").strip().upper() == "CORE IAM"
    )
    adjacent_count = sum(
        1 for job in jobs
        if job.get("match_type", "").strip().upper() == "ADJACENT IDENTITY/SECURITY"
    )

    if not jobs:
        rows = """
        <tr>
          <td colspan="12" style="padding:16px;text-align:center;">
            No matching UK IAM/PAM vacancies were found in this run.
          </td>
        </tr>
        """
    else:
        rendered_rows = []

        for job in jobs[:MAX_EMAIL_ROWS]:
            url = job.get("url") or job.get("canonical_url") or ""
            title = safe(job.get("title", ""))
            company = safe(job.get("company", ""))
            location = safe(job.get("location", ""))
            location_status = safe(job.get("location_status", ""))
            work = safe(job.get("working_arrangement", ""))
            employment = safe(job.get("employment_type", ""))
            salary = safe(job.get("salary", ""))
            posted = safe(job.get("date_posted", ""))
            match_type = safe(job.get("match_type", ""))
            score = safe(job.get("match_score", ""))
            confidence = safe(job.get("confidence", ""))
            keywords = safe(job.get("matched_keywords", ""))

            if url:
                role = (
                    f'<a href="{safe(url)}" '
                    f'style="color:#0b57d0;text-decoration:none;">'
                    f"{title or 'View job'}</a>"
                )
            else:
                role = title

            rendered_rows.append(
                f"""
                <tr>
                  <td>{company}</td>
                  <td>{role}</td>
                  <td>{match_type}</td>
                  <td>{score}</td>
                  <td>{confidence}</td>
                  <td>{location}</td>
                  <td>{location_status}</td>
                  <td>{work}</td>
                  <td>{employment}</td>
                  <td>{salary}</td>
                  <td>{posted}</td>
                  <td>{keywords}</td>
                </tr>
                """
            )

        rows = "\n".join(rendered_rows)

    extra_note = ""
    if len(jobs) > MAX_EMAIL_ROWS:
        extra_note = (
            f"<p>Showing the first {MAX_EMAIL_ROWS} of "
            f"{len(jobs)} results. The full result set is available "
            "in the GitHub Actions artifact.</p>"
        )

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>UK IAM Job Hunter V5.3</title>
</head>
<body style="font-family:Arial,Helvetica,sans-serif;color:#202124;">
  <div style="max-width:1400px;margin:0 auto;">
    <h2 style="margin-bottom:6px;">UK IAM / PAM Job Hunter V5.3</h2>
    <p style="margin-top:0;">
      <strong>{len(jobs)}</strong> matching job(s) found.<br>
      Core IAM: <strong>{core_count}</strong> &nbsp;|&nbsp;
      Adjacent identity/security: <strong>{adjacent_count}</strong><br>
      Report generated: {safe(generated)}
    </p>

    {extra_note}

    <div style="overflow-x:auto;">
      <table
        cellpadding="0"
        cellspacing="0"
        style="border-collapse:collapse;width:100%;font-size:12px;"
      >
        <thead>
          <tr>
            <th style="text-align:left;padding:8px;border:1px solid #ddd;">Company</th>
            <th style="text-align:left;padding:8px;border:1px solid #ddd;">Role</th>
            <th style="text-align:left;padding:8px;border:1px solid #ddd;">Match Type</th>
            <th style="text-align:left;padding:8px;border:1px solid #ddd;">Score</th>
            <th style="text-align:left;padding:8px;border:1px solid #ddd;">Confidence</th>
            <th style="text-align:left;padding:8px;border:1px solid #ddd;">Location</th>
            <th style="text-align:left;padding:8px;border:1px solid #ddd;">UK Status</th>
            <th style="text-align:left;padding:8px;border:1px solid #ddd;">Work</th>
            <th style="text-align:left;padding:8px;border:1px solid #ddd;">Employment</th>
            <th style="text-align:left;padding:8px;border:1px solid #ddd;">Salary</th>
            <th style="text-align:left;padding:8px;border:1px solid #ddd;">Posted</th>
            <th style="text-align:left;padding:8px;border:1px solid #ddd;">IAM signals</th>
          </tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </div>

    <p style="margin-top:20px;font-size:12px;color:#666;">
      Generated automatically by UK IAM / PAM Job Hunter V5.3.
    </p>
  </div>
</body>
</html>
"""


def build_payload(
    jobs: List[Dict[str, str]],
    sender_email: str,
    recipient_email: str,
) -> Dict[str, object]:
    today = datetime.now(timezone.utc).strftime("%d %b %Y")

    return {
        "sender": {
            "name": "UK IAM Job Hunter",
            "email": sender_email,
        },
        "to": [
            {
                "email": recipient_email,
            }
        ],
        "subject": f"UK IAM Job Hunter V5.3 - {len(jobs)} match(es) - {today}",
        "htmlContent": build_html(jobs),
        "tags": ["uk-iam-job-hunter-v5-3"],
    }


def send_report(
    api_key: str,
    payload: Dict[str, object],
) -> str:
    response = requests.post(
        BREVO_ENDPOINT,
        headers={
            "accept": "application/json",
            "api-key": api_key,
            "content-type": "application/json",
        },
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code != 201:
        body = response.text.strip()
        if len(body) > 1000:
            body = body[:1000] + "..."
        raise RuntimeError(
            f"Brevo returned HTTP {response.status_code}: {body}"
        )

    try:
        data = response.json()
    except ValueError:
        data = {}

    return str(data.get("messageId", "")).strip()


def main() -> None:
    api_key = require_env("BREVO_API_KEY")
    report_email = require_env("REPORT_EMAIL")
    sender_email = require_env("BREVO_SENDER_EMAIL")

    jobs = read_jobs()
    payload = build_payload(
        jobs=jobs,
        sender_email=sender_email,
        recipient_email=report_email,
    )

    print(f"Preparing IAM job email with {len(jobs)} result(s)...")

    message_id = send_report(
        api_key=api_key,
        payload=payload,
    )

    if message_id:
        print(f"Email sent successfully. Brevo message ID: {message_id}")
    else:
        print("Email sent successfully.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
