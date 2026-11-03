#!/usr/bin/env python3
"""UK IAM Hunter manual-review and weekly transparency digests.

This is not a replacement for strictly verified NEW vacancy alerts.
'Needs Manual Check' contains uncertain employer/ATS matches, not confirmed
live vacancies; it never enters the verified-delivery state.
"""
from __future__ import annotations

import csv
import html
import os
import sys
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse

from send_email import (
    BLOCKED_EMAIL_DOMAINS, UK_TZ, email_rejection_reasons,
    live_application_page, require_env, send_report
)

RESULTS_FILE = Path(os.getenv("IAM_REVIEW_RESULTS_FILE", "uk_iam_results.csv"))
AUDIT_FILE = Path(os.getenv("IAM_REVIEW_AUDIT_FILE", "uk_iam_source_audit.csv"))
MAX_REVIEW = 12
MAX_VERIFIED = 8


def read_rows(path: Path):
    if not path.exists():
        raise FileNotFoundError(str(path))
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _parse_date(value):
    value = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


def review_candidate(job, reasons, now=None):
    """Never turn uncertain records into claimed verified vacancies."""
    now = now or datetime.now(timezone.utc)
    if not reasons:
        return False
    # Fail closed for missing/ambiguous geography. A confirmed UK city,
    # town, region, GB/UK designation or job-specific UK-remote location
    # is required. A generic "remote" or unlocated post is not enough.
    from uk_iam_hunter import contains_uk_location, is_placeholder_location
    location = str(job.get("location", "") or "").strip()
    if str(job.get("location_status", "")).upper() != "UK CONFIRMED":
        return False
    if (not location or is_placeholder_location(location)
            or location.lower() == "united kingdom (confirmed)"
            or not contains_uk_location(location)):
        return False
    if str(job.get("match_type", "")).upper() != "CORE IAM":
        return False
    try:
        if float(job.get("match_score") or 0) < 85:
            return False
    except (TypeError, ValueError):
        return False
    employment = str(job.get("employment_type", "")).lower()
    if any(t in employment for t in ("contract", "fixed", "temporary", "freelance", "interim")):
        return False
    url = str(job.get("url") or "").strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    hostname = parsed.hostname.lower()
    if any(hostname == blocked or hostname.endswith("." + blocked) for blocked in BLOCKED_EMAIL_DOMAINS):
        return False
    if not job.get("company") or str(job.get("company")).lower() in ("unknown", "discovered employer"):
        return False
    posted = _parse_date(job.get("date_posted"))
    if posted and (now - posted.astimezone(timezone.utc)) > timedelta(days=45):
        return False
    # If the employer omitted posting date, require recent first observation
    # (this is discovery recency, NOT proof of datePosted or of a live vacancy).
    if not posted:
        first_seen = _parse_date(job.get("first_seen") or job.get("discovered_at"))
        if not first_seen or (now - first_seen.astimezone(timezone.utc)) > timedelta(days=14):
            return False
    return True


def generate_digest(rows, source_audit=None, check_live=False):
    """Return result counts and review candidates, without changing state."""
    counts = Counter()
    verified, review = [], []
    for job in rows:
        reasons = email_rejection_reasons(job)
        for reason in reasons:
            counts[reason] += 1
        if not reasons:
            if not check_live or live_application_page(job):
                verified.append(job)
            else:
                counts["final live application check failed"] += 1
        elif review_candidate(job, reasons):
            review.append((job, reasons))
    audit_rejections = 0
    for row in (source_audit or []):
        try:
            audit_rejections += int(row.get("rejected") or 0)
        except ValueError:
            pass
    return verified[:MAX_VERIFIED], review[:MAX_REVIEW], counts, audit_rejections


def build_html(verified, review, reasons, audit_rejections, daily=False):
    esc = lambda value: html.escape(str(value or ""), quote=True)
    def section(items, with_reasons):
        if not items:
            return "<p>None.</p>"
        parts = ["<ul>"]
        for item in items:
            job, why = item if with_reasons else (item, [])
            url = str(job.get("url") or "")
            label = esc(f"{job.get('company', 'Employer')} — {job.get('title', 'Vacancy')}")
            link = f'<a href="{esc(url)}">{label}</a>' if url.startswith("https://") else label
            detail = esc(job.get("location", "Location not specified"))
            if why:
                detail += "; CHECK: " + esc("; ".join(why[:4]))
            parts.append(f"<li>{link} — {detail}</li>")
        return "".join(parts) + "</ul>"
    stats = "".join(
        f"<li>{esc(reason)}: {count}</li>"
        for reason, count in reasons.most_common(10)
    ) or "<li>No recorded eligibility failures.</li>"
    return (
        "<html><body style='font-family:Arial,sans-serif;max-width:820px'>"
        ("<h2>UK IAM Hunter — Daily Needs Manual Check</h2>" if daily else
         "<h2>UK IAM Hunter — Weekly Discovery & Review</h2>")
        ("<p><strong>Daily unverified job review, not a verified vacancy alert.</strong> " if daily
         else "<p><strong>Weekly status digest, not a new-vacancy alert.</strong> ")
        "A listing under Needs Manual Check is NOT confirmed permanent, current, "
        "or application-open. Check the official employer vacancy before applying.</p>"
        f"<p>Current audit: {len(verified)} displayed verified matches; "
        f"{len(review)} displayed unverified matches; {audit_rejections} source-level rejections.</p>"
        + ("" if daily else "<h3>Verified Matches (current evidence; may already have been emailed)</h3>"
           + section(verified, False))
        + "<h3>Needs Manual Check (unverified — never included in verified alerts)</h3>"
        + section(review, True)
        + "<h3>Verification failure counts across current results</h3><ul>"
        + stats + "</ul>"
        "<p>Counts describe the current scan, not the whole UK job market. "
        "A vacancy may have more than one reason for rejection.</p>"
        "</body></html>"
    )


def main():
    rows = read_rows(RESULTS_FILE)
    audit = read_rows(AUDIT_FILE) if AUDIT_FILE.exists() else []
    verified, review, reasons, rejects = generate_digest(
        rows, audit, check_live="--audit-only" not in sys.argv
    )
    print(
        f"REVIEW DIGEST | results={len(rows)} | verified={len(verified)} | "
        f"needs_manual_check={len(review)} | source_rejected={rejects} | "
        f"reason_counts={dict(reasons.most_common(10))}"
    )
    if "--audit-only" in sys.argv:
        return
    daily = "--daily" in sys.argv
    if daily and not review:
        print("DAILY REVIEW | no UK-confirmed high-confidence unverified IAM roles; email not sent")
        return
    payload = {
        "sender": {"name": "UK IAM Hunter Review", "email": require_env("BREVO_SENDER_EMAIL")},
        "to": [{"email": require_env("REPORT_EMAIL")}],
        "subject": ("UK IAM Hunter — Daily Needs Manual Check" if daily
                    else "UK IAM Hunter — Weekly Discovery & Needs Review"),
        "htmlContent": build_html(verified, review, reasons, rejects, daily=daily),
        "tags": ["uk-iam-daily-review" if daily else "uk-iam-weekly-review"],
    }
    ident = send_report(require_env("BREVO_API_KEY"), payload)
    print(f"{'Daily' if daily else 'Weekly'} review digest accepted by Brevo: {ident}")


if __name__ == "__main__":
    main()
