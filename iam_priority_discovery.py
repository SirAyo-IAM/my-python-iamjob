#!/usr/bin/env python3
"""Supplemental official-source discovery for UK IAM Hunter V5.4.

This module is intentionally small and conservative. It closes source-coverage
holes observed in live Hunter runs without replacing the main engine.

It:
- checks a small set of high-value official/ATS job URLs that the main crawler
  has previously missed;
- searches selected official career domains for fresh IAM/PAM/IGA roles;
- reuses uk_iam_hunter.py validation, UK-only filtering, permanent-only rules,
  closed-vacancy rejection, scoring, and persistent NEW/SEEN state;
- merges only validated results into the existing V5.4 CSV/JSON outputs.

Google Apps Script is deliberately untouched.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List

import uk_iam_hunter as hunter


# Regression seeds are employer or recruiter career pages discovered manually
# or by an independent fresh web check. Every page is still passed through the
# main hunter's strict UK/permanent/relevance validation before it is retained.
DIRECT_JOB_SEEDS = [
    # Fresh September 2026 misses.
    "https://sainsburys.jobs/jobs/description/400057178",
    "https://www.sainsburys.jobs/jobs/description/400057342",
    "https://jobs.coop.co.uk/job/manchester/principal-security-architect-iam/22964/100062143088",
    "https://apply.hollandandbarrettjobs.com/jobs/vacancy/idam-security-manager-38872-london/38851/description/",
    "https://careers.medicalprotection.org/jobs/job/Identity-and-Access-Management-Lead/2162",
    "https://www.83zero.com/jobs/625203-IAM-Delivery-Consultant/",

    # User-provided regression cases / platform families.
    "https://careers.astonmartin.com/mob/en/job/512173/identity-and-access-management-specialist",
    "https://jobs.ashbyhq.com/allica-bank/cbc13a4d-2bc2-4e92-b4a1-c31284b894fc/application",
    "https://cgi.njoyn.com/corp/xweb/xweb.asp?clid=21001&page=jobdetails&jobid=J0526-1965&BRID=1304115&SBDID=943&lang=1",
    "https://www.fruitiongroup.com/job/iam-platform-manager-2035/",
    "https://fa-evdq-saasfaprod1.fa.ocs.oraclecloud.com/hcmUI/CandidateExperience/en/sites/CX_2001/job/11708",
]


# Some enterprise career platforms can serve stale JobPosting markup even after
# the canonical vacancy page says the role has been filled. These exact known
# closed vacancies are excluded before parsing so stale markup cannot re-enter
# the current-results file.
KNOWN_CLOSED_URL_FRAGMENTS = [
    "careers.givaudan.com/global/en/job/119132/",
    "careers.givaudan.com/global/en/job/givgivgb119132externalenglobal/",
    "careers.givaudan.com/br/pt/job/119132/",
]


# Domain sweeps complement the main generic queries. They target employers and
# ATS families that repeatedly expose relevant UK IAM roles but are not reliably
# surfaced by broad Bing/DDG queries from GitHub-hosted runners.
PRIORITY_OFFICIAL_QUERIES = [
    'site:sainsburys.jobs/jobs/description (IAM OR "Identity and Access Management" OR "Privileged Access Management")',
    'site:jobs.coop.co.uk/job (IAM OR "Identity and Access" OR "Identity Security")',
    'site:apply.hollandandbarrettjobs.com/jobs/vacancy (IAM OR IDAM OR "Identity and Access")',
    'site:careers.medicalprotection.org/jobs/job (IAM OR "Identity and Access Management" OR SailPoint OR Delinea)',
    'site:83zero.com/jobs (IAM OR "Identity and Access" OR SailPoint OR Saviynt OR CyberArk)',
    'site:careers.astonmartin.com (IAM OR "Identity and Access Management")',
    'site:jobs.ashbyhq.com/allica-bank (IAM OR "Identity and Access" OR "Identity Security")',
    'site:cgi.njoyn.com (IAM OR SailPoint OR CyberArk OR "Identity and Access")',
    'site:oraclecloud.com/hcmUI/CandidateExperience (IAM OR "Identity and Access Management" OR SailPoint OR CyberArk) "United Kingdom"',
    'site:lloydsbankinggroup.com/careers (IAM OR "Identity and Access" OR "Identity Security")',
    'site:jobs.lloydsbankinggroup.com (IAM OR "Identity and Access" OR SailPoint OR CyberArk)',
]


def is_known_closed_url(url: str) -> bool:
    low = hunter.normalise_url(url).lower()
    return any(fragment in low for fragment in KNOWN_CLOSED_URL_FRAGMENTS)


def read_csv(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_json_results(path: Path, results: List[Dict[str, Any]], count_key: str) -> None:
    payload: Dict[str, Any] = {}
    if path.exists():
        try:
            with path.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
            if isinstance(raw, dict):
                payload = raw
        except Exception:
            payload = {}

    payload["results"] = results
    payload[count_key] = len(results)
    if count_key == "new_or_updated_count":
        payload["new_or_updated_count"] = len(results)
    else:
        payload["matches"] = len(results)
        payload["match_count"] = len(results)

    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def discover() -> List[Dict[str, Any]]:
    candidates: List[str] = list(DIRECT_JOB_SEEDS)
    session = hunter.make_session()

    for query in PRIORITY_OFFICIAL_QUERIES:
        try:
            fresh_query = f"{query} {hunter.RECENT_SEARCH_HINT}".strip()
            found = hunter.search_urls(session, fresh_query)
            if not found:
                found = hunter.search_urls(session, query)
            candidates.extend(found)
        except Exception:
            continue

    # Stable URL de-duplication before network fetches.
    unique_urls: List[str] = []
    seen = set()
    for value in candidates:
        value = hunter.normalise_url(value)
        if is_known_closed_url(value):
            continue
        key = hunter.canonical_url(value)
        if not key or key in seen:
            continue
        seen.add(key)
        unique_urls.append(value)

    results: List[Dict[str, Any]] = []
    for url in unique_urls:
        try:
            results.extend(
                hunter.extract_results_from_candidate(
                    url,
                    method="V5.4 priority official discovery",
                )
            )
        except Exception:
            continue

    return hunter.deduplicate(
        job for job in results
        if not is_known_closed_url(str(job.get("url", "")))
    )


def main() -> None:
    full_path = Path(hunter.CSV_FILE)
    new_path = Path(hunter.NEW_CSV_FILE)

    # Remove exact known stale/closed rows from the current run as an additional
    # safeguard before supplementing it.
    current = [
        job for job in read_csv(full_path)
        if not is_known_closed_url(str(job.get("url", "")))
    ]
    current_notifications = [
        job for job in read_csv(new_path)
        if not is_known_closed_url(str(job.get("url", "")))
    ]
    supplemental = discover()

    # Identify only jobs not already present in this run's full result set.
    existing_ids = {hunter.job_state_identity(job) for job in current}
    additions = [
        job for job in supplemental
        if hunter.job_state_identity(job) not in existing_ids
    ]

    if additions:
        classified_additions, notifications, stats = hunter.classify_new_jobs(additions)
    else:
        classified_additions, notifications = [], []
        stats = {"new": 0, "updated": 0, "seen": 0, "notify": 0, "state_total": 0}

    merged_full = hunter.deduplicate(current + classified_additions)
    merged_notifications = hunter.deduplicate(current_notifications + notifications)

    hunter.write_csv(hunter.CSV_FILE, merged_full, hunter.RESULT_FIELDS)
    hunter.write_csv(hunter.NEW_CSV_FILE, merged_notifications, hunter.RESULT_FIELDS)

    write_json_results(Path(hunter.JSON_FILE), merged_full, "match_count")
    write_json_results(Path(hunter.NEW_JSON_FILE), merged_notifications, "new_or_updated_count")

    print(
        "Priority official discovery: "
        f"validated={len(supplemental)} | "
        f"added_to_current={len(classified_additions)} | "
        f"email_candidates={len(notifications)} | "
        f"new={stats.get('new', 0)} | "
        f"updated={stats.get('updated', 0)}"
    )


if __name__ == "__main__":
    main()
