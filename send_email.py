#!/usr/bin/env python3
"""Email UK IAM Job Hunter V5.4 results through Brevo."""
from __future__ import annotations
import csv, html, os, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse
import requests

RESULT_CSV = Path(os.getenv("IAM_EMAIL_RESULTS_FILE", "uk_iam_new_results.csv"))
BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"
REQUEST_TIMEOUT = 30
MAX_EMAIL_ROWS = 100
CV_GENERAL = "Identity & Access Administrator"
CV_OPERATIONAL = "Operational IAM Engineer"
CV_PAM = "Identity & Privileged Access Engineer"
CV_SAILPOINT = "SailPoint IdentityIQ Engineer"
CV_OKTA = "IAM Engineer - Okta / SSO / CIAM"

# Last-line notification guard. Discovery remains authoritative, but the email
# must not advertise known aggregators, clearly non-IAM roles, or obviously
# foreign vacancies accidentally labelled UK-confirmed upstream.
BLOCKED_EMAIL_DOMAINS = {
    "dreamworkhq.com", "jobsinuk.app", "vercida.com", "jobtoday.com",
    "linkedin.com", "indeed.com", "reed.co.uk", "totaljobs.com",
    "cv-library.co.uk", "glassdoor.com",
}
NON_IAM_TITLE_TERMS = (
    "product marketing", "marketing manager", "sales engineer",
    "customer success manager", "cloud operations engineer",
    "cyber security jobs", "technology jobs", "create job alerts",
)
UK_LOCATION_TERMS = (
    "united kingdom", " uk", "uk ", "england", "scotland", "wales",
    "northern ireland", "london", "manchester", "birmingham", "edinburgh",
    "glasgow", "bristol", "leeds", "reading", "cardiff", "belfast",
)
CLEAR_FOREIGN_LOCATION_TERMS = (
    "canada", "metro vancouver", "united states", " usa", "u.s.",
    "australia", "india", "singapore", "germany", "france", "spain",
    "netherlands", "ireland", "czechia", "poland", "romania",
)

def recommend_cv(job: Dict[str, str]) -> str:
    haystack = " ".join(str(job.get(f, "") or "") for f in ("title", "matched_keywords", "match_type", "description")).lower()
    if any(t in haystack for t in ("sailpoint", "identityiq", "identity iq", "identitynow", "identity security cloud")): return CV_SAILPOINT
    if any(t in haystack for t in ("okta", "ciam", "customer identity", "auth0")): return CV_OKTA
    if any(t in haystack for t in ("cyberark", "beyondtrust", "delinea", "privileged access management", "pam engineer", "pam analyst", "privileged identity")): return CV_PAM
    if any(t in haystack for t in ("entra id", "microsoft entra", "azure ad", "azure active directory", "conditional access", "azure ad connect", "microsoft graph")): return CV_OPERATIONAL
    return CV_GENERAL

def email_worthy(job: Dict[str, str]) -> bool:
    title = str(job.get("title", "") or "").strip().lower()
    if any(term in title for term in NON_IAM_TITLE_TERMS): return False
    url = str(job.get("url") or job.get("canonical_url") or "").strip()
    host = (urlparse(url).hostname or "").lower()
    if any(host == d or host.endswith("." + d) for d in BLOCKED_EMAIL_DOMAINS): return False
    location = " " + str(job.get("location", "") or "").strip().lower() + " "
    # Preserve legitimate multi-country adverts when they explicitly include a
    # UK location, but suppress unmistakably foreign-only locations. This is a
    # notification safety net; the Hunter remains responsible for classification.
    has_uk = any(term in location for term in UK_LOCATION_TERMS)
    has_foreign = any(term in location for term in CLEAR_FOREIGN_LOCATION_TERMS)
    if has_foreign and not has_uk: return False
    return True

def require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value: raise RuntimeError(f"Required environment variable {name} is missing or empty.")
    return value

def read_jobs(path: Path = RESULT_CSV) -> List[Dict[str, str]]:
    if not path.exists(): raise FileNotFoundError(f"{path} was not found. Run uk_iam_hunter.py before send_email.py.")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [{str(k): str(v or "").strip() for k, v in row.items() if k is not None} for row in csv.DictReader(handle)]

def safe(value: object) -> str: return html.escape(str(value or ""), quote=True)

def build_html(jobs: List[Dict[str, str]]) -> str:
    generated = datetime.now(timezone.utc).strftime("%d %B %Y %H:%M UTC")
    core_count = sum(1 for j in jobs if j.get("match_type", "").strip().upper() == "CORE IAM")
    adjacent_count = sum(1 for j in jobs if j.get("match_type", "").strip().upper() == "ADJACENT IDENTITY/SECURITY")
    rendered_rows=[]
    for job in jobs[:MAX_EMAIL_ROWS]:
        url=job.get("url") or job.get("canonical_url") or ""; title=safe(job.get("title", "")); company=safe(job.get("company", ""))
        role=f'<a href="{safe(url)}" style="color:#0b57d0;text-decoration:none;">{title or "View job"}</a>' if url else title
        vals=[company,role,safe(job.get("notification_status","NEW")),safe(job.get("match_type","")),safe(job.get("match_score","")),safe(job.get("confidence","")),safe(job.get("location","")),safe(job.get("location_status","")),safe(job.get("working_arrangement","")),safe(job.get("employment_type","")),safe(job.get("salary","")),safe(job.get("date_posted","")),safe(recommend_cv(job)),safe(job.get("matched_keywords",""))]
        rendered_rows.append("<tr>"+"".join(f"<td>{v}</td>" for v in vals)+"</tr>")
    rows="\n".join(rendered_rows)
    return f'''<!doctype html><html><head><meta charset="utf-8"><title>UK IAM Job Hunter V5.4</title></head><body style="font-family:Arial,Helvetica,sans-serif;color:#202124;"><div style="max-width:1400px;margin:0 auto;"><h2>UK IAM / PAM Job Hunter V5.4</h2><p><strong>{len(jobs)}</strong> NEW/UPDATED job(s) found.<br>Core IAM: <strong>{core_count}</strong> | Adjacent identity/security: <strong>{adjacent_count}</strong><br>Report generated: {safe(generated)}</p><div style="overflow-x:auto;"><table cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%;font-size:12px;"><thead><tr>{''.join(f'<th style="text-align:left;padding:8px;border:1px solid #ddd;">{h}</th>' for h in ['Company','Role','Status','Match Type','Score','Confidence','Location','UK Status','Work','Employment','Salary','Posted','Recommended CV','IAM signals'])}</tr></thead><tbody>{rows}</tbody></table></div><p style="margin-top:20px;font-size:12px;color:#666;">Generated automatically by UK IAM / PAM Job Hunter V5.4.</p></div></body></html>'''

def build_payload(jobs: List[Dict[str,str]], sender_email: str, recipient_email: str) -> Dict[str,object]:
    today=datetime.now(timezone.utc).strftime("%d %b %Y")
    return {"sender":{"name":"UK IAM Job Hunter","email":sender_email},"to":[{"email":recipient_email}],"subject":f"UK IAM Hunter V5.4 - {len(jobs)} NEW/UPDATED role(s) - {today}","htmlContent":build_html(jobs),"tags":["uk-iam-job-hunter-v5-4"]}

def send_report(api_key: str, payload: Dict[str,object]) -> str:
    response=requests.post(BREVO_ENDPOINT,headers={"accept":"application/json","api-key":api_key,"content-type":"application/json"},json=payload,timeout=REQUEST_TIMEOUT)
    if response.status_code != 201: raise RuntimeError(f"Brevo returned HTTP {response.status_code}: {response.text[:1000]}")
    try: data=response.json()
    except ValueError: data={}
    return str(data.get("messageId","")).strip()

def main() -> None:
    raw_jobs=read_jobs(RESULT_CSV)
    jobs=[job for job in raw_jobs if email_worthy(job)]
    suppressed=len(raw_jobs)-len(jobs)
    if suppressed: print(f"Suppressed {suppressed} non-IAM/non-official notification candidate(s).")
    if not jobs:
        print("No email-worthy NEW or UPDATED IAM jobs this run. Email not sent."); return
    payload=build_payload(jobs,require_env("BREVO_SENDER_EMAIL"),require_env("REPORT_EMAIL"))
    print(f"Preparing IAM email with {len(jobs)} NEW/UPDATED result(s)...")
    message_id=send_report(require_env("BREVO_API_KEY"),payload)
    print(f"Email sent successfully. Brevo message ID: {message_id}" if message_id else "Email sent successfully.")

if __name__ == "__main__":
    try: main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr); sys.exit(1)
