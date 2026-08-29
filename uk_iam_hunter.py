#!/usr/bin/env python3
"""
UK IAM / PAM JOB DISCOVERY ENGINE v2
====================================

Designed for:
- UK permanent IAM / PAM / Identity Security jobs
- UK location: London, regional UK, remote UK, hybrid UK, onsite UK
- Official company career sites first
- Public ATS APIs where available
- Sitemap / robots.txt discovery
- Deep internal career-page crawling
- Search-engine discovery (Google/Bing HTML search) as a discovery accelerator
- Only accepts results from configured official domains or recognised ATS domains
- Optional Google Apps Script webhook
- CSV + JSON output
- Strong deduplication and source auditing

Install:
    pip install requests beautifulsoup4 rich
Optional JS rendering:
    pip install playwright
    playwright install chromium

Run:
    python uk_iam_job_engine.py
"""

from __future__ import annotations

import csv
import html as html_lib
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, quote_plus, unquote, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

console = Console()

# =============================================================================
# CONFIGURATION
# =============================================================================

REQUEST_TIMEOUT = 18
JOB_REQUEST_TIMEOUT = 15
MAX_WORKERS = 8

# Deep crawl controls.
MAX_PAGES_PER_COMPANY = 18
MAX_JOB_LINKS_PER_COMPANY = 180
MAX_SITEMAP_URLS_PER_COMPANY = 500
MAX_SEARCH_RESULTS_PER_QUERY = 12
MAX_SEARCH_QUERIES_PER_COMPANY = 8

# Search engine discovery. This is intentionally an accelerator, not the source
# of truth. A result is accepted only if its domain is an official configured
# domain or an allow-listed ATS domain.
USE_SEARCH_DISCOVERY = True
SEARCH_ENGINES = ["bing", "google"]

# JavaScript rendering. Keep enabled; requests is always attempted first.
USE_PLAYWRIGHT_FALLBACK = True
PLAYWRIGHT_TIMEOUT_MS = 35000

# Only turn this on after you have tested the scanner.
SEND_TO_APPS_SCRIPT = False

# Your deployed Apps Script endpoint. The scanner will NOT call it unless
# SEND_TO_APPS_SCRIPT = True.
APPS_SCRIPT_WEBHOOK = (
    "https://script.google.com/macros/s/"
    "AKfycbzAxS5Keh8vArI6xXwWc-SmU6DN-FkTcKDVONmEMCLdfxgrQR-vPoDfloxGK8Z0MVBssg/"
    "exec"
)
APPS_SCRIPT_TOKEN = "IAMJOBSEARCHAUGUST2026"

WRITE_CSV = True
WRITE_JSON = True
CSV_FILENAME = "uk_iam_results.csv"

# Fast validation mode. Set to False for the full company database scan.
TEST_MODE = True
TEST_COMPANY_LIMIT = 12

# Save results after every completed company/API batch so an interrupted scan
# never loses everything discovered before the interruption.
INCREMENTAL_CSV_SAVE = True
JSON_FILENAME = "uk_iam_results.json"

# If True, jobs with an explicit future/old posting date are still returned.
# Set a number to limit results to jobs posted within N days when a posting date
# can be extracted. Jobs with no detectable date are retained.
POSTED_WITHIN_DAYS: Optional[int] = None

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0 Safari/537.36"
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Language": "en-GB,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# =============================================================================
# ATS ALLOW-LIST
# =============================================================================

ATS_DOMAINS = {
    "myworkdayjobs.com": "Workday",
    "greenhouse.io": "Greenhouse",
    "lever.co": "Lever",
    "smartrecruiters.com": "SmartRecruiters",
    "ashbyhq.com": "Ashby",
    "teamtailor.com": "Teamtailor",
    "icims.com": "iCIMS",
    "successfactors.com": "SAP SuccessFactors",
    "oraclecloud.com": "Oracle Recruiting",
    "workable.com": "Workable",
    "taleo.net": "Taleo",
    "jobvite.com": "Jobvite",
    "recruitee.com": "Recruitee",
    "pinpointhq.com": "Pinpoint",
    "bamboohr.com": "BambooHR",
}

# =============================================================================
# TARGET ROLE / TECHNOLOGY KEYWORDS
# =============================================================================

# Title terms are deliberately broad enough to catch security roles where IAM
# is in the description rather than the title.
ROLE_KEYWORDS = [
    "IAM",
    "Identity and Access Management",
    "Identity & Access Management",
    "Identity Management",
    "Access Management",
    "Identity Engineer",
    "Identity Architect",
    "Identity Analyst",
    "Identity Consultant",
    "Identity Specialist",
    "Identity Security",
    "Identity Platform",
    "Identity Product",
    "Identity Service",
    "Access Governance",
    "Identity Governance",
    "IGA",
    "PAM",
    "Privileged Access Management",
    "Privileged Access",
    "Privileged Identity",
    "Privileged Account",
    "CyberArk",
    "SailPoint",
    "BeyondTrust",
    "Delinea",
    "One Identity",
    "Saviynt",
    "Okta",
    "Ping Identity",
    "PingFederate",
    "ForgeRock",
    "IdentityNow",
    "IdentityIQ",
    "Entra ID",
    "Microsoft Entra",
    "Azure AD",
    "Azure Active Directory",
    "Privileged Identity Management",
    "PIM",
    "Conditional Access",
    "Access Reviews",
    "Access Certification",
    "Entitlement Management",
    "HashiCorp Vault",
]

# Terms that commonly identify an adjacent cyber/security job with meaningful
# identity responsibility. These only help if an identity term is also present.
SECURITY_CONTEXT = [
    "Cyber Security",
    "Cybersecurity",
    "Information Security",
    "Cloud Security",
    "Security Engineer",
    "Security Architect",
    "Security Consultant",
    "Security Analyst",
    "Zero Trust",
    "Authentication",
    "Authorisation",
    "Authorization",
    "RBAC",
    "SSO",
    "Single Sign-On",
    "Federation",
]

# Exclude obvious non-role pages.
EXCLUDED_TITLE_TERMS = [
    "internship",
    "intern",
    "apprentice",
    "graduate programme",
    "graduate program",
    "school leaver",
    "talent acquisition",
    "recruitment coordinator",
]

# =============================================================================
# UK LOCATION / WORKING ARRANGEMENT
# =============================================================================

UK_TERMS = [
    "united kingdom",
    "uk",
    "u.k.",
    "england",
    "scotland",
    "wales",
    "northern ireland",
    "london",
    "manchester",
    "birmingham",
    "edinburgh",
    "glasgow",
    "bristol",
    "leeds",
    "cambridge",
    "oxford",
    "reading",
    "milton keynes",
    "cardiff",
    "belfast",
    "newcastle",
    "nottingham",
    "sheffield",
    "southampton",
    "brighton",
    "luton",
    "guildford",
    "slough",
    "portsmouth",
    "havant",
    "coventry",
    "derby",
    "york",
    "exeter",
    "liverpool",
    "newport",
    "remote uk",
    "uk remote",
    "remote, uk",
    "remote - uk",
    "remote within the uk",
    "based in the uk",
]

WORKING_ARRANGEMENT_TERMS = [
    "remote",
    "hybrid",
    "onsite",
    "on-site",
    "office-based",
    "office based",
]

EMPLOYMENT_TERMS = [
    "permanent",
    "full-time",
    "full time",
]

# =============================================================================
# OFFICIAL COMPANY SOURCES
# =============================================================================

# Each company can have several seeds. More seeds = deeper discovery.
COMPANIES: List[Dict[str, Any]] = [
    # Banking / financial services
    {"id": "HSBC", "name": "HSBC", "domains": ["hsbc.com"], "seeds": ["https://www.hsbc.com/careers"]},
    {"id": "LLOYDS", "name": "Lloyds Banking Group", "domains": ["lloydsbankinggroup.com", "lloydsbankinggroupcareers.co.uk"], "seeds": ["https://www.lloydsbankinggroup.com/careers.html"]},
    {"id": "NATWEST", "name": "NatWest Group", "domains": ["natwestgroup.com"], "seeds": ["https://www.natwestgroup.com/careers-at-natwest-group.html", "https://jobs.natwestgroup.com/"]},
    {"id": "BARCLAYS", "name": "Barclays", "domains": ["search.jobs.barclays"], "seeds": ["https://search.jobs.barclays/"]},
    {"id": "STANDARD_CHARTERED", "name": "Standard Chartered", "domains": ["sc.com", "standardchartered.com"], "seeds": ["https://www.sc.com/en/global-careers/"]},
    {"id": "AVIVA", "name": "Aviva", "domains": ["aviva.com", "careers.aviva.com"], "seeds": ["https://www.aviva.com/careers/"]},
    {"id": "SCHRODERS", "name": "Schroders", "domains": ["schroders.com"], "seeds": ["https://www.schroders.com/en-gb/uk/institutional/about-us/careers/"]},
    {"id": "MAN_GROUP", "name": "Man Group", "domains": ["man.com"], "seeds": ["https://www.man.com/careers"]},
    {"id": "GOLDMAN", "name": "Goldman Sachs", "domains": ["goldmansachs.com"], "seeds": ["https://www.goldmansachs.com/careers/"]},
    {"id": "MORGAN_STANLEY", "name": "Morgan Stanley", "domains": ["morganstanley.com"], "seeds": ["https://www.morganstanley.com/careers/career-opportunities-search/"]},
    {"id": "JPMORGAN", "name": "JPMorgan Chase", "domains": ["jpmorganchase.com"], "seeds": ["https://www.jpmorganchase.com/careers"]},
    {"id": "CITI", "name": "Citi", "domains": ["jobs.citi.com"], "seeds": ["https://jobs.citi.com/"]},
    {"id": "MUFG", "name": "MUFG", "domains": ["mufg.co.uk", "mufgcareers.com"], "seeds": ["https://www.mufg.co.uk/careers"]},
    {"id": "DEUTSCHE_BANK", "name": "Deutsche Bank", "domains": ["db.com"], "seeds": ["https://careers.db.com/"]},
    {"id": "UBS", "name": "UBS", "domains": ["ubs.com"], "seeds": ["https://www.ubs.com/global/en/careers.html"]},

    # Fintech
    {"id": "WISE", "name": "Wise", "domains": ["wise.jobs", "wise.com"], "seeds": ["https://wise.jobs/"]},
    {"id": "MONZO", "name": "Monzo", "domains": ["monzo.com", "greenhouse.io"], "seeds": ["https://monzo.com/careers"]},
    {"id": "REVOLUT", "name": "Revolut", "domains": ["revolut.com", "lever.co"], "seeds": ["https://www.revolut.com/careers/"]},
    {"id": "STARLING", "name": "Starling Bank", "domains": ["starlingbank.com", "workable.com"], "seeds": ["https://www.starlingbank.com/careers/"]},
    {"id": "CHECKOUT", "name": "Checkout.com", "domains": ["checkout.com", "greenhouse.io"], "seeds": ["https://www.checkout.com/careers"]},
    {"id": "DELIVEROO", "name": "Deliveroo", "domains": ["deliveroo.co.uk", "greenhouse.io"], "seeds": ["https://careers.deliveroo.co.uk/"]},
    {"id": "OCTOPUS", "name": "Octopus Energy", "domains": ["octopus.energy"], "seeds": ["https://octopus.energy/careers/"]},

    # Telecommunications / technology
    {"id": "BT", "name": "BT Group", "domains": ["jobs.bt.com"], "seeds": ["https://jobs.bt.com/BT/", "https://jobs.bt.com/BT/viewalljobs/"]},
    {"id": "OPENREACH", "name": "Openreach", "domains": ["jobs.bt.com"], "seeds": ["https://jobs.bt.com/Openreach/viewalljobs/"]},
    {"id": "VODAFONE", "name": "Vodafone / VodafoneThree", "domains": ["careers.vodafone.com"], "seeds": ["https://careers.vodafone.com/", "https://careers.vodafone.com/uk/"]},
    {"id": "VIRGIN_MEDIA_O2", "name": "Virgin Media O2", "domains": ["virginmediao2.co.uk"], "seeds": ["https://www.virginmediao2.co.uk/careers"]},
    {"id": "SKY", "name": "Sky", "domains": ["sky.com", "careers.sky.com"], "seeds": ["https://careers.sky.com/jobs"]},
    {"id": "SOFTCAT", "name": "Softcat", "domains": ["softcat.com"], "seeds": ["https://www.softcat.com/careers"]},
    {"id": "CANONICAL", "name": "Canonical", "domains": ["canonical.com", "lever.co"], "seeds": ["https://canonical.com/careers"]},

    # Transport / aviation / rail
    {"id": "NETWORK_RAIL", "name": "Network Rail", "domains": ["networkrail.co.uk", "operationscareers.networkrail.co.uk"], "seeds": ["https://www.networkrail.co.uk/careers/", "https://operationscareers.networkrail.co.uk/role-search/"]},
    {"id": "EASYJET", "name": "easyJet", "domains": ["easyjet.com", "careers.easyjet.com"], "seeds": ["https://careers.easyjet.com/en"]},
    {"id": "BRITISH_AIRWAYS", "name": "British Airways", "domains": ["ba.com"], "seeds": ["https://careers.ba.com/"]},
    {"id": "VIRGIN_ATLANTIC", "name": "Virgin Atlantic", "domains": ["virginatlantic.com"], "seeds": ["https://careers.virginatlantic.com/"]},
    {"id": "HEATHROW", "name": "Heathrow Airport", "domains": ["heathrow.com"], "seeds": ["https://www.heathrow.com/company/careers"]},
    {"id": "ROYAL_MAIL", "name": "Royal Mail Group", "domains": ["royalmailgroup.com"], "seeds": ["https://careers.royalmailgroup.com/gb/en"]},
    {"id": "DHL", "name": "DHL UK", "domains": ["dhl.com"], "seeds": ["https://careers.dhl.com/global/en/dhl-uk"]},

    # Energy / utilities
    {"id": "SSE", "name": "SSE", "domains": ["sse.com", "careers.sse.com"], "seeds": ["https://careers.sse.com/"]},
    {"id": "NATIONAL_GRID", "name": "National Grid", "domains": ["nationalgrid.com", "jobs.nationalgrid.com"], "seeds": ["https://www.nationalgrid.com/careers?region=uk", "https://jobs.nationalgrid.com/uk/jobs"]},
    {"id": "CENTRICA", "name": "Centrica", "domains": ["centrica.com"], "seeds": ["https://www.centrica.com/careers"]},
    {"id": "ENERGY_UTILITIES_JOBS", "name": "Energy & Utilities Jobs", "domains": ["energyutilitiesjobs.co.uk"], "seeds": ["https://careers.energyutilitiesjobs.co.uk/"]},

    # Public sector / NHS / government-adjacent
    {"id": "NHS_JOBS", "name": "NHS Jobs", "domains": ["jobs.nhs.uk"], "seeds": ["https://www.jobs.nhs.uk/"]},
    {"id": "NHS_SCOTLAND", "name": "NHS Scotland", "domains": ["careers.nhs.scot"], "seeds": ["https://careers.nhs.scot/"]},
    {"id": "GCHQ", "name": "GCHQ", "domains": ["gchq-careers.co.uk"], "seeds": ["https://www.gchq-careers.co.uk/"]},

    # Consulting / technology services
    {"id": "COMPUTACENTER", "name": "Computacenter", "domains": ["computacenter.com", "careers.computacenter.com"], "seeds": ["https://careers.computacenter.com/uk/"]},
    {"id": "SERCO", "name": "Serco", "domains": ["serco.com", "careers.serco.com"], "seeds": ["https://www.serco.com/uk/careers", "https://careers.serco.com/gb/en"]},
    {"id": "SOPRA_STERIA", "name": "Sopra Steria", "domains": ["soprasteria.com", "careers.soprasteria.co.uk"], "seeds": ["https://careers.soprasteria.co.uk/uk/en"]},
    {"id": "CGI", "name": "CGI UK", "domains": ["cgi.com"], "seeds": ["https://www.cgi.com/uk/en-gb/careers"]},
    {"id": "DELOITTE", "name": "Deloitte UK", "domains": ["deloitte.com"], "seeds": ["https://apply.deloitte.com/"]},
    {"id": "EY", "name": "EY UK", "domains": ["ey.com", "careers.ey.com"], "seeds": ["https://careers.ey.com/"]},
    {"id": "KPMG", "name": "KPMG UK", "domains": ["kpmg.com"], "seeds": ["https://kpmg.com/uk/en/careers.html"]},
    {"id": "PWC", "name": "PwC UK", "domains": ["pwc.co.uk", "jobs.pwc.co.uk"], "seeds": ["https://www.pwc.co.uk/careers", "https://jobs.pwc.co.uk/uk/en/"]},

    # Large enterprise / pharma / engineering
    {"id": "BAE", "name": "BAE Systems", "domains": ["baesystems.com"], "seeds": ["https://www.baesystems.com/careers/"]},
    {"id": "ROLLS_ROYCE", "name": "Rolls-Royce", "domains": ["rolls-royce.com", "careers.rolls-royce.com"], "seeds": ["https://careers.rolls-royce.com/our-locations/uk"]},
    {"id": "QINETIQ", "name": "QinetiQ", "domains": ["qinetiq.com", "careers.qinetiq.com"], "seeds": ["https://www.qinetiq.com/en-gb/careers", "https://careers.qinetiq.com/"]},
    {"id": "GSK", "name": "GSK", "domains": ["gsk.com", "careers.gsk.com"], "seeds": ["https://www.gsk.com/en-gb/careers/"]},
    {"id": "ASTRAZENECA", "name": "AstraZeneca", "domains": ["astrazeneca.com", "careers.astrazeneca.com"], "seeds": ["https://careers.astrazeneca.com/search-jobs/united-kingdom"]},
    {"id": "UNILEVER", "name": "Unilever UK", "domains": ["unilever.com", "careers.unilever.com"], "seeds": ["https://careers.unilever.com/en/united-kingdom-and-ireland"]},
    {"id": "KINGFISHER", "name": "Kingfisher", "domains": ["kingfisher.com", "careers.kingfisher.com"], "seeds": ["https://careers.kingfisher.com/"]},
    {"id": "OCADO", "name": "Ocado Group", "domains": ["ocado.com", "careers.ocadogroup.com"], "seeds": ["https://careers.ocadogroup.com/"]},
    {"id": "APPLE_UK", "name": "Apple UK", "domains": ["jobs.apple.com"], "seeds": ["https://jobs.apple.com/en-gb/search?location=united-kingdom-GBR"]},
    {"id": "MICROSOFT_UK", "name": "Microsoft UK", "domains": ["jobs.careers.microsoft.com", "microsoft.com"], "seeds": ["https://jobs.careers.microsoft.com/global/en/search"]},
    {"id": "UNIVERSITY_CAMBRIDGE", "name": "University of Cambridge", "domains": ["jobs.cam.ac.uk"], "seeds": ["https://www.jobs.cam.ac.uk/"]},

    # Oracle Recruiting / user-provided public enterprise board
    {"id": "ORACLE_CX_1003", "name": "Oracle Recruiting CX_1003", "domains": ["oraclecloud.com"], "seeds": ["https://don.fa.em2.oraclecloud.com/hcmUI/CandidateExperience/en/sites/CX_1003/"]},
]

# =============================================================================
# PUBLIC ATS BOARD IDs
# =============================================================================

ATS_BOARDS = [
    ("Monzo", "greenhouse", "monzo"),
    ("Deliveroo", "greenhouse", "deliveroo"),
    ("Checkout.com", "greenhouse", "checkoutcom"),
    ("Darktrace", "greenhouse", "darktrace"),
    ("Sophos", "greenhouse", "sophos"),
    ("Revolut", "lever", "revolut"),
    ("Canonical", "lever", "canonical"),
    ("Starling Bank", "workable", "starling-bank"),
]

# =============================================================================
# URL / HTTP HELPERS
# =============================================================================

def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    return s


def normalise_url(url: str) -> str:
    if not url:
        return ""
    return url.strip().rstrip("#")


def host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def registrableish_host(url: str) -> str:
    """Good enough for configured corporate/ATS allow-list checks."""
    h = host(url)
    parts = h.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return h


def detect_ats(url: str) -> Optional[str]:
    h = host(url)
    for domain, name in ATS_DOMAINS.items():
        if h == domain or h.endswith("." + domain):
            return name
    return None


def fetch(session: requests.Session, url: str, timeout: int = REQUEST_TIMEOUT) -> Optional[requests.Response]:
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        if r.status_code >= 400:
            return None
        return r
    except requests.RequestException:
        return None


def is_html_response(r: requests.Response) -> bool:
    ct = r.headers.get("content-type", "").lower()
    return "html" in ct or "xml" in ct or not ct


def same_domain_or_subdomain(url: str, configured_domains: Iterable[str]) -> bool:
    h = host(url)
    for d in configured_domains:
        d = d.lower().strip()
        if h == d or h.endswith("." + d):
            return True
    return False


def allowed_result_url(url: str, company: Dict[str, Any]) -> bool:
    if same_domain_or_subdomain(url, company["domains"]):
        return True
    if detect_ats(url):
        return True
    return False

# =============================================================================
# KEYWORD / MATCHING
# =============================================================================

def keyword_found(keyword: str, text: str) -> bool:
    if not keyword or not text:
        return False
    if len(keyword) <= 4:
        pattern = rf"(?<![A-Za-z0-9]){re.escape(keyword)}(?![A-Za-z0-9])"
    else:
        pattern = re.escape(keyword)
    return re.search(pattern, text, re.I) is not None


def matched_keywords(text: str) -> List[str]:
    return [k for k in ROLE_KEYWORDS if keyword_found(k, text)]


def excluded_title(title: str) -> bool:
    low = title.lower()
    return any(x in low for x in EXCLUDED_TITLE_TERMS)


def is_uk(text: str) -> bool:
    low = text.lower()
    # Avoid treating "uk" inside a larger word as a location.
    for term in UK_TERMS:
        if term == "uk":
            if re.search(r"(?<![a-z])uk(?![a-z])", low):
                return True
        elif term in low:
            return True
    return False


def extract_working_arrangement(text: str) -> str:
    low = text.lower()
    found = []
    for term in WORKING_ARRANGEMENT_TERMS:
        if term in low and term not in found:
            found.append(term)
    return ", ".join(found[:5])


def extract_employment_type(text: str) -> str:
    low = text.lower()
    if "permanent" in low:
        return "Permanent"
    if "fixed term" in low or "fixed-term" in low:
        return "Fixed-term"
    if "contract" in low:
        return "Contract"
    return ""


def is_target_job(title: str, description: str, url: str) -> Tuple[bool, List[str]]:
    combined = f"{title}\n{description}\n{url}"
    matches = matched_keywords(combined)
    if not matches:
        return False, []
    if excluded_title(title):
        return False, matches
    # Require UK evidence in the job content, not just the company's UK domain.
    if not is_uk(combined):
        return False, matches
    return True, matches


# =============================================================================
# STRUCTURED DATA
# =============================================================================

def parse_jsonld(soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
    jobs: List[Dict[str, Any]] = []
    for script in soup.find_all("script", type="application/ld+json"):
        raw = script.string or script.get_text()
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except Exception:
            continue

        items: List[Any]
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict) and isinstance(data.get("@graph"), list):
            items = data["@graph"]
        elif isinstance(data, dict):
            items = [data]
        else:
            continue

        for item in items:
            if not isinstance(item, dict):
                continue
            typ = item.get("@type")
            if isinstance(typ, list):
                is_job = "JobPosting" in typ
            else:
                is_job = typ == "JobPosting"
            if not is_job:
                continue

            title = str(item.get("title", "")).strip()
            desc = BeautifulSoup(str(item.get("description", "")), "html.parser").get_text(" ", strip=True)
            loc = extract_jsonld_location(item.get("jobLocation"))
            url = urljoin(base_url, str(item.get("url") or base_url))
            date_posted = str(item.get("datePosted", "") or "")
            employment = str(item.get("employmentType", "") or "")
            salary = extract_salary(item.get("baseSalary"))

            jobs.append({
                "title": title,
                "description": desc,
                "location": loc,
                "url": url,
                "date_posted": date_posted,
                "employment_type": employment,
                "salary": salary,
                "method": "JSON-LD JobPosting",
            })
    return jobs


def extract_jsonld_location(value: Any) -> str:
    def one(v: Any) -> str:
        if not isinstance(v, dict):
            return str(v or "")
        address = v.get("address", v)
        if isinstance(address, dict):
            parts = [
                address.get("addressLocality", ""),
                address.get("addressRegion", ""),
                address.get("postalCode", ""),
                address.get("addressCountry", ""),
            ]
            return ", ".join(str(x) for x in parts if x)
        return str(address or "")

    if isinstance(value, list):
        return " | ".join(one(v) for v in value)
    return one(value)


def extract_salary(value: Any) -> str:
    if not value:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        currency = value.get("currency", "")
        val = value.get("value", value)
        if isinstance(val, dict):
            low = val.get("minValue", "")
            high = val.get("maxValue", "")
            single = val.get("value", "")
            if low and high:
                return f"{currency} {low}-{high}".strip()
            if single:
                return f"{currency} {single}".strip()
        return str(value)
    return str(value)


# =============================================================================
# GENERIC HTML EXTRACTION
# =============================================================================

JOB_LINK_HINTS = [
    "job", "jobs", "career", "careers", "vacanc", "opportunit",
    "position", "opening", "employment", "apply", "requisition",
    "role", "search", "viewalljobs",
]


def looks_like_job_link(url: str, text: str = "") -> bool:
    s = f"{url} {text}".lower()
    return any(x in s for x in JOB_LINK_HINTS)


def looks_like_navigation(url: str, text: str = "") -> bool:
    s = f"{url} {text}".lower()
    return any(x in s for x in [
        "next", "page=", "start=", "offset=", "load more",
        "view all", "all jobs", "search jobs", "see all",
    ])


def extract_location_from_html(soup: BeautifulSoup) -> str:
    selectors = [
        '[class*="location"]',
        '[id*="location"]',
        '[data-testid*="location"]',
        '[aria-label*="location" i]',
    ]
    for selector in selectors:
        try:
            node = soup.select_one(selector)
        except Exception:
            node = None
        if node:
            value = node.get_text(" ", strip=True)
            if value:
                return value[:500]
    return ""


def page_title(soup: BeautifulSoup) -> str:
    h1 = soup.find("h1")
    if h1:
        return h1.get_text(" ", strip=True)
    if soup.title:
        return soup.title.get_text(" ", strip=True)
    return ""


def extract_page_links(html: str, page_url: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    soup = BeautifulSoup(html, "html.parser")
    jobs = parse_jsonld(soup, page_url)
    links: List[str] = []
    seen: Set[str] = set()

    for a in soup.find_all("a", href=True):
        href = urljoin(page_url, a.get("href", ""))
        text = a.get_text(" ", strip=True)
        if not href.startswith(("http://", "https://")):
            continue
        href = normalise_url(href)
        if href in seen:
            continue
        if looks_like_job_link(href, text):
            seen.add(href)
            links.append(href)
    return jobs, links


# =============================================================================
# SITEMAPS
# =============================================================================

def discover_sitemaps(session: requests.Session, seed: str) -> List[str]:
    root = f"{urlparse(seed).scheme}://{host(seed)}"
    urls = [
        urljoin(root, "/robots.txt"),
        urljoin(root, "/sitemap.xml"),
        urljoin(root, "/sitemap_index.xml"),
    ]
    found: Set[str] = set()

    for candidate in urls:
        r = fetch(session, candidate, timeout=12)
        if not r:
            continue
        text = r.text
        if candidate.endswith("robots.txt"):
            for line in text.splitlines():
                if line.lower().startswith("sitemap:"):
                    found.add(line.split(":", 1)[1].strip())
        else:
            found.add(candidate)

    return list(found)


def parse_sitemap(session: requests.Session, sitemap_url: str, limit: int = MAX_SITEMAP_URLS_PER_COMPANY) -> List[str]:
    out: List[str] = []
    queue = [sitemap_url]
    seen: Set[str] = set()

    while queue and len(out) < limit:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        r = fetch(session, current, timeout=15)
        if not r:
            continue
        text = r.text
        soup = BeautifulSoup(text, "xml")
        if soup.find("sitemap"):
            for loc in soup.find_all("loc"):
                if loc.get_text(strip=True):
                    queue.append(loc.get_text(strip=True))
        else:
            for loc in soup.find_all("loc"):
                u = loc.get_text(strip=True)
                if u:
                    out.append(u)
                    if len(out) >= limit:
                        break
    return out


# =============================================================================
# SEARCH ENGINE DISCOVERY
# =============================================================================

def search_google(session: requests.Session, query: str) -> List[str]:
    url = "https://www.google.com/search?q=" + quote_plus(query) + "&num=20&hl=en-GB"
    r = fetch(session, url, timeout=15)
    if not r:
        return []
    soup = BeautifulSoup(r.text, "html.parser")
    urls = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith("/url?q="):
            href = parse_qs(urlparse(href).query).get("q", [""])[0]
        elif href.startswith("https://www.google.com/"):
            continue
        if href.startswith(("http://", "https://")):
            urls.append(href)
    return urls


def search_bing(session: requests.Session, query: str) -> List[str]:
    url = "https://www.bing.com/search?q=" + quote_plus(query) + "&count=20&setlang=en-GB"
    r = fetch(session, url, timeout=15)
    if not r:
        return []
    soup = BeautifulSoup(r.text, "html.parser")
    urls = []
    for a in soup.select("li.b_algo h2 a, h2 a"):
        href = a.get("href", "")
        if href.startswith(("http://", "https://")):
            urls.append(href)
    return urls


def search_urls(session: requests.Session, query: str) -> List[str]:
    urls: List[str] = []
    for engine in SEARCH_ENGINES:
        try:
            if engine == "google":
                urls.extend(search_google(session, query))
            elif engine == "bing":
                urls.extend(search_bing(session, query))
        except Exception:
            continue
    # Preserve order, remove duplicates.
    return list(dict.fromkeys(urls))


def build_search_queries(company: Dict[str, Any]) -> List[str]:
    domain = company["domains"][0]
    terms = [
        '"Identity and Access Management"',
        '"IAM Engineer"',
        '"Identity Engineer"',
        '"Identity Security"',
        '"PAM" CyberArk',
        '"Privileged Access Management"',
        '"Entra ID"',
        '"SailPoint" OR "Saviynt" OR "Okta"',
    ]
    return [f"site:{domain} {term} UK jobs" for term in terms[:MAX_SEARCH_QUERIES_PER_COMPANY]]


# =============================================================================
# PLAYWRIGHT RENDERING
# =============================================================================

def render_page(url: str) -> Optional[Tuple[str, str]]:
    if not USE_PLAYWRIGHT_FALLBACK or not PLAYWRIGHT_AVAILABLE:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(locale="en-GB", user_agent=USER_AGENT)
            page.goto(url, wait_until="domcontentloaded", timeout=PLAYWRIGHT_TIMEOUT_MS)
            page.wait_for_timeout(1500)
            html = page.content()
            final_url = page.url
            browser.close()
            return html, final_url
    except Exception:
        return None


# =============================================================================
# JOB RECORD NORMALISATION
# =============================================================================

def canonical_url(url: str) -> str:
    if not url:
        return ""
    p = urlparse(url)
    # Remove query/fragment so tracking and filter parameters do not create
    # duplicate records.
    return urlunparse((
        p.scheme.lower(),
        p.netloc.lower(),
        p.path.rstrip("/"),
        "",
        "",
        "",
    ))


def extract_reference(url: str, text: str = "") -> str:
    patterns = [
        r"\bReq(?:uisition)?(?:\s*(?:ID|No|Number|#))?\s*[:\-]?\s*([A-Z0-9\-]{4,})\b",
        r"\bJob\s*(?:ID|Ref(?:erence)?)\s*[:\-]?\s*([A-Z0-9\-]{4,})\b",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if m:
            return m.group(1)
    return ""


def parse_posted_date(text: str) -> str:
    patterns = [
        r"(?:posted|posting date|date posted)\s*[:\-]?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})",
        r"(?:posted|posting date|date posted)\s*[:\-]?\s*([A-Z][a-z]+\s+\d{1,2},\s+\d{4})",
        r"(\d{4}-\d{2}-\d{2})",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if m:
            return m.group(1)
    return ""


def passes_posted_filter(date_text: str) -> bool:
    if POSTED_WITHIN_DAYS is None or not date_text:
        return True
    # Conservative: if a date exists but cannot be parsed, retain it.
    from datetime import datetime, timedelta
    formats = ["%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%B %d, %Y"]
    parsed = None
    for fmt in formats:
        try:
            parsed = datetime.strptime(date_text, fmt)
            break
        except ValueError:
            pass
    if not parsed:
        return True
    cutoff = datetime.now() - timedelta(days=POSTED_WITHIN_DAYS)
    return parsed >= cutoff


def build_result(
    company: Dict[str, Any],
    title: str,
    description: str,
    location: str,
    url: str,
    method: str,
    date_posted: str = "",
    employment_type: str = "",
    salary: str = "",
) -> Optional[Dict[str, Any]]:
    title = re.sub(r"\s+", " ", title or "").strip()
    description = re.sub(r"\s+", " ", description or "").strip()
    url = normalise_url(url)

    if not title or not url:
        return None

    matched, keywords = is_target_job(title, f"{description} {location}", url)
    if not matched:
        return None
    if not allowed_result_url(url, company):
        return None
    if not passes_posted_filter(date_posted):
        return None

    arrangement = extract_working_arrangement(f"{title} {description} {location}")
    employment = employment_type or extract_employment_type(f"{title} {description}")

    return {
        "company": company["name"],
        "title": title,
        "location": location or "UK location not specified",
        "working_arrangement": arrangement,
        "employment_type": employment,
        "salary": salary,
        "date_posted": date_posted,
        "job_reference": extract_reference(url, f"{title} {description}"),
        "source_method": method,
        "matched_keywords": ", ".join(keywords),
        "url": url,
        "canonical_url": canonical_url(url),
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }


# =============================================================================
# COMPANY CRAWLER
# =============================================================================

def crawl_company(company: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    session = make_session()
    results: List[Dict[str, Any]] = []
    audit = {
        "company": company["name"],
        "verified_seeds": [],
        "failed_seeds": [],
        "pages_scanned": 0,
        "job_links_scanned": 0,
        "sitemap_urls": 0,
        "search_urls": 0,
        "errors": [],
    }

    # 1. Verify seeds.
    seeds: List[str] = []
    for seed in company["seeds"]:
        r = fetch(session, seed)
        if r:
            final = r.url
            seeds.append(final)
            audit["verified_seeds"].append(final)
        else:
            audit["failed_seeds"].append(seed)

    if not seeds:
        return [], audit

    # 2. Sitemap discovery.
    sitemap_urls: Set[str] = set()
    for seed in seeds[:3]:
        for sm in discover_sitemaps(session, seed):
            sitemap_urls.add(sm)

    sitemap_job_candidates: List[str] = []
    for sm in list(sitemap_urls)[:5]:
        sitemap_job_candidates.extend(parse_sitemap(session, sm))
        if len(sitemap_job_candidates) >= MAX_SITEMAP_URLS_PER_COMPANY:
            break

    audit["sitemap_urls"] = len(sitemap_job_candidates)

    # We do not fetch every sitemap URL. Only URLs whose path/title looks job-like.
    sitemap_candidates = [
        u for u in sitemap_job_candidates
        if looks_like_job_link(u)
    ][:MAX_JOB_LINKS_PER_COMPANY]

    # 3. Search engine discovery.
    search_candidates: List[str] = []
    if USE_SEARCH_DISCOVERY:
        for q in build_search_queries(company):
            found = search_urls(session, q)
            for u in found:
                if allowed_result_url(u, company):
                    search_candidates.append(u)
            if len(search_candidates) >= MAX_JOB_LINKS_PER_COMPANY:
                break
        search_candidates = list(dict.fromkeys(search_candidates))
        audit["search_urls"] = len(search_candidates)

    # 4. Deep crawl of careers pages.
    pages: List[str] = list(dict.fromkeys(seeds))
    pages.extend(sitemap_candidates[:80])
    pages.extend(search_candidates[:80])

    visited_pages: Set[str] = set()
    job_links: List[str] = []
    seen_job_links: Set[str] = set()

    while pages and len(visited_pages) < MAX_PAGES_PER_COMPANY:
        page_url = normalise_url(pages.pop(0))
        if not page_url or page_url in visited_pages:
            continue
        if not same_domain_or_subdomain(page_url, company["domains"]) and not detect_ats(page_url):
            continue

        visited_pages.add(page_url)

        response = fetch(session, page_url)
        html = None
        final_url = page_url

        if response and is_html_response(response):
            html = response.text
            final_url = response.url
            static_text = BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
            if USE_PLAYWRIGHT_FALLBACK and len(static_text) < 900:
                rendered = render_page(final_url)
                if rendered:
                    html, final_url = rendered
        else:
            rendered = render_page(page_url)
            if rendered:
                html, final_url = rendered

        if not html:
            continue

        audit["pages_scanned"] += 1

        soup = BeautifulSoup(html, "html.parser")
        page_text = soup.get_text(" ", strip=True)

        # JSON-LD jobs.
        for job in parse_jsonld(soup, final_url):
            item = build_result(
                company,
                job.get("title", ""),
                job.get("description", ""),
                job.get("location", ""),
                job.get("url", final_url),
                f"Official/ATS -> {detect_ats(final_url) or 'Corporate'} -> JSON-LD",
                job.get("date_posted", ""),
                job.get("employment_type", ""),
                job.get("salary", ""),
            )
            if item:
                results.append(item)

        # All links. We intentionally collect a much larger set than v1.
        for a in soup.find_all("a", href=True):
            href = urljoin(final_url, a.get("href", ""))
            text = a.get_text(" ", strip=True)
            if not href.startswith(("http://", "https://")):
                continue
            href = normalise_url(href)

            if not allowed_result_url(href, company):
                continue

            if looks_like_job_link(href, text):
                if href not in seen_job_links and len(job_links) < MAX_JOB_LINKS_PER_COMPANY:
                    seen_job_links.add(href)
                    job_links.append(href)
            elif looks_like_navigation(href, text):
                if href not in visited_pages and len(pages) < MAX_PAGES_PER_COMPANY * 3:
                    pages.append(href)

    # 5. Fetch individual job links.
    for job_url in job_links[:MAX_JOB_LINKS_PER_COMPANY]:
        audit["job_links_scanned"] += 1
        try:
            response = fetch(session, job_url, timeout=JOB_REQUEST_TIMEOUT)
            html = None
            final_url = job_url

            if response and is_html_response(response):
                html = response.text
                final_url = response.url
                static_text = BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
                if USE_PLAYWRIGHT_FALLBACK and len(static_text) < 900:
                    rendered = render_page(final_url)
                    if rendered:
                        html, final_url = rendered
            else:
                rendered = render_page(job_url)
                if rendered:
                    html, final_url = rendered

            if not html:
                continue

            soup = BeautifulSoup(html, "html.parser")

            json_jobs = parse_jsonld(soup, final_url)
            if json_jobs:
                for job in json_jobs:
                    item = build_result(
                        company,
                        job.get("title", ""),
                        job.get("description", ""),
                        job.get("location", ""),
                        job.get("url", final_url),
                        f"Official/ATS -> {detect_ats(final_url) or 'Corporate'} -> JobPosting",
                        job.get("date_posted", ""),
                        job.get("employment_type", ""),
                        job.get("salary", ""),
                    )
                    if item:
                        results.append(item)
                continue

            title = page_title(soup)
            text = soup.get_text(" ", strip=True)
            location = extract_location_from_html(soup)
            date_posted = parse_posted_date(text)
            item = build_result(
                company,
                title,
                text,
                location,
                final_url,
                f"Official/ATS -> {detect_ats(final_url) or 'Corporate'} -> HTML",
                date_posted,
            )
            if item:
                results.append(item)

        except Exception as exc:
            audit["errors"].append(str(exc)[:250])

    return dedupe(results), audit


# =============================================================================
# ATS API SCANNERS
# =============================================================================

def scan_greenhouse(company: str, board: str) -> List[Dict[str, Any]]:
    out = []
    try:
        r = requests.get(
            f"https://boards-api.greenhouse.io/v1/boards/{board}/jobs?content=true",
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code != 200:
            return []
        for job in r.json().get("jobs", []):
            title = str(job.get("title", ""))
            desc = BeautifulSoup(str(job.get("content", "")), "html.parser").get_text(" ", strip=True)
            loc = str((job.get("location") or {}).get("name", ""))
            url = str(job.get("absolute_url", ""))
            fake_company = {"name": company, "domains": [registrableish_host(url)]}
            item = build_result(fake_company, title, desc, loc, url, "Direct API (Greenhouse)")
            if item:
                out.append(item)
    except Exception:
        pass
    return out


def scan_lever(company: str, board: str) -> List[Dict[str, Any]]:
    out = []
    try:
        r = requests.get(
            f"https://api.lever.co/v0/postings/{board}?mode=json",
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code != 200:
            return []
        for job in r.json():
            title = str(job.get("text", ""))
            cat = job.get("categories") or {}
            loc = str(cat.get("location", ""))
            desc = str(job.get("descriptionPlain", ""))
            url = str(job.get("hostedUrl", ""))
            fake_company = {"name": company, "domains": [registrableish_host(url)]}
            item = build_result(fake_company, title, desc, loc, url, "Direct API (Lever)")
            if item:
                out.append(item)
    except Exception:
        pass
    return out


def scan_workable(company: str, board: str) -> List[Dict[str, Any]]:
    out = []
    try:
        r = requests.get(
            f"https://apply.workable.com/api/v3/accounts/{board}",
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code != 200:
            return []
        data = r.json()
        for job in data.get("jobs", []):
            title = str(job.get("title", ""))
            loc = ", ".join(
                str(job.get(k, ""))
                for k in ("city", "state", "country")
                if job.get(k)
            )
            desc = str(job.get("description", ""))
            url = str(job.get("url", ""))
            fake_company = {"name": company, "domains": [registrableish_host(url)]}
            item = build_result(fake_company, title, desc, loc, url, "Direct API (Workable)")
            if item:
                out.append(item)
    except Exception:
        pass
    return out


def scan_ats_board(item: Tuple[str, str, str]) -> List[Dict[str, Any]]:
    company, platform, board = item
    if platform == "greenhouse":
        return scan_greenhouse(company, board)
    if platform == "lever":
        return scan_lever(company, board)
    if platform == "workable":
        return scan_workable(company, board)
    return []


# =============================================================================
# DEDUPLICATION
# =============================================================================

def dedupe(results: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    seen: Set[str] = set()
    for item in results:
        key = item.get("canonical_url") or canonical_url(item.get("url", ""))
        if not key:
            key = f"{item.get('company','')}|{item.get('title','')}".lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


# =============================================================================
# GOOGLE APPS SCRIPT
# =============================================================================

def send_to_apps_script(job: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "token": APPS_SCRIPT_TOKEN,
        "application_id": "",
        "date_applied": "",
        "company": job.get("company", ""),
        "title": job.get("title", ""),
        "job_reference": job.get("job_reference", ""),
        "url": job.get("url", ""),
        "source": job.get("source_method", ""),
        "salary": job.get("salary", ""),
        "employment_type": job.get("employment_type", ""),
        "location": job.get("location", ""),
        "working_arrangement": job.get("working_arrangement", ""),
        "status": "Discovered",
        "cv_used": "",
        "matched_keywords": job.get("matched_keywords", ""),
        "match_score": "",
        "outcome": "",
        "notes": "Automatically discovered by UK IAM Job Engine v2",
    }
    try:
        r = requests.post(APPS_SCRIPT_WEBHOOK, json=payload, timeout=30)
        return r.json()
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# =============================================================================
# EXPORT
# =============================================================================

def export_csv(results: List[Dict[str, Any]]) -> None:
    if not WRITE_CSV:
        return
    fields = [
        "company", "title", "job_reference", "location",
        "working_arrangement", "employment_type", "salary",
        "date_posted", "matched_keywords", "source_method", "url",
        "canonical_url", "discovered_at",
    ]
    with open(CSV_FILENAME, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in results:
            writer.writerow({k: row.get(k, "") for k in fields})
    console.print(f"[green]✔ CSV saved: {CSV_FILENAME}[/green]")


def export_json(results: List[Dict[str, Any]], audits: List[Dict[str, Any]]) -> None:
    if not WRITE_JSON:
        return
    payload = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "result_count": len(results),
        "results": results,
        "source_audit": audits,
    }
    with open(JSON_FILENAME, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    console.print(f"[green]✔ JSON saved: {JSON_FILENAME}[/green]")


# =============================================================================
# DISPLAY
# =============================================================================

def display_results(results: List[Dict[str, Any]]) -> None:
    if not results:
        console.print("[yellow]No matching UK IAM/PAM roles found.[/yellow]")
        return

    table = Table(title=f"UK IAM / PAM Discovery Results ({len(results)})")
    table.add_column("Company", style="cyan", no_wrap=True)
    table.add_column("Role", style="magenta")
    table.add_column("Location", style="green")
    table.add_column("Work", style="yellow")
    table.add_column("Terms", style="white")
    table.add_column("URL", style="blue", max_width=55)

    for r in results:
        table.add_row(
            r.get("company", ""),
            r.get("title", ""),
            r.get("location", ""),
            r.get("working_arrangement", ""),
            r.get("matched_keywords", ""),
            r.get("url", ""),
        )
    console.print(table)


def display_audit(audits: List[Dict[str, Any]]) -> None:
    table = Table(title="Source Audit")
    table.add_column("Company", style="cyan")
    table.add_column("Seeds", style="green")
    table.add_column("Pages", style="yellow")
    table.add_column("Job Links", style="magenta")
    table.add_column("Sitemap", style="white")
    table.add_column("Search", style="blue")
    table.add_column("Failed", style="red")

    for a in sorted(audits, key=lambda x: x["company"].lower()):
        table.add_row(
            a["company"],
            str(len(a["verified_seeds"])),
            str(a["pages_scanned"]),
            str(a["job_links_scanned"]),
            str(a["sitemap_urls"]),
            str(a["search_urls"]),
            str(len(a["failed_seeds"])),
        )
    console.print(table)


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    console.print("\n[bold cyan]🚀 UK IAM / PAM Job Discovery Engine v2[/bold cyan]")
    console.print(
        f"[cyan]Companies: {len(COMPANIES)} | "
        f"ATS boards: {len(ATS_BOARDS)} | "
        f"Search discovery: {'ON' if USE_SEARCH_DISCOVERY else 'OFF'} | "
        f"Playwright: {'ON' if USE_PLAYWRIGHT_FALLBACK else 'OFF'}[/cyan]\n"
    )

    if USE_PLAYWRIGHT_FALLBACK and not PLAYWRIGHT_AVAILABLE:
        console.print(
            "[yellow]Playwright not installed. The engine will still run, "
            "but JS-heavy sites may return fewer jobs.[/yellow]\n"
        )

    all_results: List[Dict[str, Any]] = []
    audits: List[Dict[str, Any]] = []

    # 1. ATS APIs
    console.print("[bold]1/2[/bold] Scanning public ATS APIs...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(scan_ats_board, b) for b in ATS_BOARDS]
        for future in as_completed(futures):
            try:
                all_results.extend(future.result())
            except Exception:
                pass
    console.print(f"   ATS matches: {len(all_results)}")

    # 2. Company sources
    console.print("\n[bold]2/2[/bold] Deep-scanning official careers sources + search discovery...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        future_map = {ex.submit(crawl_company, c): c for c in COMPANIES}
        completed = 0
        for future in as_completed(future_map):
            completed += 1
            company = future_map[future]
            try:
                results, audit = future.result()
                all_results.extend(results)
                audits.append(audit)
                console.print(
                    f"   [{completed:02d}/{len(COMPANIES):02d}] "
                    f"{company['name']}: {len(results)} match(es)"
                )
            except Exception as exc:
                console.print(f"   [red]{company['name']}: {exc}[/red]")

    all_results = dedupe(all_results)
    all_results.sort(key=lambda x: (x.get("company", "").lower(), x.get("title", "").lower()))

    # Optional webhook. Disabled by default.
    if SEND_TO_APPS_SCRIPT and all_results:
        console.print("\n[bold]Sending discovered jobs to Google Apps Script...[/bold]")
        sent = 0
        for job in all_results:
            result = send_to_apps_script(job)
            if result.get("success"):
                sent += 1
        console.print(f"[green]✔ Sent {sent}/{len(all_results)} jobs.[/green]")

    display_results(all_results)
    export_csv(all_results)
    export_json(all_results, audits)
    display_audit(audits)

    console.print(
        f"\n[bold green]✔ FINAL: {len(all_results)} unique UK IAM/PAM result(s)[/bold green]"
    )
    console.print(
        "[cyan]Policy: official company/ATS domains only. "
        "Search engines are used only to discover official/ATS URLs; "
        "LinkedIn, Indeed, Reed and other job-board URLs are rejected.[/cyan]"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        sys.exit(1)
