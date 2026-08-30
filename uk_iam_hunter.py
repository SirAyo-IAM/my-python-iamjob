#!/usr/bin/env python3
"""
UK IAM / PAM JOB DISCOVERY ENGINE v5.1
====================================

Purpose:
- Discover substantially more UK IAM / PAM / Identity Security vacancies.
- Search official company career sites deeply.
- Search Google + Bing for vacancies missed by career-page crawling.
- Discover recognised ATS job pages.
- Scan public Greenhouse / Lever / Workable APIs.
- Crawl sitemaps without requiring lxml.
- Handle JS-heavy sites when Playwright is installed.
- UK-wide: London, regional UK, remote UK, hybrid UK and onsite UK.
- Permanent-only: explicit contract/fixed-term/temporary/interim roles are excluded.
- V5 multi-channel discovery + high-precision relevance scoring prevents generic authentication/authorization pages from becoming IAM matches.
- V5 validates real job titles and UK job-location evidence before a result is retained.
- Does NOT use LinkedIn, Indeed, Reed or other job-board URLs as final results.
- Produces uk_iam_results.csv exactly for the existing GitHub workflow.
- Produces JSON and audit files.
- Optional Google Apps Script archiving.

GitHub Actions dependencies:
    pip install requests beautifulsoup4

Optional:
    pip install playwright
    playwright install chromium

Environment variables:
    ARCHIVE_TO_GOOGLE=true/false
    GOOGLE_APPS_SCRIPT_URL
    GOOGLE_APPS_SCRIPT_TOKEN
    USE_PLAYWRIGHT=true/false
    IAM_MIN_SCORE (optional, default 75)
    USE_GLOBAL_DISCOVERY=true/false
    BRAVE_SEARCH_API_KEY (optional, improves global search reliability)
"""

from __future__ import annotations

import csv
import html
import json
import os
import re
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import (
    parse_qs,
    parse_qsl,
    quote_plus,
    urlencode,
    unquote,
    urljoin,
    urlparse,
    urlunparse,
)

import requests
from bs4 import BeautifulSoup


# ============================================================================
# CONFIGURATION
# ============================================================================

REQUEST_TIMEOUT = int(os.getenv("IAM_REQUEST_TIMEOUT", "12"))
SEARCH_TIMEOUT = int(os.getenv("IAM_SEARCH_TIMEOUT", "8"))
JOB_TIMEOUT = int(os.getenv("IAM_JOB_TIMEOUT", "12"))

MAX_WORKERS = int(os.getenv("IAM_MAX_WORKERS", "8"))

# Deep discovery.
MAX_PAGES_PER_COMPANY = int(os.getenv("IAM_MAX_PAGES_PER_COMPANY", "6"))
MAX_JOB_LINKS_PER_COMPANY = int(os.getenv("IAM_MAX_JOB_LINKS_PER_COMPANY", "40"))
MAX_SITEMAP_URLS = int(os.getenv("IAM_MAX_SITEMAP_URLS", "500"))

# V5 open-ended discovery. Unlike V4, discovery is not limited to the
# predefined company database. Global search results and ATS/listing pages
# can introduce employers dynamically.
USE_GLOBAL_DISCOVERY = os.getenv("USE_GLOBAL_DISCOVERY", "true").lower() == "true"
USE_COMPANY_SEARCH_DISCOVERY = os.getenv(
    "USE_COMPANY_SEARCH_DISCOVERY", "false"
).lower() == "true"
SEARCH_ENGINE_MODE = os.getenv("SEARCH_ENGINE_MODE", "light").strip().lower()
COMPANY_SCAN_SECONDS = int(os.getenv("IAM_COMPANY_SCAN_SECONDS", "75"))
PLAYWRIGHT_BUDGET = int(os.getenv("IAM_PLAYWRIGHT_BUDGET", "10"))
_playwright_calls = 0
_playwright_lock = threading.Lock()
GLOBAL_SEARCH_QUERY_LIMIT = int(os.getenv("GLOBAL_SEARCH_QUERY_LIMIT", "12"))
MAX_GLOBAL_CANDIDATES = int(os.getenv("MAX_GLOBAL_CANDIDATES", "140"))
MAX_LISTING_LINKS = int(os.getenv("MAX_LISTING_LINKS", "60"))
BRAVE_SEARCH_API_KEY = os.getenv("BRAVE_SEARCH_API_KEY", "").strip()

# Search engine discovery.
USE_SEARCH_DISCOVERY = True
MAX_SEARCH_RESULTS = int(os.getenv("IAM_MAX_SEARCH_RESULTS", "12"))
SEARCH_QUERIES_PER_COMPANY = int(os.getenv("IAM_SEARCH_QUERIES_PER_COMPANY", "6"))

# High-precision V4 relevance threshold.
IAM_MIN_SCORE = int(os.getenv("IAM_MIN_SCORE", "75"))
HIGH_CONFIDENCE_SCORE = int(os.getenv("IAM_HIGH_CONFIDENCE_SCORE", "110"))

# Browser rendering.
USE_PLAYWRIGHT = os.getenv(
    "USE_PLAYWRIGHT",
    "false"
).lower() == "true"

PLAYWRIGHT_TIMEOUT_MS = int(os.getenv("IAM_PLAYWRIGHT_TIMEOUT_MS", "15000"))

# Google archive.
ARCHIVE_TO_GOOGLE = os.getenv(
    "ARCHIVE_TO_GOOGLE",
    "false"
).lower() == "true"

GOOGLE_APPS_SCRIPT_URL = os.getenv(
    "GOOGLE_APPS_SCRIPT_URL",
    ""
)

GOOGLE_APPS_SCRIPT_TOKEN = os.getenv(
    "GOOGLE_APPS_SCRIPT_TOKEN",
    ""
)

CSV_FILE = "uk_iam_results.csv"
JSON_FILE = "uk_iam_results.json"
AUDIT_FILE = "uk_iam_source_audit.csv"
RUN_LOG_FILE = "uk_iam_run_log.csv"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0 Safari/537.36"
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Language": "en-GB,en;q=0.9",
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,*/*;q=0.8"
    ),
}


# ============================================================================
# ATS ALLOW LIST
# ============================================================================

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
    "personio.com": "Personio",
    "phenompeople.com": "Phenom",
    "ultipro.com": "UKG",
    "ukg.com": "UKG",
    "applytojob.com": "ApplyToJob",
}


# ============================================================================
# IAM / PAM MATCHING - V4 HIGH PRECISION
# ============================================================================

# Terms in the TITLE are the strongest indicator that a vacancy is genuinely
# IAM/PAM rather than a generic role whose page happens to contain words such
# as "authentication" or "authorization".
TITLE_SIGNAL_WEIGHTS = {
    "identity & access": 105,
    "identity and access": 105,
    "identity access": 100,
    "iam governance": 100,
    "identity governance specialist": 105,
    "identity & access lead": 110,
    "identity and access lead": 110,
    "identity and access management": 105,
    "identity & access management": 105,
    "identity access management": 105,
    "iam engineer": 100,
    "iam analyst": 95,
    "iam architect": 100,
    "iam administrator": 90,
    "iam consultant": 95,
    "iam specialist": 95,
    "iam": 90,
    "identity engineer": 100,
    "identity architect": 100,
    "identity analyst": 95,
    "identity consultant": 95,
    "identity specialist": 95,
    "identity administrator": 90,
    "identity operations": 85,
    "identity security": 95,
    "identity governance": 100,
    "access governance": 95,
    "access management": 85,
    "access engineer": 85,
    "access analyst": 80,
    "access administrator": 80,
    "privileged access management": 105,
    "pam engineer": 100,
    "pam analyst": 95,
    "pam architect": 100,
    "pam": 85,
    "cyberark": 90,
    "sailpoint": 90,
    "saviynt": 90,
    "beyondtrust": 85,
    "delinea": 85,
    "okta": 80,
    "entra id": 80,
    "microsoft entra": 80,
    "azure ad": 75,
    "identitynow": 85,
    "identityiq": 85,
    "ping identity": 80,
    "pingfederate": 80,
    "forgerock": 80,
    "directory services": 70,
    "single sign-on": 70,
    "sso": 65,
}

# Body signals are grouped so synonyms do not artificially inflate scores.
# Each group contributes at most once.
BODY_SIGNAL_GROUPS = [
    ("IAM", 45, [
        "identity and access management", "identity & access management",
        "identity access management", " iam ",
    ]),
    ("Identity Governance / IGA", 38, [
        "identity governance", "access governance", " iga ", "sailpoint",
        "saviynt", "identityiq", "identitynow", "access certification",
        "access reviews", "entitlement management",
    ]),
    ("PAM", 42, [
        "privileged access management", "privileged access",
        "privileged identity", "cyberark", "beyondtrust", "delinea",
        "secret server", "privileged account",
    ]),
    ("Okta", 26, ["okta"]),
    ("Microsoft Identity", 28, [
        "entra id", "microsoft entra", "azure ad", "azure active directory",
        "conditional access", "privileged identity management",
    ]),
    ("Federation / SSO", 20, [
        "single sign-on", " sso ", "saml", "openid connect", "oidc",
        "federation", "oauth", "ws-federation", "pingfederate",
    ]),
    ("Provisioning / JML", 20, [
        "joiner mover leaver", "joiner-mover-leaver", " jml ",
        "provisioning", "deprovisioning", "identity lifecycle",
        "lifecycle management",
    ]),
    ("Access Reviews", 24, [
        "access review", "access reviews", "access certification",
        "recertification", "entitlement review",
    ]),
    ("SCIM / Automation", 14, [
        " scim ", "microsoft graph", "graph api", "identity automation",
    ]),
    ("RBAC / Least Privilege", 12, [
        " rbac ", "role based access", "role-based access",
        "least privilege", "access model",
    ]),
    ("Directory Services", 12, [
        "active directory", "directory services", "ldap", "azure ad connect",
    ]),
    ("Secrets Management", 18, [
        "hashicorp vault", "secrets management", "secret management",
        "credential vault",
    ]),
]

# These words occur on many unrelated websites and job adverts. They can be
# recorded as context, but they are never sufficient to qualify a vacancy.
WEAK_IAM_TERMS = [
    "authentication",
    "authorisation",
    "authorization",
    "access control",
    "security",
]

ADJACENT_TITLE_TERMS = [
    "security engineer",
    "security architect",
    "security consultant",
    "security analyst",
    "cloud security",
    "platform security",
    "directory services",
    "active directory",
    "microsoft 365",
]

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

# Search/corporate/navigation pages must never become final vacancies.
NON_JOB_TITLE_PATTERNS = [
    r"^search jobs(?:\b|\s*-)",
    r"^job search(?:\b|\s*-)",
    r"^careers?$",
    r"^careers? at ",
    r"^jobs? at ",
    r"^privacy (?:notice|statement|policy)",
    r"^cookie (?:notice|policy)",
    r"^terms (?:and|&) conditions",
    r"^meet ",
    r"^people$",
    r"^marketing$",
    r"^finance$",
    r"^operations$",
    r"^product$",
    r"^tech$",
    r"^culture(?: and| &)? ",
    r"^faq(?:s)?$",
    r"^home$",
]

NON_PERMANENT_TERMS = [
    "contract",
    "contractor",
    "fixed term",
    "fixed-term",
    "temporary",
    "interim",
    "freelance",
    "day rate",
    "daily rate",
    "inside ir35",
    "outside ir35",
]

# ============================================================================
# UK LOCATION
# ============================================================================

UK_TERMS = [
    "united kingdom",
    "great britain",
    "u.k.",
    "uk",
    "gb",
    "gbr",
    "england",
    "scotland",
    "wales",
    "northern ireland",
    "remote uk",
    "uk remote",
    "remote, uk",
    "remote - uk",
    "remote within the uk",
    "remote within uk",
    "based in the uk",
    "based in uk",

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
    "norwich",
    "leicester",
    "bath",
    "swindon",
    "warrington",
    "chester",
    "peterborough",
    "st albans",
    "watford",
    "canary wharf",
    "surrey",
    "berkshire",
    "hertfordshire",
    "essex",
    "kent",
    "hampshire",
    "west midlands",
    "east midlands",
    "north west",
    "north east",
    "south west",
    "south east",
    "yorkshire",
]


WORKING_TERMS = [
    "remote",
    "hybrid",
    "onsite",
    "on-site",
    "office-based",
    "office based",
    "home based",
    "home-based",
]

# If an actual job-location field clearly points outside the UK, V4 rejects the
# vacancy even when the global careers page contains UK text elsewhere.
FOREIGN_LOCATION_TERMS = [
    "united states", "usa", "u.s.a", "canada", "australia", "spain",
    "germany", "france", "italy", "belgium", "netherlands", "vietnam",
    "india", "singapore", "poland", "portugal", "switzerland", "austria",
    "united arab emirates", "dubai", "barcelona", "madrid", "paris",
    "berlin", "munich", "new york", "boston", "houston", "nashville",
    "seattle", "san francisco", "sydney", "melbourne", "macquarie park",
    "ho chi minh", "bengaluru", "bangalore", "mumbai", "hyderabad",
]

PLACEHOLDER_LOCATION_TERMS = [
    "location city",
    "state, country",
    "city, state, country",
    "near location",
    "choose locations",
    "select your preferred locations",
    "our locations",
    "locations",
    "all",
    "expand_more",
]


# ============================================================================
# V5 GLOBAL DISCOVERY
# ============================================================================

# Final results must still resolve to an employer careers page or recognised
# ATS. These domains are discovery-only job boards/aggregators and are rejected
# as final destinations.
BLOCKED_JOB_BOARD_DOMAINS = {
    "linkedin.com", "indeed.com", "reed.co.uk", "totaljobs.com",
    "cv-library.co.uk", "glassdoor.com", "jobsite.co.uk", "monster.co.uk",
    "adzuna.co.uk", "jooble.org", "simplyhired.co.uk", "ziprecruiter.com",
    "talent.com", "jobsora.com", "jobrapido.com", "careerjet.co.uk",
}

# Durable high-value sources. These are not individual vacancies; they are
# listing/ATS sources used to discover live vacancies.
DIRECT_DISCOVERY_SEEDS = [
    ("Barclays IAM search", "https://search.jobs.barclays/search-jobs/iam/22545/1/1"),
    ("Odevo jobs", "https://career.odevo.com/jobs"),
    ("Qube Greenhouse", "https://job-boards.greenhouse.io/quberesearchandtechnologies"),
]

# Greenhouse wrappers where the employer site renders {{ job.title }} and the
# actual vacancy data lives in Greenhouse. gh_jid is preserved by V5 URL
# canonicalisation and resolved through the public Greenhouse API.
GREENHOUSE_WRAPPER_BOARDS = {
    "qube-rt.com": ("Qube Research & Technologies", "quberesearchandtechnologies"),
    "www.qube-rt.com": ("Qube Research & Technologies", "quberesearchandtechnologies"),
}

GLOBAL_DISCOVERY_QUERIES = [
    '"IAM Engineer" (UK OR "United Kingdom" OR London) jobs',
    '"IAM Analyst" (UK OR "United Kingdom" OR London) jobs',
    '"Identity Engineer" (UK OR "United Kingdom" OR London) jobs',
    '"Identity & Access" (UK OR "United Kingdom" OR London) jobs',
    '"Identity and Access Management" (UK OR "United Kingdom") jobs',
    '"Identity Governance" (UK OR "United Kingdom") jobs',
    '"IAM Governance" (UK OR "United Kingdom") jobs',
    '"Access Governance" (UK OR "United Kingdom") jobs',
    '"SailPoint" (UK OR "United Kingdom") jobs identity',
    '"Saviynt" (UK OR "United Kingdom") jobs identity',
    '"CyberArk" (UK OR "United Kingdom") jobs PAM',
    '"Privileged Access Management" (UK OR "United Kingdom") jobs',
    '"PAM Engineer" (UK OR "United Kingdom") jobs',
    '"Okta Engineer" (UK OR "United Kingdom") jobs',
    '"Entra ID" identity (UK OR "United Kingdom") jobs',
    '"SSO Engineer" (UK OR "United Kingdom") jobs',
    '"Identity Security" (UK OR "United Kingdom") jobs',
    '"Access Management" (UK OR "United Kingdom") jobs identity',
]

DISCOVERY_TITLE_HINTS = [
    "iam", "identity", "access", "pam", "privileged", "cyberark",
    "sailpoint", "saviynt", "okta", "entra", "sso", "federation",
    "directory services", "security",
]

# ============================================================================
# COMPANY DATABASE
# ============================================================================

# Multiple seeds deliberately used where useful.
# Search discovery additionally searches each company's primary domain.

COMPANIES: List[Tuple[str, List[str], List[str]]] = [

    # ------------------------------------------------------------------------
    # BANKING / FINANCE
    # ------------------------------------------------------------------------

    (
        "HSBC",
        ["hsbc.com"],
        ["https://www.hsbc.com/careers"],
    ),

    (
        "Lloyds Banking Group",
        ["lloydsbankinggroup.com"],
        ["https://www.lloydsbankinggroup.com/careers/"],
    ),

    (
        "Barclays",
        ["barclays.com", "search.jobs.barclays"],
        [
            "https://home.barclays/careers/",
            "https://search.jobs.barclays/search-jobs/iam/22545/1/1",
        ],
    ),

    (
        "Standard Chartered",
        ["sc.com"],
        ["https://www.sc.com/en/careers/"],
    ),

    (
        "Morgan Stanley",
        ["morganstanley.com"],
        ["https://www.morganstanley.com/people-opportunities"],
    ),

    (
        "Goldman Sachs",
        ["goldmansachs.com"],
        ["https://www.goldmansachs.com/careers"],
    ),

    (
        "Citi",
        ["citi.com"],
        ["https://jobs.citi.com/"],
    ),

    (
        "JPMorgan Chase",
        ["jpmorganchase.com", "jpmorgan.com"],
        ["https://www.jpmorganchase.com/careers"],
    ),

    (
        "UBS",
        ["ubs.com"],
        ["https://www.ubs.com/global/en/careers.html"],
    ),

    (
        "Schroders",
        ["schroders.com"],
        ["https://www.schroders.com/en/global/individual/careers/"],
    ),

    (
        "MUFG",
        ["mufgemea.com", "mufg.co.uk"],
        ["https://www.mufgemea.com/careers/"],
    ),

    (
        "Deutsche Bank",
        ["db.com"],
        ["https://careers.db.com/"],
    ),

    (
        "NatWest Group",
        ["natwestgroup.com"],
        ["https://jobs.natwestgroup.com/"],
    ),

    (
        "Aviva",
        ["aviva.com"],
        ["https://www.aviva.com/careers/"],
    ),

    (
        "Legal & General",
        ["legalandgeneral.com"],
        ["https://careers.legalandgeneral.com/"],
    ),

    (
        "Fidelity International",
        ["fil.com"],
        ["https://www.fidelityinternational.com/careers/"],
    ),

    (
        "Man Group",
        ["man.com"],
        ["https://www.man.com/careers"],
    ),

    # ------------------------------------------------------------------------
    # FINTECH
    # ------------------------------------------------------------------------

    (
        "Revolut",
        ["revolut.com"],
        ["https://www.revolut.com/careers/"],
    ),

    (
        "Monzo",
        ["monzo.com"],
        ["https://monzo.com/careers/"],
    ),

    (
        "Wise",
        ["wise.jobs", "wise.com"],
        ["https://wise.jobs/"],
    ),

    (
        "Checkout.com",
        ["checkout.com"],
        ["https://www.checkout.com/careers"],
    ),

    (
        "Starling Bank",
        ["starlingbank.com"],
        ["https://www.starlingbank.com/careers/"],
    ),

    # ------------------------------------------------------------------------
    # TELECOMMUNICATIONS
    # ------------------------------------------------------------------------

    (
        "Virgin Media O2",
        ["virginmediao2.co.uk", "virginmedia.com"],
        ["https://www.virginmediao2.co.uk/careers/"],
    ),

    (
        "Sky",
        ["sky.com"],
        ["https://careers.sky.com/"],
    ),

    (
        "BT Group",
        ["bt.com"],
        ["https://www.bt.com/careers"],
    ),

    (
        "Openreach",
        ["openreach.com"],
        ["https://www.openreach.com/careers"],
    ),

    (
        "Vodafone / VodafoneThree",
        ["vodafone.com", "careers.vodafone.com"],
        ["https://careers.vodafone.com/"],
    ),

    # ------------------------------------------------------------------------
    # AIRLINES / AVIATION
    # ------------------------------------------------------------------------

    (
        "British Airways",
        ["ba.com"],
        ["https://careers.ba.com/"],
    ),

    (
        "Virgin Atlantic",
        ["virginatlantic.com"],
        ["https://careers.virginatlantic.com/"],
    ),

    (
        "easyJet",
        ["easyjet.com", "careers.easyjet.com"],
        ["https://careers.easyjet.com/en"],
    ),

    (
        "Heathrow Airport",
        ["heathrow.com"],
        ["https://www.heathrow.com/company/careers"],
    ),

    (
        "IAG",
        ["iairgroup.com"],
        ["https://careers.iairgroup.com/"],
    ),

    (
        "Jet2",
        ["jet2careers.com", "jet2.com"],
        ["https://www.jet2careers.com/"],
    ),

    (
        "Ryanair UK",
        ["ryanair.com"],
        ["https://careers.ryanair.com/"],
    ),

    # ------------------------------------------------------------------------
    # RAIL / TRANSPORT
    # ------------------------------------------------------------------------

    (
        "Network Rail",
        [
            "networkrail.co.uk",
            "operationscareers.networkrail.co.uk",
        ],
        [
            "https://www.networkrail.co.uk/careers/",
            "https://operationscareers.networkrail.co.uk/role-search/",
        ],
    ),

    (
        "Royal Mail Group",
        ["royalmailgroup.com"],
        ["https://careers.royalmailgroup.com/gb/en"],
    ),

    (
        "DHL UK",
        ["dhl.com"],
        ["https://careers.dhl.com/global/en/dhl-uk"],
    ),

    (
        "Stagecoach",
        ["stagecoachgroup.com"],
        ["https://www.stagecoachgroup.com/careers"],
    ),

    (
        "Transport for London",
        ["tfl.gov.uk"],
        ["https://tfl.gov.uk/corporate/careers/"],
    ),

    # ------------------------------------------------------------------------
    # ENERGY / UTILITIES
    # ------------------------------------------------------------------------

    (
        "SSE",
        ["sse.com", "careers.sse.com"],
        ["https://careers.sse.com/"],
    ),

    (
        "National Grid",
        ["nationalgrid.com", "jobs.nationalgrid.com"],
        ["https://jobs.nationalgrid.com/uk/jobs"],
    ),

    (
        "Centrica",
        ["centrica.com"],
        ["https://www.centrica.com/careers"],
    ),

    (
        "Energy & Utilities Jobs",
        ["energyutilitiesjobs.co.uk"],
        ["https://careers.energyutilitiesjobs.co.uk/"],
    ),

    (
        "Octopus Energy",
        ["octopus.energy"],
        ["https://octopus.energy/careers/"],
    ),

    # ------------------------------------------------------------------------
    # NHS / GOVERNMENT
    # ------------------------------------------------------------------------

    (
        "NHS Jobs",
        ["jobs.nhs.uk"],
        ["https://www.jobs.nhs.uk/"],
    ),

    (
        "NHS Scotland",
        ["careers.nhs.scot"],
        ["https://careers.nhs.scot/"],
    ),

    (
        "GCHQ",
        ["gchq-careers.co.uk"],
        ["https://www.gchq-careers.co.uk/"],
    ),

    # ------------------------------------------------------------------------
    # CONSULTING / TECHNOLOGY
    # ------------------------------------------------------------------------

    (
        "Computacenter",
        ["computacenter.com", "careers.computacenter.com"],
        ["https://careers.computacenter.com/uk/"],
    ),

    (
        "Sopra Steria",
        ["soprasteria.com", "careers.soprasteria.co.uk"],
        ["https://careers.soprasteria.co.uk/uk/en"],
    ),

    (
        "CGI UK",
        ["cgi.com"],
        ["https://www.cgi.com/uk/en-gb/careers"],
    ),

    (
        "Serco",
        ["serco.com", "careers.serco.com"],
        [
            "https://www.serco.com/uk/careers",
            "https://careers.serco.com/gb/en",
        ],
    ),

    (
        "Deloitte UK",
        ["deloitte.com", "apply.deloitte.com"],
        ["https://apply.deloitte.com/"],
    ),

    (
        "EY UK",
        ["ey.com", "careers.ey.com"],
        ["https://careers.ey.com/"],
    ),

    (
        "KPMG UK",
        ["kpmg.com"],
        ["https://kpmg.com/uk/en/careers.html"],
    ),

    (
        "PwC UK",
        ["pwc.co.uk", "jobs.pwc.co.uk"],
        [
            "https://www.pwc.co.uk/careers",
            "https://jobs.pwc.co.uk/uk/en/",
        ],
    ),

    # ------------------------------------------------------------------------
    # DEFENCE / ENGINEERING
    # ------------------------------------------------------------------------

    (
        "BAE Systems",
        ["baesystems.com"],
        ["https://www.baesystems.com/careers/"],
    ),

    (
        "Rolls-Royce",
        ["rolls-royce.com", "careers.rolls-royce.com"],
        ["https://careers.rolls-royce.com/our-locations/uk"],
    ),

    (
        "QinetiQ",
        ["qinetiq.com", "careers.qinetiq.com"],
        [
            "https://www.qinetiq.com/en-gb/careers",
            "https://careers.qinetiq.com/",
        ],
    ),

    (
        "Thales UK",
        ["thalesgroup.com"],
        ["https://careers.thalesgroup.com/"],
    ),

    (
        "Leonardo UK",
        ["leonardo.com"],
        ["https://www.leonardo.com/en/people/careers"],
    ),

    # ------------------------------------------------------------------------
    # PHARMA / ENTERPRISE
    # ------------------------------------------------------------------------

    (
        "GSK",
        ["gsk.com", "careers.gsk.com"],
        ["https://www.gsk.com/en-gb/careers/"],
    ),

    (
        "AstraZeneca",
        ["astrazeneca.com", "careers.astrazeneca.com"],
        ["https://careers.astrazeneca.com/search-jobs/united-kingdom"],
    ),

    (
        "Unilever UK",
        ["unilever.com", "careers.unilever.com"],
        ["https://careers.unilever.com/en/united-kingdom-and-ireland"],
    ),

    (
        "Ocado Group",
        ["ocado.com", "careers.ocadogroup.com"],
        ["https://careers.ocadogroup.com/"],
    ),

    (
        "Kingfisher",
        ["kingfisher.com", "careers.kingfisher.com"],
        ["https://careers.kingfisher.com/"],
    ),

    # ------------------------------------------------------------------------
    # TECHNOLOGY
    # ------------------------------------------------------------------------

    (
        "Microsoft UK",
        ["microsoft.com", "jobs.careers.microsoft.com"],
        ["https://jobs.careers.microsoft.com/global/en/search"],
    ),

    (
        "Apple UK",
        ["apple.com", "jobs.apple.com"],
        ["https://jobs.apple.com/en-gb/search?location=united-kingdom-GBR"],
    ),

    (
        "Amazon UK",
        ["amazon.jobs"],
        ["https://www.amazon.jobs/en-gb/"],
    ),

    (
        "Google UK",
        ["google.com"],
        ["https://www.google.com/about/careers/applications/"],
    ),

    (
        "Meta UK",
        ["metacareers.com"],
        ["https://www.metacareers.com/jobs/"],
    ),

    (
        "Canonical",
        ["canonical.com"],
        ["https://canonical.com/careers"],
    ),

    (
        "Darktrace",
        ["darktrace.com"],
        ["https://www.darktrace.com/en/careers"],
    ),

    (
        "Sophos",
        ["sophos.com"],
        ["https://www.sophos.com/en-us/careers"],
    ),

    (
        "Oracle",
        ["oracle.com"],
        ["https://www.oracle.com/careers/"],
    ),

    (
        "Odevo",
        ["career.odevo.com", "odevo.com"],
        ["https://career.odevo.com/jobs"],
    ),

    (
        "Qube Research & Technologies",
        ["qube-rt.com", "job-boards.greenhouse.io"],
        [
            "https://www.qube-rt.com/careers",
            "https://job-boards.greenhouse.io/quberesearchandtechnologies",
        ],
    ),

    # ------------------------------------------------------------------------
    # UNIVERSITY / OTHER LARGE EMPLOYERS
    # ------------------------------------------------------------------------

    (
        "University of Cambridge",
        ["cam.ac.uk", "jobs.cam.ac.uk"],
        ["https://www.jobs.cam.ac.uk/"],
    ),

    # ------------------------------------------------------------------------
    # ORACLE RECRUITING BOARD PROVIDED BY USER
    # ------------------------------------------------------------------------

    (
        "Oracle Recruiting CX_1003",
        ["oraclecloud.com"],
        [
            "https://don.fa.em2.oraclecloud.com/"
            "hcmUI/CandidateExperience/en/sites/CX_1003/"
        ],
    ),
]


# ============================================================================
# PUBLIC ATS APIs
# ============================================================================

ATS_BOARDS = [
    ("Qube Research & Technologies", "greenhouse", "quberesearchandtechnologies"),
    ("Monzo", "greenhouse", "monzo"),
    ("Deliveroo", "greenhouse", "deliveroo"),
    ("Checkout.com", "greenhouse", "checkoutcom"),
    ("Darktrace", "greenhouse", "darktrace"),
    ("Sophos", "greenhouse", "sophos"),
    ("Revolut", "lever", "revolut"),
    ("Canonical", "lever", "canonical"),
    ("Starling Bank", "workable", "starling-bank"),
]


# ============================================================================
# HTTP HELPERS
# ============================================================================

def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(HEADERS)
    return session


def host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def normalise_url(url: str) -> str:
    if not url:
        return ""

    url = html.unescape(str(url))
    url = url.replace("\\/", "/").strip()

    if url.startswith("//"):
        url = "https:" + url

    return url.rstrip("#")


def canonical_url(url: str) -> str:
    """Canonical URL used for deduplication.

    V5 preserves query parameters that identify a vacancy. This is important
    for employer wrappers such as Qube's /careers/job?gh_jid=123 where stripping
    the query would collapse every vacancy to the same URL.
    """

    url = normalise_url(url)
    if not url:
        return ""

    keep_params = {
        "gh_jid", "jobid", "job_id", "jid", "job", "reqid",
        "requisitionid", "requisition_id", "postingid", "posting_id",
    }

    try:
        parsed = urlparse(url)
        kept = [
            (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            if k.lower() in keep_params
        ]
        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip("/"),
            "",
            urlencode(kept),
            "",
        ))
    except Exception:
        return url.lower().rstrip("/")


def ats_platform(url: str) -> str:
    h = host(url)

    for domain, platform in ATS_DOMAINS.items():
        if h == domain or h.endswith("." + domain):
            return platform

    return ""


def same_domain(url: str, domains: Iterable[str]) -> bool:
    h = host(url)

    for domain in domains:
        domain = domain.lower().strip()

        if h == domain or h.endswith("." + domain):
            return True

    return False


def allowed_result_url(url: str, company: Tuple[str, List[str], List[str]]) -> bool:
    if same_domain(url, company[1]):
        return True

    if ats_platform(url):
        return True

    return False


def fetch(
    session: requests.Session,
    url: str,
    timeout: int = REQUEST_TIMEOUT,
) -> Optional[requests.Response]:

    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
        )

        if response.status_code >= 400:
            return None

        return response

    except requests.RequestException:
        return None


def is_html_response(response: requests.Response) -> bool:
    content_type = response.headers.get(
        "content-type",
        "",
    ).lower()

    return (
        "html" in content_type
        or "xml" in content_type
        or not content_type
    )


# ============================================================================
# TEXT HELPERS
# ============================================================================

def clean_text(value: str) -> str:
    if not value:
        return ""

    value = html.unescape(str(value))

    value = re.sub(
        r"<script[\s\S]*?</script>",
        " ",
        value,
        flags=re.I,
    )

    value = re.sub(
        r"<style[\s\S]*?</style>",
        " ",
        value,
        flags=re.I,
    )

    value = re.sub(
        r"<[^>]+>",
        " ",
        value,
    )

    value = re.sub(
        r"\s+",
        " ",
        value,
    )

    return value.strip()


def keyword_present(keyword: str, text: str) -> bool:
    if not keyword or not text:
        return False

    low = text.lower()

    # Short terms require word boundaries.
    if len(keyword) <= 4:
        return re.search(
            rf"(?<![a-z0-9]){re.escape(keyword.lower())}(?![a-z0-9])",
            low,
        ) is not None

    return keyword.lower() in low


def matched_terms(text: str, terms: Iterable[str]) -> List[str]:
    return [term for term in terms if keyword_present(term.strip(), text)]


def contains_uk(text: str) -> bool:
    low = (text or "").lower()

    for code in ("uk", "gb", "gbr"):
        if re.search(rf"(?<![a-z]){code}(?![a-z])", low):
            return True

    for term in UK_TERMS:
        if term in {"uk", "gb", "gbr"}:
            continue
        if term in low:
            return True

    return False


def is_placeholder_location(location: str) -> bool:
    low = re.sub(r"\s+", " ", (location or "").strip().lower())
    if not low:
        return True
    return low in PLACEHOLDER_LOCATION_TERMS or any(
        term in low for term in [
            "location city, state, country",
            "location city state country",
        ]
    )


def contains_foreign_location(location: str) -> bool:
    low = (location or "").lower()
    if contains_uk(low):
        return False
    return any(term in low for term in FOREIGN_LOCATION_TERMS)


def evaluate_uk_location(
    location: str,
    description: str,
    url: str,
) -> Tuple[bool, str]:
    location = (location or "").strip()

    if location and not is_placeholder_location(location):
        if contains_uk(location):
            return True, f"job location: {location[:180]}"
        if contains_foreign_location(location):
            return False, f"foreign job location: {location[:180]}"

    # Missing/placeholder/remote-only locations need explicit UK evidence in the
    # job-specific text or URL. We intentionally use only the leading body text
    # to reduce matches caused by global footer/navigation content.
    body_head = (description or "")[:6000]
    if contains_uk(body_head):
        return True, "UK evidence in job description"

    if contains_uk(url or ""):
        return True, "UK evidence in job URL"

    return False, "no job-specific UK evidence"


def is_non_job_title(title: str) -> bool:
    low = re.sub(r"\s+", " ", (title or "").strip().lower())
    if not low:
        return True

    for pattern in NON_JOB_TITLE_PATTERNS:
        if re.search(pattern, low, re.I):
            return True

    # Browser titles for result pages often append the employer name.
    generic_fragments = [
        "search jobs -",
        "job search -",
        "careers |",
        "careers -",
        "privacy notice |",
        "privacy statement |",
        "cookie notice |",
    ]
    return any(fragment in low for fragment in generic_fragments)


def explicit_non_permanent(
    title: str,
    description: str,
    employment_type: str = "",
) -> bool:
    title_low = (title or "").lower()
    emp_low = (employment_type or "").lower()

    if any(term in title_low for term in NON_PERMANENT_TERMS):
        return True

    if any(term in emp_low for term in [
        "contract", "fixed", "temporary", "interim", "freelance"
    ]):
        return True

    head = (description or "")[:3000].lower()
    patterns = [
        r"\b(?:employment type|job type|contract type)\s*[:\-]?\s*"
        r"(?:contract|fixed[- ]term|temporary|interim|freelance)\b",
        r"\b(?:contract|fixed[- ]term|temporary|interim)\s+"
        r"(?:role|position|assignment|opportunity)\b",
        r"\b\d{1,2}\s*(?:month|months)\s+(?:contract|ftc)\b",
        r"\b(?:inside|outside)\s+ir35\b",
        r"\b(?:day|daily)\s+rate\b",
    ]
    return any(re.search(pattern, head, re.I) for pattern in patterns)


def score_iam_relevance(
    title: str,
    description: str,
) -> Tuple[int, List[str], int, bool, bool]:
    title_low = f" {title.lower()} "
    body_low = f" {(description or '').lower()} "

    title_hits: List[str] = []
    title_score = 0

    # Use the single strongest title signal plus a small bonus for additional
    # independent title signals. This avoids overlapping synonyms exploding the
    # score while preserving strong titles such as "SailPoint IAM Engineer".
    title_candidates = []
    for term, weight in TITLE_SIGNAL_WEIGHTS.items():
        if keyword_present(term, title_low):
            title_candidates.append((term, weight))

    title_candidates.sort(key=lambda item: item[1], reverse=True)
    if title_candidates:
        title_score = title_candidates[0][1]
        title_hits.append(title_candidates[0][0])
        for term, weight in title_candidates[1:3]:
            if term not in title_hits:
                title_score += min(12, max(5, weight // 10))
                title_hits.append(term)

    body_hits: List[str] = []
    body_score = 0
    core_body_signals = 0

    for label, weight, terms in BODY_SIGNAL_GROUPS:
        hit = False
        for term in terms:
            needle = term.strip()
            if keyword_present(needle, body_low):
                hit = True
                break
        if hit:
            body_score += weight
            body_hits.append(label)
            if weight >= 20:
                core_body_signals += 1

    weak_hits = [term for term in WEAK_IAM_TERMS if keyword_present(term, body_low)]
    # Weak words contribute at most four points in total.
    body_score += min(4, len(weak_hits))

    adjacent_title = any(term in title_low for term in ADJACENT_TITLE_TERMS)
    title_anchor = bool(title_candidates)

    if adjacent_title and not title_anchor:
        title_score += 10

    score = title_score + body_score
    keywords = title_hits + body_hits
    if weak_hits and keywords:
        keywords.extend(f"context:{term}" for term in weak_hits[:3])

    return score, keywords, core_body_signals, title_anchor, adjacent_title


def extract_working_arrangement(text: str) -> str:
    low = text.lower()

    found = []

    for term in WORKING_TERMS:
        if term in low and term not in found:
            found.append(term)

    return ", ".join(found[:6])


def extract_employment_type(text: str) -> str:
    text = text or ""
    head = text[:3500]
    low = head.lower()

    explicit_patterns = [
        ("Fixed-term", r"\bfixed[- ]term\b"),
        ("Contract", r"\b\d{1,2}\s*(?:month|months)\s+(?:contract|ftc)\b"),
        ("Contract", r"\b(?:employment type|job type|contract type)\s*[:\-]?\s*contract\b"),
        ("Temporary", r"\btemporary\s+(?:role|position|assignment)\b"),
        ("Interim", r"\binterim\s+(?:role|position|assignment)\b"),
        ("Permanent", r"\bpermanent\b"),
        ("Full-time", r"\bfull[- ]time\b"),
    ]

    for label, pattern in explicit_patterns:
        if re.search(pattern, low, re.I):
            return label

    return ""


def extract_salary(text: str) -> str:
    if not text:
        return ""

    patterns = [
        r"£\s?[\d,]+(?:\s?[-–]\s?£?\s?[\d,]+)?(?:\s?(?:per annum|pa|a year|per year))?",
        r"£\s?[\d,]+k(?:\s?[-–]\s?£?\s?[\d,]+k)?",
        r"salary[^.]{0,120}",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            text,
            re.I,
        )

        if match:
            return re.sub(
                r"\s+",
                " ",
                match.group(0),
            ).strip()

    return ""


def extract_reference(text: str) -> str:
    if not text:
        return ""

    patterns = [

        r"\b(?:requisition|requisition id|requisition number)"
        r"\s*[:#-]?\s*([A-Z0-9][A-Z0-9_-]{3,})",

        r"\b(?:job id|job reference|job ref|job number)"
        r"\s*[:#-]?\s*([A-Z0-9][A-Z0-9_-]{3,})",

        r"\b(?:req|ref)\s*[:#-]\s*([A-Z0-9][A-Z0-9_-]{3,})",

        r"\b(?:JR|REQ)-?\d{4,}\b",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            text,
            re.I,
        )

        if match:

            if match.lastindex:
                return match.group(1)

            return match.group(0)

    return ""


def extract_posted_date(text: str) -> str:

    patterns = [

        r"(?:posted|posting date|date posted)"
        r"\s*[:\-]?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})",

        r"(?:posted|posting date|date posted)"
        r"\s*[:\-]?\s*([A-Z][a-z]+\s+\d{1,2},\s+\d{4})",

        r"(?:posted|posting date|date posted)"
        r"\s*[:\-]?\s*(\d{4}-\d{2}-\d{2})",

        r"\b(20\d{2}-\d{2}-\d{2})\b",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            text,
            re.I,
        )

        if match:
            return match.group(1)

    return ""


# ============================================================================
# TARGET MATCHING
# ============================================================================

def is_target_job(
    title: str,
    description: str,
    location: str,
    url: str,
    employment_type: str = "",
) -> Tuple[bool, List[str], int, str, str]:
    title = (title or "").strip()
    description = description or ""

    if not title:
        return False, [], 0, "REJECTED", "missing title"

    title_low = title.lower()

    if is_non_job_title(title):
        return False, [], 0, "REJECTED", "navigation/non-job page title"

    for excluded in EXCLUDED_TITLE_TERMS:
        if excluded in title_low:
            return False, [], 0, "REJECTED", f"excluded title term: {excluded}"

    if explicit_non_permanent(title, description, employment_type):
        return False, [], 0, "REJECTED", "explicit non-permanent employment"

    uk_ok, uk_evidence = evaluate_uk_location(location, description, url)
    if not uk_ok:
        return False, [], 0, "REJECTED", uk_evidence

    score, keywords, core_body_signals, title_anchor, adjacent_title = (
        score_iam_relevance(title, description)
    )

    # Qualification gates:
    # 1) Strong IAM title -> normal threshold.
    # 2) Security-adjacent title -> at least two core IAM body groups.
    # 3) Generic title -> at least three core IAM groups and a higher score.
    if title_anchor:
        matched = score >= IAM_MIN_SCORE
    elif adjacent_title:
        matched = score >= max(IAM_MIN_SCORE, 80) and core_body_signals >= 2
    else:
        matched = score >= max(IAM_MIN_SCORE, 90) and core_body_signals >= 3

    if not matched:
        reason = (
            f"IAM score {score} below qualification gate; "
            f"core body signals={core_body_signals}"
        )
        return False, keywords, score, "REJECTED", reason

    confidence = "HIGH" if score >= HIGH_CONFIDENCE_SCORE else "MEDIUM"
    reason = (
        f"{confidence} IAM match; score={score}; "
        f"core body signals={core_body_signals}; {uk_evidence}"
    )

    return True, keywords, score, confidence, reason


# ============================================================================
# JSON-LD EXTRACTION

# ============================================================================

def extract_jsonld_jobs(
    soup: BeautifulSoup,
    base_url: str,
) -> List[Dict[str, Any]]:

    jobs = []

    scripts = soup.find_all(
        "script",
        type="application/ld+json",
    )

    for script in scripts:

        raw = (
            script.string
            or script.get_text()
            or ""
        )

        if not raw.strip():
            continue

        try:
            data = json.loads(raw)

        except Exception:

            # Some sites contain multiple JSON objects or malformed JSON.
            # Try to repair common wrapping problems.
            raw_clean = raw.strip()

            raw_clean = re.sub(
                r",\s*}",
                "}",
                raw_clean,
            )

            raw_clean = re.sub(
                r",\s*]",
                "]",
                raw_clean,
            )

            try:
                data = json.loads(raw_clean)

            except Exception:
                continue

        if isinstance(data, list):

            items = data

        elif (
            isinstance(data, dict)
            and isinstance(data.get("@graph"), list)
        ):

            items = data["@graph"]

        elif isinstance(data, dict):

            items = [data]

        else:
            continue

        for item in items:

            if not isinstance(item, dict):
                continue

            item_type = item.get("@type")

            if isinstance(item_type, list):

                is_job = any(
                    str(x).lower() == "jobposting"
                    for x in item_type
                )

            else:

                is_job = (
                    str(item_type).lower()
                    == "jobposting"
                )

            if not is_job:
                continue

            title = str(
                item.get("title", "")
            ).strip()

            description = BeautifulSoup(
                str(
                    item.get(
                        "description",
                        "",
                    )
                ),
                "html.parser",
            ).get_text(
                " ",
                strip=True,
            )

            # Location.
            raw_location = item.get(
                "jobLocation",
                "",
            )

            def parse_location(value: Any) -> str:

                if not isinstance(value, dict):
                    return str(value or "")

                address = value.get(
                    "address",
                    value,
                )

                if isinstance(address, dict):

                    parts = [
                        address.get(
                            "addressLocality",
                            "",
                        ),
                        address.get(
                            "addressRegion",
                            "",
                        ),
                        address.get(
                            "postalCode",
                            "",
                        ),
                        address.get(
                            "addressCountry",
                            "",
                        ),
                    ]

                    return ", ".join(
                        str(x)
                        for x in parts
                        if x
                    )

                return str(address or "")

            if isinstance(raw_location, list):

                location = " | ".join(
                    parse_location(x)
                    for x in raw_location
                )

            else:

                location = parse_location(
                    raw_location
                )

            job_url = urljoin(
                base_url,
                str(
                    item.get(
                        "url",
                        base_url,
                    )
                ),
            )

            salary = ""

            raw_salary = item.get(
                "baseSalary",
                "",
            )

            if isinstance(raw_salary, dict):

                currency = raw_salary.get(
                    "currency",
                    "",
                )

                value = raw_salary.get(
                    "value",
                    raw_salary,
                )

                if isinstance(value, dict):

                    minimum = value.get(
                        "minValue",
                        "",
                    )

                    maximum = value.get(
                        "maxValue",
                        "",
                    )

                    single = value.get(
                        "value",
                        "",
                    )

                    if minimum and maximum:

                        salary = (
                            f"{currency} "
                            f"{minimum}-{maximum}"
                        ).strip()

                    elif single:

                        salary = (
                            f"{currency} "
                            f"{single}"
                        ).strip()

                else:

                    salary = str(value or "")

            elif raw_salary:

                salary = str(raw_salary)

            jobs.append(
                {
                    "title": title,
                    "description": description,
                    "location": location,
                    "url": job_url,
                    "date_posted": str(
                        item.get(
                            "datePosted",
                            "",
                        )
                        or ""
                    ),
                    "employment_type": str(
                        item.get(
                            "employmentType",
                            "",
                        )
                        or ""
                    ),
                    "salary": salary,
                }
            )

    return jobs


# ============================================================================
# LINK DISCOVERY
# ============================================================================

JOB_URL_HINTS = [
    "job",
    "jobs",
    "jobdetail",
    "job-detail",
    "jobdetails",
    "viewjob",
    "view-job",
    "vacanc",
    "opportunit",
    "position",
    "opening",
    "requisition",
    "apply",
    "employment",
    "career",
    "careers",
    "role",
]


PAGINATION_HINTS = [
    "page=",
    "page/",
    "start=",
    "offset=",
    "from=",
    "load-more",
    "loadmore",
    "next",
    "view-all",
    "viewall",
    "all-jobs",
    "search-jobs",
    "search?query",
    "jobs?query",
]


def looks_like_job_url(
    url: str,
    anchor_text: str = "",
) -> bool:

    blob = (
        f"{url} "
        f"{anchor_text}"
    ).lower()

    return any(
        hint in blob
        for hint in JOB_URL_HINTS
    )


def looks_like_pagination(
    url: str,
    anchor_text: str = "",
) -> bool:

    blob = (
        f"{url} "
        f"{anchor_text}"
    ).lower()

    return any(
        hint in blob
        for hint in PAGINATION_HINTS
    )


def extract_links(
    soup: BeautifulSoup,
    base_url: str,
) -> Tuple[List[str], List[str]]:

    job_links = []
    page_links = []

    seen_jobs = set()
    seen_pages = set()

    for anchor in soup.find_all(
        "a",
        href=True,
    ):

        href = str(
            anchor.get(
                "href",
                "",
            )
        ).strip()

        if not href:
            continue

        if href.lower().startswith(
            (
                "javascript:",
                "mailto:",
                "tel:",
                "#",
            )
        ):
            continue

        absolute = normalise_url(
            urljoin(
                base_url,
                href,
            )
        )

        if not absolute.startswith(
            (
                "http://",
                "https://",
            )
        ):
            continue

        anchor_text = anchor.get_text(
            " ",
            strip=True,
        )

        if looks_like_job_url(
            absolute,
            anchor_text,
        ):

            key = canonical_url(
                absolute
            )

            if (
                key
                and key not in seen_jobs
            ):

                seen_jobs.add(key)
                job_links.append(absolute)

        if looks_like_pagination(
            absolute,
            anchor_text,
        ):

            key = canonical_url(
                absolute
            )

            if (
                key
                and key not in seen_pages
            ):

                seen_pages.add(key)
                page_links.append(absolute)

    # Iframes are particularly important for ATS portals.
    for iframe in soup.find_all(
        "iframe",
        src=True,
    ):

        iframe_url = normalise_url(
            urljoin(
                base_url,
                iframe.get(
                    "src",
                    "",
                ),
            )
        )

        if iframe_url.startswith(
            (
                "http://",
                "https://",
            )
        ):

            if (
                ats_platform(iframe_url)
                or looks_like_job_url(
                    iframe_url
                )
            ):

                page_links.append(
                    iframe_url
                )

    return (
        list(dict.fromkeys(job_links)),
        list(dict.fromkeys(page_links)),
    )


# ============================================================================
# SITEMAP DISCOVERY
# ============================================================================

def discover_sitemaps(
    session: requests.Session,
    seed_url: str,
) -> List[str]:

    parsed = urlparse(seed_url)

    if not parsed.scheme or not parsed.netloc:
        return []

    origin = (
        f"{parsed.scheme}://"
        f"{parsed.netloc}"
    )

    found = [
        origin + "/sitemap.xml",
        origin + "/sitemap_index.xml",
    ]

    robots = fetch(
        session,
        origin + "/robots.txt",
        10,
    )

    if robots:

        for line in robots.text.splitlines():

            if line.lower().startswith(
                "sitemap:"
            ):

                value = line.split(
                    ":",
                    1,
                )[1].strip()

                if value.startswith(
                    "http"
                ):
                    found.append(value)

    return list(
        dict.fromkeys(found)
    )


def parse_sitemap(
    session: requests.Session,
    sitemap_url: str,
) -> List[str]:

    discovered = []

    queue = [sitemap_url]
    seen = set()

    while (
        queue
        and len(discovered)
        < MAX_SITEMAP_URLS
    ):

        current = queue.pop(0)

        if current in seen:
            continue

        seen.add(current)

        response = fetch(
            session,
            current,
            15,
        )

        if not response:
            continue

        content = response.text

        # IMPORTANT:
        #
        # Do NOT use:
        #
        # BeautifulSoup(content, "xml")
        #
        # because that requires an XML parser such as lxml.
        #
        # GitHub Actions only installs requests/BeautifulSoup.
        #
        # Regex is sufficient for sitemap <loc> extraction and eliminates
        # the error that caused the previous scanner to fail on almost every
        # company.

        locations = re.findall(
            r"<loc>\s*(.*?)\s*</loc>",
            content,
            flags=re.I | re.S,
        )

        is_index = (
            "<sitemapindex"
            in content.lower()
            or "<sitemap>"
            in content.lower()
        )

        for location in locations:

            value = html.unescape(
                location.strip()
            )

            if not value.startswith(
                "http"
            ):
                continue

            if is_index:

                if value not in seen:
                    queue.append(value)

            else:

                discovered.append(value)

                if (
                    len(discovered)
                    >= MAX_SITEMAP_URLS
                ):
                    break

    return list(
        dict.fromkeys(discovered)
    )


# ============================================================================
# SEARCH ENGINE DISCOVERY
# ============================================================================

def google_search(
    session: requests.Session,
    query: str,
) -> List[str]:

    results = []

    url = (
        "https://www.google.com/search"
        "?q="
        + quote_plus(query)
        + "&num=20"
        + "&hl=en-GB"
        + "&filter=0"
    )

    response = fetch(
        session,
        url,
        SEARCH_TIMEOUT,
    )

    if not response:
        return results

    soup = BeautifulSoup(
        response.text,
        "html.parser",
    )

    for anchor in soup.find_all(
        "a",
        href=True,
    ):

        href = str(
            anchor.get(
                "href",
                "",
            )
        )

        if href.startswith(
            "/url?"
        ):

            parsed = urlparse(
                href
            )

            href = parse_qs(
                parsed.query
            ).get(
                "q",
                [""],
            )[0]

        elif href.startswith(
            "//"
        ):

            href = "https:" + href

        href = unquote(href)

        if not href.startswith(
            (
                "http://",
                "https://",
            )
        ):
            continue

        if "google.com/search" in href:
            continue

        results.append(href)

        if len(results) >= MAX_SEARCH_RESULTS:
            break

    return list(
        dict.fromkeys(results)
    )


def bing_search(
    session: requests.Session,
    query: str,
) -> List[str]:

    results = []

    url = (
        "https://www.bing.com/search"
        "?q="
        + quote_plus(query)
        + "&count=20"
        + "&setlang=en-GB"
    )

    response = fetch(
        session,
        url,
        SEARCH_TIMEOUT,
    )

    if not response:
        return results

    soup = BeautifulSoup(
        response.text,
        "html.parser",
    )

    for anchor in soup.select(
        "li.b_algo h2 a, h2 a"
    ):

        href = anchor.get(
            "href",
            "",
        )

        if not href.startswith(
            (
                "http://",
                "https://",
            )
        ):
            continue

        results.append(href)

        if len(results) >= MAX_SEARCH_RESULTS:
            break

    return list(
        dict.fromkeys(results)
    )


def bing_rss_search(
    session: requests.Session,
    query: str,
) -> List[str]:
    """Use Bing's RSS representation when available.

    RSS is useful on CI runners because it avoids depending entirely on the
    layout of a JavaScript-heavy search results page.
    """
    results: List[str] = []
    url = (
        "https://www.bing.com/search?q="
        + quote_plus(query)
        + "&format=rss&setlang=en-GB"
    )
    response = fetch(session, url, SEARCH_TIMEOUT)
    if not response:
        return results

    for value in re.findall(r"<link>(.*?)</link>", response.text, re.I | re.S):
        candidate = html.unescape(value.strip())
        if not candidate.startswith(("http://", "https://")):
            continue
        if "bing.com/search" in candidate:
            continue
        results.append(candidate)
        if len(results) >= MAX_SEARCH_RESULTS:
            break
    return list(dict.fromkeys(results))


def duckduckgo_search(
    session: requests.Session,
    query: str,
) -> List[str]:
    results: List[str] = []
    url = "https://html.duckduckgo.com/html/?q=" + quote_plus(query)
    response = fetch(session, url, SEARCH_TIMEOUT)
    if not response:
        return results

    soup = BeautifulSoup(response.text, "html.parser")
    for anchor in soup.select("a.result__a, a.result-link"):
        href = str(anchor.get("href", "")).strip()
        if not href:
            continue
        if href.startswith("//"):
            href = "https:" + href
        parsed = urlparse(href)
        if "duckduckgo.com" in parsed.netloc and parsed.query:
            href = parse_qs(parsed.query).get("uddg", [href])[0]
        href = unquote(href)
        if href.startswith(("http://", "https://")):
            results.append(href)
        if len(results) >= MAX_SEARCH_RESULTS:
            break
    return list(dict.fromkeys(results))


def brave_search(
    session: requests.Session,
    query: str,
) -> List[str]:
    if not BRAVE_SEARCH_API_KEY:
        return []

    try:
        response = session.get(
            "https://api.search.brave.com/res/v1/web/search",
            headers={
                "Accept": "application/json",
                "X-Subscription-Token": BRAVE_SEARCH_API_KEY,
            },
            params={
                "q": query,
                "count": min(MAX_SEARCH_RESULTS, 20),
                "country": "gb",
                "search_lang": "en",
                "safesearch": "moderate",
            },
            timeout=SEARCH_TIMEOUT,
        )
        if response.status_code != 200:
            return []
        data = response.json()
        return [
            str(item.get("url", ""))
            for item in (data.get("web", {}) or {}).get("results", [])
            if str(item.get("url", "")).startswith(("http://", "https://"))
        ][:MAX_SEARCH_RESULTS]
    except Exception:
        return []


def search_urls(
    session: requests.Session,
    query: str,
) -> List[str]:
    """V5 multi-engine search discovery.

    Search engines are discovery mechanisms only. Final URLs are validated
    separately and job-board/aggregator destinations are rejected.
    """
    results: List[str] = []

    if SEARCH_ENGINE_MODE == "full":
        engines = [google_search, bing_search, bing_rss_search, duckduckgo_search]
    else:
        engines = [bing_rss_search, duckduckgo_search]

    if BRAVE_SEARCH_API_KEY:
        engines.insert(0, brave_search)

    for engine in engines:
        try:
            results.extend(engine(session, query))
        except Exception:
            continue

    return list(dict.fromkeys(results))


def build_search_queries(
    company: Tuple[str, List[str], List[str]],
) -> List[str]:

    name, domains, _ = company

    # Group related terms so the query budget covers the whole IAM landscape
    # instead of truncating the list before Okta/Entra/Saviynt searches run.
    groups = [
        '("IAM" OR "Identity and Access Management" OR "Identity Engineer" OR "Identity Analyst")',
        '("Identity Governance" OR "Access Governance" OR IGA OR SailPoint OR Saviynt)',
        '("Privileged Access Management" OR PAM OR CyberArk OR BeyondTrust OR Delinea)',
        '(Okta OR "Entra ID" OR "Microsoft Entra" OR "Azure AD" OR SSO OR federation)',
        '("Access Management" OR "Access Reviews" OR "Access Certification" OR "Entitlement Management")',
        '("Identity Security" OR "Zero Trust" OR "Privileged Identity" OR PIM)',
    ]

    uk_scope = (
        '(UK OR "United Kingdom" OR "Great Britain" OR London OR England OR '
        'Scotland OR Wales OR "Northern Ireland" OR remote OR hybrid)'
    )

    job_scope = (
        '(job OR jobs OR careers OR vacancy OR position OR opportunity OR recruitment)'
    )

    queries = []

    # Search official company domains. Use up to two domains where supplied.
    for domain in domains[:2]:
        for group in groups[:4]:
            queries.append(
                f'site:{domain} {group} {uk_scope} {job_scope}'
            )

    # Search common external ATS hosts by company name. A pure site:<company>
    # search cannot discover Workday/Greenhouse/Lever pages hosted elsewhere.
    ats_scope = (
        '(site:myworkdayjobs.com OR site:greenhouse.io OR site:lever.co OR '
        'site:smartrecruiters.com OR site:ashbyhq.com OR site:teamtailor.com OR '
        'site:icims.com OR site:successfactors.com OR site:oraclecloud.com)'
    )

    for group in groups:
        queries.append(
            f'"{name}" {group} {uk_scope} {ats_scope}'
        )

    return list(dict.fromkeys(queries))[:SEARCH_QUERIES_PER_COMPANY]


# ============================================================================
# V5 DYNAMIC / OPEN-ENDED DISCOVERY
# ============================================================================


def is_blocked_job_board(url: str) -> bool:
    h = host(url)
    return any(h == d or h.endswith("." + d) for d in BLOCKED_JOB_BOARD_DOMAINS)


def looks_like_official_job_candidate(url: str) -> bool:
    if not url or is_blocked_job_board(url):
        return False
    if ats_platform(url):
        return True

    parsed = urlparse(url)
    path_blob = f"{parsed.netloc} {parsed.path} {parsed.query}".lower()
    return any(
        hint in path_blob
        for hint in [
            "/job", "/jobs", "career", "vacanc", "requisition",
            "position", "opening", "opportunit", "gh_jid=",
        ]
    )


def looks_like_listing_url(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower().rstrip("/")
    query = parsed.query.lower()
    if "search-jobs" in path or "search-jobs" in query:
        return True
    return path.endswith(("/jobs", "/careers", "/career", "/vacancies", "/opportunities"))


def company_name_from_soup(soup: BeautifulSoup, url: str) -> str:
    # Prefer JobPosting.hiringOrganization when available.
    for script in soup.find_all("script", type="application/ld+json"):
        raw = script.string or script.get_text() or ""
        if not raw.strip():
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
            items = []
        for item in items:
            if not isinstance(item, dict):
                continue
            org = item.get("hiringOrganization")
            if isinstance(org, dict) and org.get("name"):
                return str(org.get("name")).strip()

    meta = soup.find("meta", attrs={"property": "og:site_name"})
    if meta and meta.get("content"):
        return str(meta.get("content")).strip()

    h = host(url)
    if h.startswith("www."):
        h = h[4:]
    bits = h.split(".")
    stem = bits[-2] if len(bits) >= 2 else h
    return stem.replace("-", " ").replace("_", " ").title() or "Discovered Employer"


def dynamic_company(url: str, soup: Optional[BeautifulSoup] = None) -> Tuple[str, List[str], List[str]]:
    name = company_name_from_soup(soup, url) if soup is not None else host(url)
    return (name or "Discovered Employer", [host(url)], [])


def greenhouse_identity_from_url(url: str) -> Tuple[str, str]:
    """Return (board_token, job_id) for Greenhouse job-board URLs."""
    parsed = urlparse(url)
    h = parsed.netloc.lower()
    path_parts = [part for part in parsed.path.split("/") if part]

    if h in {"job-boards.greenhouse.io", "boards.greenhouse.io"} and path_parts:
        board = path_parts[0]
        job_id = ""
        if "jobs" in path_parts:
            idx = path_parts.index("jobs")
            if idx + 1 < len(path_parts):
                job_id = re.sub(r"\D", "", path_parts[idx + 1])
        return board, job_id

    wrapper = GREENHOUSE_WRAPPER_BOARDS.get(h)
    if wrapper:
        job_id = parse_qs(parsed.query).get("gh_jid", [""])[0]
        return wrapper[1], re.sub(r"\D", "", str(job_id))

    return "", ""


def scan_greenhouse_job_by_id(
    board: str,
    job_id: str,
    company_name: str = "",
    original_url: str = "",
) -> List[Dict[str, Any]]:
    if not board or not job_id:
        return []

    session = make_session()
    try:
        response = session.get(
            f"https://boards-api.greenhouse.io/v1/boards/{board}/jobs/{job_id}",
            params={"questions": "false"},
            timeout=JOB_TIMEOUT,
        )
        if response.status_code != 200:
            return []
        job = response.json()
    except Exception:
        return []

    title = str(job.get("title", ""))
    description = clean_text(str(job.get("content", "")))
    location = str((job.get("location") or {}).get("name", ""))
    url = original_url or str(job.get("absolute_url", ""))
    if not url:
        url = f"https://job-boards.greenhouse.io/{board}/jobs/{job_id}"

    company = (
        company_name or str((job.get("company") or {}).get("name", "")) or board,
        [host(url), "job-boards.greenhouse.io"],
        [],
    )
    result = build_result(
        company=company,
        title=title,
        description=description,
        location=location,
        url=url,
        method="Greenhouse Job API -> V5.1 dynamic discovery",
    )
    return [result] if result else []


def fetch_candidate_page(url: str) -> Optional[Tuple[str, str]]:
    session = make_session()
    response = fetch(session, url, JOB_TIMEOUT)
    html_content: Optional[str] = None
    final_url = url

    if response and is_html_response(response):
        html_content = response.text
        final_url = normalise_url(response.url)
        static_text = clean_text(html_content)
        if USE_PLAYWRIGHT and len(static_text) < 900:
            rendered = render_page(final_url)
            if rendered:
                html_content, final_url = rendered
    elif USE_PLAYWRIGHT:
        rendered = render_page(url)
        if rendered:
            html_content, final_url = rendered

    if not html_content:
        return None
    return html_content, final_url


def extract_results_from_candidate(
    url: str,
    method: str = "V5.1 global discovery",
) -> List[Dict[str, Any]]:
    """Fetch one discovered URL and turn it into zero or more validated jobs."""
    url = normalise_url(url)
    if not looks_like_official_job_candidate(url):
        return []

    board, job_id = greenhouse_identity_from_url(url)
    if board and job_id:
        wrapper = GREENHOUSE_WRAPPER_BOARDS.get(host(url))
        company_name = wrapper[0] if wrapper else ""
        api_results = scan_greenhouse_job_by_id(board, job_id, company_name, url)
        if api_results:
            return api_results

    fetched = fetch_candidate_page(url)
    if not fetched:
        return []
    html_content, final_url = fetched
    soup = BeautifulSoup(html_content, "html.parser")
    company = dynamic_company(final_url, soup)

    results: List[Dict[str, Any]] = []
    structured_jobs = extract_jsonld_jobs(soup, final_url)
    for job in structured_jobs:
        result = build_result(
            company=company,
            title=job.get("title", ""),
            description=job.get("description", ""),
            location=job.get("location", ""),
            url=job.get("url", final_url),
            method=f"{method} -> JSON-LD JobPosting",
            date_posted=job.get("date_posted", ""),
            employment_type=job.get("employment_type", ""),
            salary=job.get("salary", ""),
        )
        if result:
            results.append(result)

    if results:
        return deduplicate(results)

    # Generic HTML fallback for platforms such as TalentBrew/Teamtailor.
    title = page_title(soup)
    text = soup.get_text(" ", strip=True)
    location = extract_location(soup)
    result = build_result(
        company=company,
        title=title,
        description=text,
        location=location,
        url=final_url,
        method=f"{method} -> HTML Job Page",
    )
    return [result] if result else []


def discover_candidate_links_from_listing(url: str) -> List[str]:
    fetched = fetch_candidate_page(url)
    if not fetched:
        return []
    html_content, final_url = fetched
    soup = BeautifulSoup(html_content, "html.parser")

    ranked: List[Tuple[int, str]] = []
    seen: Set[str] = set()
    for anchor in soup.find_all("a", href=True):
        href = normalise_url(urljoin(final_url, str(anchor.get("href", ""))))
        if not href.startswith(("http://", "https://")):
            continue
        if is_blocked_job_board(href):
            continue
        if not looks_like_official_job_candidate(href):
            continue
        text = anchor.get_text(" ", strip=True).lower()
        blob = f"{text} {href.lower()}"
        priority = 2 if any(term in blob for term in DISCOVERY_TITLE_HINTS) else 0
        if looks_like_job_url(href, text):
            priority += 1
        if priority <= 0:
            continue
        key = canonical_url(href)
        if key in seen:
            continue
        seen.add(key)
        ranked.append((priority, href))

    ranked.sort(key=lambda item: item[0], reverse=True)
    return [url for _, url in ranked[:MAX_LISTING_LINKS]]


def global_discovery() -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Open-ended discovery independent of the predefined company list."""
    audit: Dict[str, Any] = {
        "company": "GLOBAL DISCOVERY",
        "source_type": "global",
        "seeds": 0,
        "pages": 0,
        "job_links": 0,
        "sitemap_urls": 0,
        "search_urls": 0,
        "queries": 0,
        "candidate_urls": 0,
        "listings": 0,
        "rejected": 0,
        "matches": 0,
        "errors": 0,
        "status": "VERIFIED",
    }

    session = make_session()
    discovered: List[str] = []
    listing_urls: List[str] = []

    for _, seed in DIRECT_DISCOVERY_SEEDS:
        audit["seeds"] += 1
        listing_urls.append(seed)

    if USE_GLOBAL_DISCOVERY and USE_SEARCH_DISCOVERY:
        for query in GLOBAL_DISCOVERY_QUERIES[:GLOBAL_SEARCH_QUERY_LIMIT]:
            audit["queries"] += 1
            try:
                found = search_urls(session, query)
            except Exception:
                audit["errors"] += 1
                found = []

            for candidate in found:
                candidate = normalise_url(candidate)
                if not looks_like_official_job_candidate(candidate):
                    continue
                if looks_like_listing_url(candidate):
                    listing_urls.append(candidate)
                else:
                    discovered.append(candidate)

    listing_urls = list(dict.fromkeys(listing_urls))
    audit["listings"] = len(listing_urls)

    for listing in listing_urls[:80]:
        try:
            links = discover_candidate_links_from_listing(listing)
            discovered.extend(links)
            audit["pages"] += 1
        except Exception:
            audit["errors"] += 1

    # Include direct individual URLs returned by engines and listing-derived URLs.
    unique_candidates: List[str] = []
    seen: Set[str] = set()
    for candidate in discovered:
        key = canonical_url(candidate)
        if not key or key in seen:
            continue
        seen.add(key)
        unique_candidates.append(candidate)
        if len(unique_candidates) >= MAX_GLOBAL_CANDIDATES:
            break

    audit["search_urls"] = len(discovered)
    audit["candidate_urls"] = len(unique_candidates)
    audit["job_links"] = len(unique_candidates)

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(2, min(MAX_WORKERS, 8))) as executor:
        future_map = {
            executor.submit(extract_results_from_candidate, url): url
            for url in unique_candidates
        }
        for future in as_completed(future_map):
            try:
                found = future.result()
                if found:
                    results.extend(found)
                else:
                    audit["rejected"] += 1
            except Exception:
                audit["errors"] += 1

    results = deduplicate(results)
    audit["matches"] = len(results)
    return results, audit


# ============================================================================
# PLAYWRIGHT
# ============================================================================

def render_page(
    url: str,
) -> Optional[Tuple[str, str]]:

    global _playwright_calls

    if not USE_PLAYWRIGHT:
        return None

    with _playwright_lock:
        if _playwright_calls >= PLAYWRIGHT_BUDGET:
            return None
        _playwright_calls += 1

    try:

        from playwright.sync_api import (
            sync_playwright
        )

    except ImportError:

        return None

    try:

        with sync_playwright() as playwright:

            browser = (
                playwright.chromium.launch(
                    headless=True
                )
            )

            context = (
                browser.new_context(
                    locale="en-GB",
                    user_agent=USER_AGENT,
                    viewport={
                        "width": 1440,
                        "height": 1000,
                    },
                )
            )

            page = context.new_page()

            page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=PLAYWRIGHT_TIMEOUT_MS,
            )

            page.wait_for_timeout(
                1000
            )

            for _ in range(2):

                page.mouse.wheel(
                    0,
                    2500,
                )

                page.wait_for_timeout(
                    250
                )

            html_content = (
                page.content()
            )

            final_url = page.url

            browser.close()

            return (
                html_content,
                final_url,
            )

    except Exception:

        return None


# ============================================================================
# GENERIC JOB PAGE EXTRACTION
# ============================================================================

def extract_location(
    soup: BeautifulSoup,
) -> str:

    selectors = [

        '[data-testid*="location"]',
        '[data-test*="location"]',
        '[data-automation-id*="location"]',
        '[class*="location"]',
        '[class*="Location"]',
        '[id*="location"]',
        '[id*="Location"]',
        '[aria-label*="location"]',
        '[aria-label*="Location"]',
    ]

    for selector in selectors:

        try:

            node = soup.select_one(
                selector
            )

            if node:

                value = node.get_text(
                    " ",
                    strip=True,
                )

                if value:
                    return value[:500]

        except Exception:
            continue

    return ""


def page_title(
    soup: BeautifulSoup,
) -> str:

    h1 = soup.find("h1")

    if h1:

        title = h1.get_text(
            " ",
            strip=True,
        )

        if title:
            return title

    if soup.title:

        return soup.title.get_text(
            " ",
            strip=True,
        )

    return ""


# ============================================================================
# JOB RECORD
# ============================================================================

def build_result(
    company: Tuple[str, List[str], List[str]],
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
    location = re.sub(r"\s+", " ", location or "").strip()
    original_url = normalise_url(url)

    if not title or not original_url:
        return None

    full_text = f"{title} {description} {location}"

    if not employment_type:
        employment_type = extract_employment_type(full_text)

    matched, keywords, score, confidence, match_reason = is_target_job(
        title=title,
        description=description,
        location=location,
        url=original_url,
        employment_type=employment_type,
    )

    if not matched:
        return None

    if not allowed_result_url(original_url, company):
        return None

    if not salary:
        salary = extract_salary(full_text)

    if not date_posted:
        date_posted = extract_posted_date(full_text)

    arrangement = extract_working_arrangement(full_text)

    return {
        "company": company[0],
        "title": title,
        "location": location or "UK location not specified",
        "working_arrangement": arrangement,
        "employment_type": employment_type,
        "salary": salary,
        "date_posted": date_posted,
        "job_reference": extract_reference(full_text),
        "match_score": score,
        "confidence": confidence,
        "match_reason": match_reason,
        "matched_keywords": ", ".join(keywords),
        "source_method": method,
        "url": original_url,
        "canonical_url": canonical_url(original_url),
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================================
# COMPANY CRAWLER

# ============================================================================

def crawl_company(
    company: Tuple[str, List[str], List[str]],
) -> Tuple[
    List[Dict[str, Any]],
    Dict[str, Any],
]:

    name, domains, seeds = company

    session = make_session()
    company_deadline = time.monotonic() + COMPANY_SCAN_SECONDS

    def company_time_left() -> bool:
        return time.monotonic() < company_deadline

    results = []

    audit = {
        "company": name,
        "source_type": "company",
        "seeds": 0,
        "pages": 0,
        "job_links": 0,
        "sitemap_urls": 0,
        "search_urls": 0,
        "queries": 0,
        "candidate_urls": 0,
        "listings": 0,
        "rejected": 0,
        "matches": 0,
        "errors": 0,
        "status": "FAILED",
    }

    verified_seeds = []

    # ------------------------------------------------------------------------
    # 1. Verify every seed.
    # ------------------------------------------------------------------------

    for seed in seeds:
        if not company_time_left():
            audit["status"] = "PARTIAL_TIMEOUT"
            break

        response = fetch(
            session,
            seed,
        )

        if response:

            final_url = normalise_url(
                response.url
            )

            if final_url:

                verified_seeds.append(
                    final_url
                )

                audit["seeds"] += 1

        else:

            audit["errors"] += 1

    if not verified_seeds:

        return results, audit

    audit["status"] = "VERIFIED"

    # ------------------------------------------------------------------------
    # 2. Sitemap discovery.
    # ------------------------------------------------------------------------

    sitemap_candidates = []

    for seed in verified_seeds:
        if not company_time_left():
            audit["status"] = "PARTIAL_TIMEOUT"
            break

        try:

            sitemaps = (
                discover_sitemaps(
                    session,
                    seed,
                )
            )

            for sitemap in sitemaps:
                if not company_time_left():
                    audit["status"] = "PARTIAL_TIMEOUT"
                    break

                urls = parse_sitemap(
                    session,
                    sitemap,
                )

                for url in urls:

                    low = url.lower()

                    if any(
                        hint in low
                        for hint in [
                            "job",
                            "career",
                            "vacanc",
                            "requisition",
                            "position",
                            "opportunit",
                            "opening",
                            "employment",
                            "role",
                        ]
                    ):

                        sitemap_candidates.append(
                            url
                        )

                    if (
                        len(sitemap_candidates)
                        >= MAX_JOB_LINKS_PER_COMPANY
                    ):
                        break

                if (
                    len(sitemap_candidates)
                    >= MAX_JOB_LINKS_PER_COMPANY
                ):
                    break

        except Exception:

            audit["errors"] += 1

        if (
            len(sitemap_candidates)
            >= MAX_JOB_LINKS_PER_COMPANY
        ):
            break

    sitemap_candidates = list(
        dict.fromkeys(
            sitemap_candidates
        )
    )

    sitemap_candidates.sort(
        key=lambda u: (
            0 if any(term in u.lower() for term in DISCOVERY_TITLE_HINTS) else 1,
            u.lower(),
        )
    )

    audit["sitemap_urls"] = len(
        sitemap_candidates
    )

    # ------------------------------------------------------------------------
    # 3. Search-engine discovery.
    #
    # This is the major improvement over the previous version.
    #
    # Instead of relying on a single career page, each company receives
    # multiple targeted Google/Bing searches.
    # ------------------------------------------------------------------------

    search_candidates = []

    if USE_SEARCH_DISCOVERY and USE_COMPANY_SEARCH_DISCOVERY:

        queries = build_search_queries(
            company
        )
        audit["queries"] = len(queries)

        for query in queries:
            if not company_time_left():
                audit["status"] = "PARTIAL_TIMEOUT"
                break

            try:

                found = search_urls(
                    session,
                    query,
                )

            except Exception:

                found = []

            for url in found:

                url = normalise_url(
                    url
                )

                if not url:
                    continue

                if allowed_result_url(
                    url,
                    company,
                ):

                    search_candidates.append(
                        url
                    )

            # Don't stop after the first query.
            # The entire point is deeper discovery.

        search_candidates = list(
            dict.fromkeys(
                search_candidates
            )
        )

    audit["search_urls"] = len(
        search_candidates
    )

    # ------------------------------------------------------------------------
    # 4. Initial crawl queue.
    # ------------------------------------------------------------------------

    page_queue = []

    page_queue.extend(
        verified_seeds
    )

    page_queue.extend(
        sitemap_candidates[:250]
    )

    page_queue.extend(
        search_candidates[:250]
    )

    page_queue = list(
        dict.fromkeys(
            page_queue
        )
    )

    visited_pages = set()
    job_links = []
    seen_job_links = set()

    # ------------------------------------------------------------------------
    # 5. Crawl pages.
    # ------------------------------------------------------------------------

    while (
        page_queue
        and len(visited_pages)
        < MAX_PAGES_PER_COMPANY
        and company_time_left()
    ):

        page_url = normalise_url(
            page_queue.pop(0)
        )

        if not page_url:
            continue

        page_key = canonical_url(
            page_url
        )

        if page_key in visited_pages:
            continue

        if not allowed_result_url(
            page_url,
            company,
        ):
            continue

        visited_pages.add(
            page_key
        )

        response = fetch(
            session,
            page_url,
        )

        html_content = None
        final_url = page_url

        if response and is_html_response(
            response
        ):

            html_content = (
                response.text
            )

            final_url = normalise_url(
                response.url
            )

            static_text = clean_text(
                html_content
            )

            # JS fallback.
            if (
                USE_PLAYWRIGHT
                and len(static_text) < 900
            ):

                rendered = render_page(
                    final_url
                )

                if rendered:

                    (
                        html_content,
                        final_url,
                    ) = rendered

        else:

            rendered = render_page(
                page_url
            )

            if rendered:

                (
                    html_content,
                    final_url,
                ) = rendered

        if not html_content:
            continue

        audit["pages"] += 1

        soup = BeautifulSoup(
            html_content,
            "html.parser",
        )

        # --------------------------------------------------------------------
        # JSON-LD directly on page.
        # --------------------------------------------------------------------

        structured_jobs = (
            extract_jsonld_jobs(
                soup,
                final_url,
            )
        )

        for job in structured_jobs:

            result = build_result(
                company=company,
                title=job.get(
                    "title",
                    "",
                ),
                description=job.get(
                    "description",
                    "",
                ),
                location=job.get(
                    "location",
                    "",
                ),
                url=job.get(
                    "url",
                    final_url,
                ),
                method=(
                    f"{ats_platform(final_url) or 'Corporate'} -> "
                    "JSON-LD JobPosting"
                ),
                date_posted=job.get(
                    "date_posted",
                    "",
                ),
                employment_type=job.get(
                    "employment_type",
                    "",
                ),
                salary=job.get(
                    "salary",
                    "",
                ),
            )

            if result:
                results.append(
                    result
                )

        # --------------------------------------------------------------------
        # Discover links.
        # --------------------------------------------------------------------

        discovered_jobs, discovered_pages = (
            extract_links(
                soup,
                final_url,
            )
        )

        for job_url in discovered_jobs:

            job_url = normalise_url(
                job_url
            )

            if not allowed_result_url(
                job_url,
                company,
            ):
                continue

            key = canonical_url(
                job_url
            )

            if (
                key
                and key not in seen_job_links
                and len(seen_job_links)
                < MAX_JOB_LINKS_PER_COMPANY
            ):

                seen_job_links.add(
                    key
                )

                job_links.append(
                    job_url
                )

        # --------------------------------------------------------------------
        # Continue crawling pagination / result pages.
        # --------------------------------------------------------------------

        for next_page in discovered_pages:

            next_page = normalise_url(
                next_page
            )

            if not allowed_result_url(
                next_page,
                company,
            ):
                continue

            key = canonical_url(
                next_page
            )

            if (
                key
                and key not in visited_pages
            ):

                if len(page_queue) < (
                    MAX_PAGES_PER_COMPANY * 8
                ):

                    page_queue.append(
                        next_page
                    )

    audit["job_links"] = len(
        job_links
    )
    audit["candidate_urls"] = len(job_links)

    # ------------------------------------------------------------------------
    # 6. Fetch individual job pages.
    # ------------------------------------------------------------------------

    for job_url in job_links:
        if not company_time_left():
            audit["status"] = "PARTIAL_TIMEOUT"
            break

        response = fetch(
            session,
            job_url,
            JOB_TIMEOUT,
        )

        html_content = None
        final_url = job_url

        if response and is_html_response(
            response
        ):

            html_content = (
                response.text
            )

            final_url = normalise_url(
                response.url
            )

            static_text = clean_text(
                html_content
            )

            if (
                USE_PLAYWRIGHT
                and len(static_text) < 900
            ):

                rendered = render_page(
                    final_url
                )

                if rendered:

                    (
                        html_content,
                        final_url,
                    ) = rendered

        else:

            rendered = render_page(
                job_url
            )

            if rendered:

                (
                    html_content,
                    final_url,
                ) = rendered

        if not html_content:
            continue

        try:

            soup = BeautifulSoup(
                html_content,
                "html.parser",
            )

            # JSON-LD first.
            structured_jobs = (
                extract_jsonld_jobs(
                    soup,
                    final_url,
                )
            )

            if structured_jobs:

                for job in structured_jobs:

                    result = build_result(
                        company=company,
                        title=job.get(
                            "title",
                            "",
                        ),
                        description=job.get(
                            "description",
                            "",
                        ),
                        location=job.get(
                            "location",
                            "",
                        ),
                        url=job.get(
                            "url",
                            final_url,
                        ),
                        method=(
                            f"{ats_platform(final_url) or 'Corporate'} -> "
                            "JobPosting"
                        ),
                        date_posted=job.get(
                            "date_posted",
                            "",
                        ),
                        employment_type=job.get(
                            "employment_type",
                            "",
                        ),
                        salary=job.get(
                            "salary",
                            "",
                        ),
                    )

                    if result:
                        results.append(
                            result
                        )

                continue

            # ---------------------------------------------------------------
            # Generic HTML job page.
            # ---------------------------------------------------------------

            title = page_title(
                soup
            )

            text = soup.get_text(
                " ",
                strip=True,
            )

            location = extract_location(
                soup
            )

            result = build_result(
                company=company,
                title=title,
                description=text,
                location=location,
                url=final_url,
                method=(
                    f"{ats_platform(final_url) or 'Corporate'} -> "
                    "HTML Job Page"
                ),
            )

            if result:

                results.append(
                    result
                )

        except Exception:

            audit["errors"] += 1

    results = deduplicate(
        results
    )

    audit["matches"] = len(
        results
    )

    return results, audit


# ============================================================================
# ATS API SCANNERS
# ============================================================================

def scan_greenhouse(
    company_name: str,
    board: str,
) -> List[Dict[str, Any]]:

    results = []

    try:

        session = make_session()

        response = session.get(
            (
                "https://boards-api.greenhouse.io/"
                f"v1/boards/{board}/jobs"
                "?content=true"
            ),
            timeout=25,
        )

        if response.status_code != 200:
            return results

        data = response.json()

        for job in data.get(
            "jobs",
            [],
        ):

            title = str(
                job.get(
                    "title",
                    "",
                )
            )

            description = BeautifulSoup(
                str(
                    job.get(
                        "content",
                        "",
                    )
                ),
                "html.parser",
            ).get_text(
                " ",
                strip=True,
            )

            location = str(
                (
                    job.get(
                        "location",
                        {}
                    )
                    or {}
                ).get(
                    "name",
                    "",
                )
            )

            url = str(
                job.get(
                    "absolute_url",
                    "",
                )
            )

            if not url:
                continue

            company = (
                company_name,
                [host(url)],
                [],
            )

            result = build_result(
                company=company,
                title=title,
                description=description,
                location=location,
                url=url,
                method="Greenhouse Public API",
            )

            if result:
                results.append(
                    result
                )

    except Exception:
        pass

    return results


def scan_lever(
    company_name: str,
    board: str,
) -> List[Dict[str, Any]]:

    results = []

    try:

        session = make_session()

        response = session.get(
            (
                "https://api.lever.co/v0/postings/"
                f"{board}?mode=json"
            ),
            timeout=25,
        )

        if response.status_code != 200:
            return results

        jobs = response.json()

        for job in jobs:

            title = str(
                job.get(
                    "text",
                    "",
                )
            )

            description = str(
                job.get(
                    "descriptionPlain",
                    "",
                )
            )

            categories = (
                job.get(
                    "categories",
                    {}
                )
                or {}
            )

            location = str(
                categories.get(
                    "location",
                    "",
                )
            )

            url = str(
                job.get(
                    "hostedUrl",
                    "",
                )
            )

            if not url:
                continue

            company = (
                company_name,
                [host(url)],
                [],
            )

            result = build_result(
                company=company,
                title=title,
                description=description,
                location=location,
                url=url,
                method="Lever Public API",
            )

            if result:
                results.append(
                    result
                )

    except Exception:
        pass

    return results


def scan_workable(
    company_name: str,
    board: str,
) -> List[Dict[str, Any]]:

    results = []

    try:

        session = make_session()

        response = session.get(
            (
                "https://apply.workable.com/"
                f"api/v3/accounts/{board}"
            ),
            timeout=25,
        )

        if response.status_code != 200:
            return results

        data = response.json()

        for job in data.get(
            "jobs",
            [],
        ):

            title = str(
                job.get(
                    "title",
                    "",
                )
            )

            description = str(
                job.get(
                    "description",
                    "",
                )
            )

            location_parts = []

            for key in [
                "city",
                "state",
                "country",
            ]:

                if job.get(key):
                    location_parts.append(
                        str(
                            job.get(key)
                        )
                    )

            location = ", ".join(
                location_parts
            )

            url = str(
                job.get(
                    "url",
                    "",
                )
            )

            if not url:
                continue

            company = (
                company_name,
                [host(url)],
                [],
            )

            result = build_result(
                company=company,
                title=title,
                description=description,
                location=location,
                url=url,
                method="Workable Public API",
            )

            if result:
                results.append(
                    result
                )

    except Exception:
        pass

    return results


def scan_ats_board(
    board: Tuple[str, str, str],
) -> List[Dict[str, Any]]:

    company, platform, board_id = board

    if platform == "greenhouse":

        return scan_greenhouse(
            company,
            board_id,
        )

    if platform == "lever":

        return scan_lever(
            company,
            board_id,
        )

    if platform == "workable":

        return scan_workable(
            company,
            board_id,
        )

    return []


# ============================================================================
# DEDUPLICATION
# ============================================================================

def deduplicate(
    results: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    output = []

    seen_urls = set()
    seen_titles = set()

    for item in results:

        url_key = (
            item.get(
                "canonical_url",
                "",
            )
            or canonical_url(
                item.get(
                    "url",
                    "",
                )
            )
        )

        company = re.sub(
            r"[^a-z0-9]+",
            " ",
            item.get(
                "company",
                "",
            ).lower(),
        ).strip()

        title = re.sub(
            r"[^a-z0-9]+",
            " ",
            item.get(
                "title",
                "",
            ).lower(),
        ).strip()

        location = re.sub(
            r"[^a-z0-9]+",
            " ",
            item.get("location", "").lower(),
        ).strip()

        reference = re.sub(
            r"[^a-z0-9]+",
            "",
            item.get("job_reference", "").lower(),
        ).strip()

        fuzzy_key = (
            f"{company}|{title}|{reference or location}"
        )

        # URL is strongest.
        if (
            url_key
            and url_key in seen_urls
        ):
            continue

        # Same company + same role from multiple discovery routes.
        if (
            fuzzy_key
            and fuzzy_key in seen_titles
        ):
            continue

        if url_key:
            seen_urls.add(
                url_key
            )

        if fuzzy_key:
            seen_titles.add(
                fuzzy_key
            )

        output.append(
            item
        )

    return output


# ============================================================================
# GOOGLE APPS SCRIPT
# ============================================================================

def archive_to_google(
    job: Dict[str, Any],
) -> bool:

    if not ARCHIVE_TO_GOOGLE:
        return False

    if not GOOGLE_APPS_SCRIPT_URL:
        return False

    try:

        payload = {
            "token": (
                GOOGLE_APPS_SCRIPT_TOKEN
            ),

            "application_id": "",

            "date_applied": "",

            "company": job.get(
                "company",
                "",
            ),

            "title": job.get(
                "title",
                "",
            ),

            "job_reference": job.get(
                "job_reference",
                "",
            ),

            "url": job.get(
                "url",
                "",
            ),

            "source": job.get(
                "source_method",
                "",
            ),

            "salary": job.get(
                "salary",
                "",
            ),

            "salary_min": "",

            "salary_max": "",

            "employment_type": job.get(
                "employment_type",
                "",
            ),

            "location": job.get(
                "location",
                "",
            ),

            "working_arrangement": job.get(
                "working_arrangement",
                "",
            ),

            "status": "Discovered",

            "cv_used": "",

            "matched_keywords": job.get(
                "matched_keywords",
                "",
            ),

            "match_score": job.get(
                "match_score",
                "",
            ),

            "outcome": "",

            "notes": "",
        }

        response = requests.post(
            GOOGLE_APPS_SCRIPT_URL,
            json=payload,
            timeout=45,
        )

        return (
            response.ok
            and bool(response.text)
        )

    except Exception:

        return False


# ============================================================================
# CSV / JSON OUTPUT
# ============================================================================

RESULT_FIELDS = [
    "company",
    "title",
    "location",
    "working_arrangement",
    "employment_type",
    "salary",
    "date_posted",
    "job_reference",
    "match_score",
    "confidence",
    "match_reason",
    "matched_keywords",
    "source_method",
    "url",
    "canonical_url",
    "discovered_at",
]


def write_csv(
    filename: str,
    rows: List[Dict[str, Any]],
    fields: List[str],
) -> None:

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields,
            extrasaction="ignore",
        )

        writer.writeheader()

        for row in rows:

            writer.writerow(
                {
                    field: row.get(
                        field,
                        "",
                    )
                    for field in fields
                }
            )


def write_json(
    filename: str,
    results: List[Dict[str, Any]],
    audits: List[Dict[str, Any]],
) -> None:

    payload = {
        "scan_time": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),
        "result_count": len(
            results
        ),
        "results": results,
        "source_audit": audits,
    }

    with open(
        filename,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            payload,
            file,
            indent=2,
            ensure_ascii=False,
        )


def write_run_log(
    results: List[Dict[str, Any]],
    audits: List[Dict[str, Any]],
) -> None:

    file_exists = os.path.exists(
        RUN_LOG_FILE
    )

    with open(
        RUN_LOG_FILE,
        "a",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.writer(
            file
        )

        if not file_exists:

            writer.writerow(
                [
                    "Run Time",
                    "Results",
                    "Companies",
                    "Verified Sources",
                    "Errors",
                ]
            )

        writer.writerow(
            [
                datetime.now(
                    timezone.utc
                ).isoformat(),

                len(results),

                len(audits),

                sum(
                    1
                    for a in audits
                    if a.get(
                        "status"
                    )
                    == "VERIFIED"
                ),

                sum(
                    int(
                        a.get(
                            "errors",
                            0,
                        )
                    )
                    for a in audits
                ),
            ]
        )


# ============================================================================
# DISPLAY
# ============================================================================

def display_results(
    results: List[Dict[str, Any]],
) -> None:

    print()
    print(
        "=" * 110
    )

    print(
        f"UK IAM / PAM RESULTS "
        f"({len(results)})"
    )

    print(
        "=" * 110
    )

    if not results:

        print(
            "No qualifying UK IAM/PAM vacancies found."
        )

        return

    for index, job in enumerate(
        results,
        start=1,
    ):

        print(
            f"\n{index}. "
            f"{job.get('company', '')} "
            f"- "
            f"{job.get('title', '')}"
        )

        print(
            f"   Location: "
            f"{job.get('location', '')}"
        )

        print(
            f"   Work: "
            f"{job.get('working_arrangement', '')}"
        )

        print(
            f"   Employment: "
            f"{job.get('employment_type', '')}"
        )

        print(
            f"   Salary: "
            f"{job.get('salary', '')}"
        )

        print(
            f"   Keywords: "
            f"{job.get('matched_keywords', '')}"
        )

        print(
            f"   Source: "
            f"{job.get('source_method', '')}"
        )

        print(
            f"   URL: "
            f"{job.get('url', '')}"
        )


def display_audit(
    audits: List[Dict[str, Any]],
) -> None:

    print()
    print(
        "=" * 110
    )

    print(
        "SOURCE AUDIT"
    )

    print(
        "=" * 110
    )

    print(
        f"{'Company':35} "
        f"{'Seed':>5} "
        f"{'Pages':>7} "
        f"{'Links':>7} "
        f"{'Search':>7} "
        f"{'Sitemap':>8} "
        f"{'Matches':>8}"
    )

    print(
        "-" * 110
    )

    for audit in sorted(
        audits,
        key=lambda x: x.get(
            "company",
            "",
        ).lower(),
    ):

        print(
            f"{audit.get('company','')[:35]:35} "
            f"{audit.get('seeds',0):>5} "
            f"{audit.get('pages',0):>7} "
            f"{audit.get('job_links',0):>7} "
            f"{audit.get('search_urls',0):>7} "
            f"{audit.get('sitemap_urls',0):>8} "
            f"{audit.get('matches',0):>8}"
        )


# ============================================================================
# MAIN
# ============================================================================

def run_self_test() -> None:
    """Offline regression tests for V5 matching logic.

    These are intentionally based on the live-good/live-bad patterns that
    exposed V4's recall/precision problems. No network access is required.
    """
    cases = [
        (
            "Barclays Identity & Access Lead",
            True,
            "Identity & Access Lead - BPL",
            "Extensive experience of Identity & Access Management (IAM). "
            "Experience of Joiner-Mover-Leaver pipeline creation and zero trust.",
            "London, United Kingdom",
            "Permanent",
        ),
        (
            "Barclays IAM Governance Specialist",
            True,
            "IAM Governance Specialist",
            "IAM controls, identity governance, SailPoint, Entra ID and CyberArk.",
            "Knutsford, United Kingdom; Prague, Czechia",
            "Permanent",
        ),
        (
            "Odevo IAM Engineer",
            True,
            "IAM Engineer",
            "Microsoft Entra ID, Active Directory, Conditional Access, SailPoint, "
            "Saviynt, PAM, PIM, SAML, OIDC, SCIM, JML and PowerShell automation.",
            "London",
            "Permanent",
        ),
        (
            "Qube identity role",
            True,
            "Identity & Access Management Engineer",
            "Identity governance, privileged access management, CyberArk and SSO.",
            "London, United Kingdom",
            "Permanent",
        ),
        (
            "Medical sales US",
            False,
            "Senior Medical Science Liaison - Cell Therapy",
            "The portal supports authorization and authentication.",
            "Boston, Massachusetts, United States",
            "Full-time",
        ),
        (
            "Privacy page",
            False,
            "Privacy Notice - Staff-related personal data",
            "Access control and security apply to personal data.",
            "UK location not specified",
            "Permanent",
        ),
        (
            "Generic AI engineer",
            False,
            "Senior AI Full Stack Engineer",
            "Authentication and authorization are used in the application.",
            "London, United Kingdom",
            "Permanent",
        ),
        (
            "Contract IAM",
            False,
            "IAM Engineer - 6 month contract",
            "Identity and access management, Entra ID and SailPoint.",
            "London, United Kingdom",
            "Contract",
        ),
        (
            "Barcelona software role",
            False,
            "Software Engineer III",
            "Authentication and access control.",
            "Barcelona, Spain",
            "Permanent",
        ),
    ]

    failures = []
    for name, expected, title, desc, location, emp in cases:
        matched, _, score, confidence, reason = is_target_job(
            title, desc, location, "https://example.com/jobs/test", emp
        )
        ok = matched is expected
        print(
            f"{'PASS' if ok else 'FAIL'} | {name:38} | "
            f"expected={expected} got={matched} score={score} {confidence} | {reason}"
        )
        if not ok:
            failures.append(name)

    # Critical V5 dedupe regression: job IDs in query strings must survive.
    q1 = canonical_url("https://www.qube-rt.com/careers/job?gh_jid=8460881002")
    q2 = canonical_url("https://www.qube-rt.com/careers/job?gh_jid=9999999999")
    if q1 == q2 or "gh_jid=8460881002" not in q1:
        failures.append("Qube gh_jid canonicalisation")
        print("FAIL | Qube gh_jid canonicalisation")
    else:
        print("PASS | Qube gh_jid canonicalisation")

    if failures:
        raise RuntimeError("V5 self-test failed: " + ", ".join(failures))

    print(f"V5.1 self-test passed: {len(cases)} classifier cases + URL identity test")


def main() -> None:
    if "--self-test" in sys.argv:
        run_self_test()
        return

    started = time.time()

    print()
    print("🚀 UK IAM / PAM JOB DISCOVERY ENGINE v5.1")
    print(f"Companies/fallback sources: {len(COMPANIES)}")
    print(f"ATS API boards: {len(ATS_BOARDS)}")
    print(f"Global discovery: {'ON' if USE_GLOBAL_DISCOVERY else 'OFF'}")
    print(f"Search discovery: {'ON' if USE_SEARCH_DISCOVERY else 'OFF'}")
    print(f"Company search discovery: {'ON' if USE_COMPANY_SEARCH_DISCOVERY else 'OFF'}")
    print(f"Search engine mode: {SEARCH_ENGINE_MODE}")
    print(f"Playwright: {'ON' if USE_PLAYWRIGHT else 'OFF'} (budget={PLAYWRIGHT_BUDGET})")
    print(
        f"Bounded fallback: pages/company={MAX_PAGES_PER_COMPANY}, "
        f"job-links/company={MAX_JOB_LINKS_PER_COMPANY}, "
        f"seconds/company={COMPANY_SCAN_SECONDS}"
    )
    print(f"IAM minimum score: {IAM_MIN_SCORE}")
    print("UK scope: UK-wide / Remote / Hybrid / Onsite")
    print("Employment: Permanent-only; contract/fixed-term/temporary/interim excluded")
    print()

    if USE_PLAYWRIGHT:
        try:
            import playwright  # noqa: F401
        except ImportError:
            print("⚠ Playwright package is not installed; continuing without browser rendering.")

    all_results: List[Dict[str, Any]] = []
    audits: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # 1/3 Public ATS APIs
    # ------------------------------------------------------------------
    print("1/3 Scanning public ATS APIs...")
    ats_results: List[Dict[str, Any]] = []
    ats_errors = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(scan_ats_board, board) for board in ATS_BOARDS]
        for future in as_completed(futures):
            try:
                ats_results.extend(future.result())
            except Exception:
                ats_errors += 1

    ats_results = deduplicate(ats_results)
    all_results.extend(ats_results)
    audits.append({
        "company": "PUBLIC ATS APIs",
        "source_type": "ats",
        "seeds": len(ATS_BOARDS),
        "pages": 0,
        "job_links": 0,
        "sitemap_urls": 0,
        "search_urls": 0,
        "queries": 0,
        "candidate_urls": 0,
        "listings": 0,
        "rejected": 0,
        "matches": len(ats_results),
        "errors": ats_errors,
        "status": "VERIFIED",
    })
    print(f"   ATS matches: {len(ats_results)}")

    # ------------------------------------------------------------------
    # 2/3 Open-ended discovery independent of employer list
    # ------------------------------------------------------------------
    print()
    print("2/3 Running open-ended IAM discovery (search + listings + ATS)...")
    if USE_GLOBAL_DISCOVERY:
        try:
            global_results, global_audit = global_discovery()
            all_results.extend(global_results)
            audits.append(global_audit)
            print(
                f"   Global: {len(global_results)} match(es) | "
                f"queries={global_audit.get('queries', 0)} | "
                f"listings={global_audit.get('listings', 0)} | "
                f"candidates={global_audit.get('candidate_urls', 0)} | "
                f"rejected={global_audit.get('rejected', 0)}"
            )
        except Exception as exc:
            audits.append({
                "company": "GLOBAL DISCOVERY",
                "source_type": "global",
                "seeds": len(DIRECT_DISCOVERY_SEEDS),
                "pages": 0,
                "job_links": 0,
                "sitemap_urls": 0,
                "search_urls": 0,
                "queries": 0,
                "candidate_urls": 0,
                "listings": 0,
                "rejected": 0,
                "matches": 0,
                "errors": 1,
                "status": "FAILED",
            })
            print(f"   Global discovery ERROR: {str(exc)[:180]}")
    else:
        print("   Global discovery disabled by environment variable.")

    # ------------------------------------------------------------------
    # 3/3 Company-site fallback/deep crawl
    # ------------------------------------------------------------------
    print()
    print("3/3 Deep-scanning company career sources as fallback...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {
            executor.submit(crawl_company, company): company
            for company in COMPANIES
        }
        completed = 0
        for future in as_completed(future_map):
            completed += 1
            company = future_map[future]
            try:
                results, audit = future.result()
                all_results.extend(results)
                audits.append(audit)
                print(
                    f"[{completed:02d}/{len(COMPANIES):02d}] {company[0]}: "
                    f"{len(results)} match(es) | pages={audit.get('pages', 0)} "
                    f"| links={audit.get('job_links', 0)} "
                    f"| search={audit.get('search_urls', 0)}"
                )
            except Exception as exc:
                audits.append({
                    "company": company[0],
                    "source_type": "company",
                    "seeds": 0,
                    "pages": 0,
                    "job_links": 0,
                    "sitemap_urls": 0,
                    "search_urls": 0,
                    "queries": 0,
                    "candidate_urls": 0,
                    "listings": 0,
                    "rejected": 0,
                    "matches": 0,
                    "errors": 1,
                    "status": "FAILED",
                })
                print(
                    f"[{completed:02d}/{len(COMPANIES):02d}] {company[0]}: "
                    f"ERROR {str(exc)[:180]}"
                )

    # Deduplicate and rank.
    all_results = deduplicate(all_results)
    all_results.sort(
        key=lambda item: (
            -int(item.get("match_score", 0) or 0),
            item.get("company", "").lower(),
            item.get("title", "").lower(),
        )
    )

    # Google Apps Script archive.
    archived = 0
    if ARCHIVE_TO_GOOGLE and not GOOGLE_APPS_SCRIPT_URL:
        print()
        print(
            "⚠ Google archive requested, but GOOGLE_APPS_SCRIPT_URL is missing. "
            "Set GOOGLE_APPS_SCRIPT_URL and GOOGLE_APPS_SCRIPT_TOKEN as secrets."
        )
    if ARCHIVE_TO_GOOGLE and GOOGLE_APPS_SCRIPT_URL and all_results:
        print()
        print("Sending discovered jobs to Google Apps Script...")
        for job in all_results:
            if archive_to_google(job):
                archived += 1
        print(f"Google archive submissions: {archived}/{len(all_results)}")

    # Output files.
    write_csv(CSV_FILE, all_results, RESULT_FIELDS)
    write_json(JSON_FILE, all_results, audits)
    audit_fields = [
        "company", "source_type", "seeds", "pages", "job_links",
        "sitemap_urls", "search_urls", "queries", "candidate_urls",
        "listings", "rejected", "matches", "errors", "status",
    ]
    write_csv(AUDIT_FILE, audits, audit_fields)
    write_run_log(all_results, audits)

    display_results(all_results)
    display_audit(audits)

    elapsed = time.time() - started
    verified = sum(1 for audit in audits if audit.get("status") == "VERIFIED")
    global_audit = next(
        (a for a in audits if a.get("source_type") == "global"), {}
    )

    print()
    print("=" * 110)
    print("✔ V5 SCAN COMPLETE")
    print(f"✔ Time: {elapsed:.1f} seconds")
    print(f"✔ Unique UK IAM/PAM results: {len(all_results)}")
    print(f"✔ Verified discovery sources: {verified}/{len(audits)}")
    print(
        "✔ Global diagnostics: "
        f"queries={global_audit.get('queries', 0)}, "
        f"candidates={global_audit.get('candidate_urls', 0)}, "
        f"rejected={global_audit.get('rejected', 0)}, "
        f"matches={global_audit.get('matches', 0)}"
    )
    print(f"✔ CSV saved: {CSV_FILE}")
    print(f"✔ JSON saved: {JSON_FILE}")
    print(f"✔ Audit saved: {AUDIT_FILE}")
    print(f"✔ Run log saved: {RUN_LOG_FILE}")
    if ARCHIVE_TO_GOOGLE:
        print(f"✔ Google archive: {archived}/{len(all_results)}")
    print()
    print("Policy: official employer and recognised ATS destinations only.")
    print("Search engines are discovery mechanisms only; job boards are rejected.")
    print("=" * 110)


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            "\n⚠ Scan interrupted."
        )

        sys.exit(130)

    except Exception as exc:

        print(
            "\n❌ Fatal error:"
        )

        print(
            str(exc)
        )

        sys.exit(1)
