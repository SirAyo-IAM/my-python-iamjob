#!/usr/bin/env python3
"""
UK IAM / PAM JOB DISCOVERY ENGINE v4
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
- V4 high-precision relevance scoring prevents generic authentication/authorization pages from becoming IAM matches.
- V4 validates real job titles and UK job-location evidence before a result is retained.
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
"""

from __future__ import annotations

import csv
import html
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import (
    parse_qs,
    quote_plus,
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

REQUEST_TIMEOUT = 18
SEARCH_TIMEOUT = 15
JOB_TIMEOUT = 18

MAX_WORKERS = int(os.getenv("IAM_MAX_WORKERS", "8"))

# Deep discovery.
MAX_PAGES_PER_COMPANY = 35
MAX_JOB_LINKS_PER_COMPANY = 300
MAX_SITEMAP_URLS = 2500

# Search engine discovery.
USE_SEARCH_DISCOVERY = True
MAX_SEARCH_RESULTS = 20
SEARCH_QUERIES_PER_COMPANY = 16

# High-precision V4 relevance threshold.
IAM_MIN_SCORE = int(os.getenv("IAM_MIN_SCORE", "75"))
HIGH_CONFIDENCE_SCORE = int(os.getenv("IAM_HIGH_CONFIDENCE_SCORE", "110"))

# Browser rendering.
USE_PLAYWRIGHT = os.getenv(
    "USE_PLAYWRIGHT",
    "true"
).lower() == "true"

PLAYWRIGHT_TIMEOUT_MS = 35000

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
        ["barclays.com"],
        ["https://home.barclays/careers/"],
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
    """
    Removes tracking/query/fragment parameters for deduplication.

    The original URL is retained separately.
    """

    url = normalise_url(url)

    if not url:
        return ""

    try:
        parsed = urlparse(url)

        return urlunparse(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path.rstrip("/"),
                "",
                "",
                "",
            )
        )

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


def search_urls(
    session: requests.Session,
    query: str,
) -> List[str]:

    results = []

    try:
        results.extend(
            google_search(
                session,
                query,
            )
        )

    except Exception:
        pass

    try:
        results.extend(
            bing_search(
                session,
                query,
            )
        )

    except Exception:
        pass

    return list(
        dict.fromkeys(results)
    )


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
# PLAYWRIGHT
# ============================================================================

def render_page(
    url: str,
) -> Optional[Tuple[str, str]]:

    if not USE_PLAYWRIGHT:
        return None

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
                2500
            )

            # Trigger lazy-loading.
            for _ in range(5):

                page.mouse.wheel(
                    0,
                    3000,
                )

                page.wait_for_timeout(
                    500
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

    results = []

    audit = {
        "company": name,
        "seeds": 0,
        "pages": 0,
        "job_links": 0,
        "sitemap_urls": 0,
        "search_urls": 0,
        "matches": 0,
        "errors": 0,
        "status": "FAILED",
    }

    verified_seeds = []

    # ------------------------------------------------------------------------
    # 1. Verify every seed.
    # ------------------------------------------------------------------------

    for seed in seeds:

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

        try:

            sitemaps = (
                discover_sitemaps(
                    session,
                    seed,
                )
            )

            for sitemap in sitemaps:

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

    if USE_SEARCH_DISCOVERY:

        queries = build_search_queries(
            company
        )

        for query in queries:

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

    # ------------------------------------------------------------------------
    # 6. Fetch individual job pages.
    # ------------------------------------------------------------------------

    for job_url in job_links:

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

def main() -> None:

    started = time.time()

    print()
    print(
        "🚀 UK IAM / PAM JOB DISCOVERY ENGINE v4"
    )

    print(
        f"Companies: {len(COMPANIES)}"
    )

    print(
        f"ATS APIs: {len(ATS_BOARDS)}"
    )

    print(
        "Search discovery: "
        f"{'ON' if USE_SEARCH_DISCOVERY else 'OFF'}"
    )

    print(
        "Playwright: "
        f"{'ON' if USE_PLAYWRIGHT else 'OFF'}"
    )

    print(
        "UK scope: UK-wide / Remote / Hybrid / Onsite"
    )

    print(
        "Employment: Permanent-only; "
        "contract/fixed-term/temporary/interim roles excluded"
    )

    print()

    # ------------------------------------------------------------------------
    # Playwright status.
    # ------------------------------------------------------------------------

    playwright_available = False

    if USE_PLAYWRIGHT:

        try:

            import playwright  # noqa: F401

            playwright_available = True

        except ImportError:

            print(
                "⚠ Playwright package is not installed."
            )

            print(
                "Continuing with requests-based discovery."
            )

            print(
                "JS-heavy sites will still be searched "
                "through Google/Bing and direct ATS routes."
            )

    # ------------------------------------------------------------------------
    # ATS APIs.
    # ------------------------------------------------------------------------

    print(
        "1/2 Scanning public ATS APIs..."
    )

    all_results = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = [
            executor.submit(
                scan_ats_board,
                board,
            )
            for board in ATS_BOARDS
        ]

        for future in as_completed(
            futures
        ):

            try:

                all_results.extend(
                    future.result()
                )

            except Exception:
                pass

    print(
        f"   ATS matches: "
        f"{len(all_results)}"
    )

    # ------------------------------------------------------------------------
    # Company discovery.
    # ------------------------------------------------------------------------

    print()
    print(
        "2/2 Deep-scanning official careers "
        "+ sitemaps + Google + Bing + ATS..."
    )

    audits = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        future_map = {
            executor.submit(
                crawl_company,
                company,
            ): company
            for company in COMPANIES
        }

        completed = 0

        for future in as_completed(
            future_map
        ):

            completed += 1

            company = future_map[
                future
            ]

            try:

                results, audit = (
                    future.result()
                )

                all_results.extend(
                    results
                )

                audits.append(
                    audit
                )

                print(
                    f"[{completed:02d}/"
                    f"{len(COMPANIES):02d}] "
                    f"{company[0]}: "
                    f"{len(results)} match(es) "
                    f"| pages="
                    f"{audit.get('pages', 0)} "
                    f"| links="
                    f"{audit.get('job_links', 0)} "
                    f"| search="
                    f"{audit.get('search_urls', 0)}"
                )

            except Exception as exc:

                audits.append(
                    {
                        "company": company[0],
                        "seeds": 0,
                        "pages": 0,
                        "job_links": 0,
                        "sitemap_urls": 0,
                        "search_urls": 0,
                        "matches": 0,
                        "errors": 1,
                        "status": "FAILED",
                    }
                )

                print(
                    f"[{completed:02d}/"
                    f"{len(COMPANIES):02d}] "
                    f"{company[0]}: "
                    f"ERROR "
                    f"{str(exc)[:180]}"
                )

    # ------------------------------------------------------------------------
    # Deduplicate.
    # ------------------------------------------------------------------------

    all_results = deduplicate(
        all_results
    )

    # Highest-confidence IAM vacancies first.
    all_results.sort(
        key=lambda item: (
            -int(item.get("match_score", 0) or 0),
            item.get("company", "").lower(),
            item.get("title", "").lower(),
        )
    )

    # ------------------------------------------------------------------------
    # Google archive.
    #
    # Disabled by default so the first run cannot flood the Google database.
    #
    # Enable with:
    #
    # ARCHIVE_TO_GOOGLE=true
    #
    # ------------------------------------------------------------------------

    archived = 0

    if ARCHIVE_TO_GOOGLE and not GOOGLE_APPS_SCRIPT_URL:
        print()
        print(
            "⚠ Google archive requested, but GOOGLE_APPS_SCRIPT_URL is missing. "
            "Set GOOGLE_APPS_SCRIPT_URL and GOOGLE_APPS_SCRIPT_TOKEN as GitHub secrets/env vars."
        )

    if (
        ARCHIVE_TO_GOOGLE
        and GOOGLE_APPS_SCRIPT_URL
        and all_results
    ):

        print()
        print(
            "Sending discovered jobs "
            "to Google Apps Script..."
        )

        for job in all_results:

            if archive_to_google(
                job
            ):

                archived += 1

        print(
            f"Google archive submissions: "
            f"{archived}/{len(all_results)}"
        )

    # ------------------------------------------------------------------------
    # Output files.
    # ------------------------------------------------------------------------

    write_csv(
        CSV_FILE,
        all_results,
        RESULT_FIELDS,
    )

    write_json(
        JSON_FILE,
        all_results,
        audits,
    )

    write_csv(
        AUDIT_FILE,
        audits,
        [
            "company",
            "seeds",
            "pages",
            "job_links",
            "sitemap_urls",
            "search_urls",
            "matches",
            "errors",
            "status",
        ],
    )

    write_run_log(
        all_results,
        audits,
    )

    # ------------------------------------------------------------------------
    # Display.
    # ------------------------------------------------------------------------

    display_results(
        all_results
    )

    display_audit(
        audits
    )

    # ------------------------------------------------------------------------
    # Final.
    # ------------------------------------------------------------------------

    elapsed = (
        time.time()
        - started
    )

    verified = sum(
        1
        for audit in audits
        if audit.get(
            "status"
        )
        == "VERIFIED"
    )

    print()
    print(
        "=" * 110
    )

    print(
        "✔ SCAN COMPLETE"
    )

    print(
        f"✔ Time: {elapsed:.1f} seconds"
    )

    print(
        f"✔ Unique UK IAM/PAM results: "
        f"{len(all_results)}"
    )

    print(
        f"✔ Verified company sources: "
        f"{verified}/{len(COMPANIES)}"
    )

    print(
        f"✔ CSV saved: {CSV_FILE}"
    )

    print(
        f"✔ JSON saved: {JSON_FILE}"
    )

    print(
        f"✔ Audit saved: {AUDIT_FILE}"
    )

    print(
        f"✔ Run log saved: {RUN_LOG_FILE}"
    )

    if ARCHIVE_TO_GOOGLE:

        print(
            f"✔ Google archive: "
            f"{archived}/{len(all_results)}"
        )

    print()
    print(
        "Policy: official company and recognised ATS "
        "job destinations only."
    )

    print(
        "Google/Bing are discovery mechanisms only."
    )

    print(
        "LinkedIn, Indeed, Reed and other job-board "
        "destinations are rejected."
    )

    print(
        "=" * 110
    )


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
