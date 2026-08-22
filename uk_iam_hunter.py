from __future__ import annotations

import csv
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
console = Console()
from rich.table import Table

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# ============================================================================
# CONFIGURATION
# ============================================================================

REQUEST_TIMEOUT = 15
JOB_REQUEST_TIMEOUT = 12
MAX_WORKERS = 8

# Maximum job-looking links followed from one careers source.
MAX_JOB_LINKS_PER_SOURCE = 75

# Maximum pagination-like links followed from one careers source.
MAX_CAREER_PAGES_PER_SOURCE = 4

# Use Playwright for pages that look JavaScript-heavy.
USE_PLAYWRIGHT_FALLBACK = True

# IMPORTANT:
# False = no manually entered individual job URLs are allowed into results.
USE_MANUAL_FALLBACKS = False

# Keep a local set of known job URLs so the same vacancy is not printed twice.
DEDUPLICATE_RESULTS = True

# Save every run to a CSV so you can feed the results into your tracker/database.
WRITE_CSV = True
CSV_FILENAME = "uk_iam_results.csv"

# ============================================================================
# GOOGLE SHEETS JOB ARCHIVE
# ============================================================================

GOOGLE_SHEETS_WEBHOOK_URL = (
    "https://script.google.com/macros/s/"
    "AKfycbzAxS5Keh8vArI6xXwWc-SmU6DN-FkTcKDVONmEMCLdfxgrQR-vPoDfloxGK8Z0MVBssg"
    "/exec"
)

SEND_RESULTS_TO_GOOGLE_SHEETS = True

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0 Safari/537.36"
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Language": "en-GB,en;q=0.9",
}


# ============================================================================
# ATS PLATFORM ALLOW-LIST
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
}


# ============================================================================
# PUBLIC ATS/API BOARDS
# ============================================================================
# Only use a board here when the public board identifier is known.
#
# The generic careers crawler is still used for all companies below as well.
# This means the ATS API is an acceleration path, not the only discovery path.
# ============================================================================

COMPANY_BOARDS = [
    {"company": "Monzo", "platform": "greenhouse", "board": "monzo"},
    {"company": "Revolut", "platform": "lever", "board": "revolut"},
    {"company": "Deliveroo", "platform": "greenhouse", "board": "deliveroo"},
    {"company": "Checkout.com", "platform": "greenhouse", "board": "checkoutcom"},
    {"company": "Canonical", "platform": "lever", "board": "canonical"},
    {"company": "Darktrace", "platform": "greenhouse", "board": "darktrace"},
    {"company": "Sophos", "platform": "greenhouse", "board": "sophos"},
    {"company": "Microsoft UK partners", "platform": "greenhouse", "board": "microsoft"},
    {"company": "Starling Bank", "platform": "workable", "board": "starling-bank"},
]


# ============================================================================
# VERIFIED COMPANY CAREERS SOURCES
# ============================================================================
# This is the source database from your existing script.
#
# The crawler treats careers_url as the primary source.
# external_job_platform_url is optional metadata; the crawler also discovers
# ATS links directly from the official careers page.
#
# IMPORTANT:
# A value here is a SOURCE URL, not a manually discovered vacancy.
# The crawler still has to discover and extract the actual vacancy.
# ============================================================================

COMPANY_CAREERS = [
    {
        "company_id": "HSBC-UK-001",
        "company_name": "HSBC Holdings plc",
        "companies_house_number": "0014259",
        "careers_url": "https://www.hsbc.com/careers",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "LLOYDS-UK-002",
        "company_name": "Lloyds Banking Group plc",
        "companies_house_number": "SC095000",
        "careers_url": "https://www.lloydsbankinggroup.com/careers.html",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "NATWEST-UK-003",
        "company_name": "NatWest Group plc",
        "companies_house_number": "SC045551",
        "careers_url": "https://www.natwestgroup.com/careers-at-natwest-group.html",
        "external_job_platform_url": "https://jobs.natwestgroup.com/",
        "careers_platform": "external_careers",
        "uk_location": True,
    },
    {
        "company_id": "STANCHRO-004",
        "company_name": "Standard Chartered PLC",
        "companies_house_number": "09649495",
        "careers_url": "https://www.standardchartered.com/en/careers",
        "external_job_platform_url": "https://www.sc.com/en/global-careers/",
        "careers_platform": "external_careers",
        "uk_location": True,
    },
    {
        "company_id": "AVIVA-UK-005",
        "company_name": "Aviva plc",
        "companies_house_number": "02468686",
        "careers_url": "https://www.aviva.com/careers/",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "SCHRODERS-006",
        "company_name": "Schroders plc",
        "companies_house_number": "00390988",
        "careers_url": "https://www.schroders.com/en-gb/uk/institutional/about-us/careers/",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "MANGROUP-007",
        "company_name": "Man Group plc",
        "companies_house_number": "02249393",
        "careers_url": "https://www.man.com/careers",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "VODAFONE-008",
        "company_name": "Vodafone Group",
        "companies_house_number": "1833679",
        "careers_url": "https://careers.vodafone.com/",
        "external_job_platform_url": "https://opportunities.vodafone.com/",
        "careers_platform": "external_careers",
        "uk_location": True,
    },
    {
        "company_id": "BT-UK-009",
        "company_name": "BT Group",
        "companies_house_number": "1800000",
        "careers_url": "https://jobs.bt.com/",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "SKY-UK-010",
        "company_name": "Sky UK",
        "companies_house_number": "02906991",
        "careers_url": "https://careers.sky.com/jobs",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "LEGALGEN-011",
        "company_name": "Legal & General",
        "companies_house_number": "00141716",
        "careers_url": "https://careers.legalandgeneral.com/",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "WISE-012",
        "company_name": "Wise",
        "companies_house_number": "07203984",
        "careers_url": "https://wise.jobs/",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "BAESYSTEMS-013",
        "company_name": "BAE Systems",
        "companies_house_number": "01470151",
        "careers_url": "https://www.baesystems.com/careers/",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "ROLLSROYCE-014",
        "company_name": "Rolls-Royce",
        "companies_house_number": "100516",
        "careers_url": "https://careers.rolls-royce.com/our-locations/uk",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "QINETIQ-015",
        "company_name": "QinetiQ",
        "companies_house_number": "04586941",
        "careers_url": "https://www.qinetiq.com/en-gb/careers",
        "external_job_platform_url": "https://careers.qinetiq.com/",
        "careers_platform": "external_careers",
        "uk_location": True,
    },
    {
        "company_id": "GSK-016",
        "company_name": "GSK",
        "companies_house_number": "03888792",
        "careers_url": "https://www.gsk.com/en-gb/careers/",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "KINGFISHER-017",
        "company_name": "Kingfisher plc",
        "companies_house_number": "01664812",
        "careers_url": "https://careers.kingfisher.com/",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "OCADO-018",
        "company_name": "Ocado Group",
        "companies_house_number": "03875000",
        "careers_url": "https://careers.ocadogroup.com/",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "NATGRID-019",
        "company_name": "National Grid",
        "companies_house_number": "04031152",
        "careers_url": "https://www.nationalgrid.com/careers?region=uk",
        "external_job_platform_url": "https://jobs.nationalgrid.com/uk/jobs",
        "careers_platform": "external_careers",
        "uk_location": True,
    },
    {
        "company_id": "CENTRICA-020",
        "company_name": "Centrica",
        "companies_house_number": "03033654",
        # NOTE: kept as the source from your existing database. If this no
        # longer resolves to careers, the runtime will report it as failed.
        "careers_url": "https://www.centrica.com/careers",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "SSE-021",
        "company_name": "SSE",
        "companies_house_number": "SC117119",
        "careers_url": "https://careers.sse.com/",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "ASTRAZENECA-022",
        "company_name": "AstraZeneca",
        "companies_house_number": "02723534",
        "careers_url": "https://careers.astrazeneca.com/search-jobs/united-kingdom",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "UNILEVER-023",
        "company_name": "Unilever UK",
        "companies_house_number": "00033450",
        "careers_url": "https://careers.unilever.com/en/united-kingdom-and-ireland",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "EASYJET-024",
        "company_name": "easyJet",
        "companies_house_number": "03659633",
        "careers_url": "https://careers.easyjet.com/en",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "HEATHROW-025",
        "company_name": "Heathrow Airport",
        "companies_house_number": "01991017",
        "careers_url": "https://www.heathrow.com/company/careers",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "ROYALMAIL-026",
        "company_name": "Royal Mail Group",
        "companies_house_number": "04074929",
        "careers_url": "https://careers.royalmailgroup.com/gb/en",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "DHL-027",
        "company_name": "DHL International UK",
        "companies_house_number": "02580790",
        "careers_url": "https://careers.dhl.com/global/en/dhl-uk",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "SERCO-028",
        "company_name": "Serco",
        "companies_house_number": "00242246",
        "careers_url": "https://www.serco.com/uk/careers",
        "external_job_platform_url": "https://careers.serco.com/gb/en",
        "careers_platform": "external_careers",
        "uk_location": True,
    },
    {
        "company_id": "SOPRA-029",
        "company_name": "Sopra Steria UK",
        "companies_house_number": "01077797",
        "careers_url": "https://careers.soprasteria.co.uk/uk/en",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "COMPUTACENTER-030",
        "company_name": "Computacenter",
        "companies_house_number": "03110569",
        "careers_url": "https://careers.computacenter.com/uk/",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "EY-031",
        "company_name": "EY UK",
        "companies_house_number": "OC300091",
        "careers_url": "https://careers.ey.com/?locale=en_GB",
        "external_job_platform_url": None,
        "careers_platform": "external_careers",
        "uk_location": True,
    },
    {
        "company_id": "KPMG-032",
        "company_name": "KPMG UK",
        "companies_house_number": "OC301540",
        "careers_url": "https://kpmg.com/uk/en/careers.html",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "PWC-033",
        "company_name": "PwC UK",
        "companies_house_number": "OC351965",
        "careers_url": "https://www.pwc.co.uk/careers",
        "external_job_platform_url": "https://jobs.pwc.co.uk/uk/en/",
        "careers_platform": "external_careers",
        "uk_location": True,
    },
    {
        "company_id": "CGI-034",
        "company_name": "CGI UK",
        "companies_house_number": "00973495",
        "careers_url": "https://www.cgi.com/uk/en-gb/careers",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "GOLDMAN-035",
        "company_name": "Goldman Sachs",
        "companies_house_number": "02263951",
        "careers_url": "https://www.goldmansachs.com/careers/",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "MORGAN-036",
        "company_name": "Morgan Stanley",
        "companies_house_number": "02096661",
        "careers_url": "https://www.morganstanley.com/careers/career-opportunities-search/",
        "external_job_platform_url": None,
        "careers_platform": "corporate",
        "uk_location": True,
    },
    {
        "company_id": "APPLE-037",
        "company_name": "Apple UK",
        "companies_house_number": "03289892",
        "careers_url": "https://jobs.apple.com/en-us/search?location=united-kingdom-GBR",
        "external_job_platform_url": None,
        "careers_platform": "corporate_careers",
        "uk_location": True,
    },
    {
        "company_id": "CAMBRIDGE-038",
        "company_name": "University of Cambridge",
        "companies_house_number": "RC000279",
        "careers_url": "https://www.jobs.cam.ac.uk/",
        "external_job_platform_url": None,
        "careers_platform": "university_jobs",
        "uk_location": True,
    },
]


# ============================================================================
# OPTIONAL MANUAL FALLBACKS
# ============================================================================
# Kept for reference, but NOT included in normal results unless explicitly
# enabled above.
# ============================================================================

DIRECT_URL_FALLBACKS = [
    {
        "company": "Starling Bank",
        "title": "Identity / Cloud Security Engineer (Workable)",
        "location": "London, UK",
        "url": "https://apply.workable.com/starling-bank/j/9FD955F9D9/",
    },
    {
        "company": "Kingfisher plc",
        "title": "Identity Platform Owner",
        "location": "London, UK",
        "url": "https://careers.kingfisher.com/job/london/it-services/identity-platform-owner/2026-142370",
    },
    {
        "company": "EY UK",
        "title": "Senior Consultant, Identity and Access Management, Cyber",
        "location": "London, UK",
        "url": "https://careers.ey.com/ey/job/London-Senior-Consultant%2C-Identity-and-Access-Management%2C-Cyber%2C-FS-E14-5EY/1168991101/",
    },
    {
        "company": "Enterprise Oracle Cloud Partner",
        "title": "Identity Specialist (Oracle Cloud)",
        "location": "UK",
        "url": "https://don.fa.em2.oraclecloud.com/hcmUI/CandidateExperience/en/sites/CX_1003/jobs/preview/9189/?keyword=Identity&mode=location",
    },
]


# ============================================================================
# TARGET KEYWORD MATRICES
# ============================================================================

IDENTITY_KEYWORDS = [
    "IAM",
    "Identity and Access Management",
    "Identity Access Management",
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
]

PAM_KEYWORDS = [
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
]

IDENTITY_PLATFORM_KEYWORDS = [
    "Identity Platform Owner",
    "Identity Product Owner",
    "Identity Service Owner",
    "Identity Governance and Administration",
    "IGA",
    "Entitlement Management",
    "Access Reviews",
    "Access Certification",
]

MICROSOFT_IDENTITY = [
    "Entra ID",
    "Microsoft Entra",
    "Azure AD",
    "Azure Active Directory",
    "Privileged Identity Management",
    "PIM",
    "Conditional Access",
]

OTHER_IDENTITY_PLATFORMS = [
    "Okta",
    "Ping Identity",
    "PingFederate",
    "ForgeRock",
    "Saviynt",
    "IdentityNow",
    "IdentityIQ",
    "HashiCorp Vault",
]

ALL_TARGET_KEYWORDS = (
    IDENTITY_KEYWORDS
    + PAM_KEYWORDS
    + IDENTITY_PLATFORM_KEYWORDS
    + MICROSOFT_IDENTITY
    + OTHER_IDENTITY_PLATFORMS
)


# ============================================================================
# UK LOCATION DETECTION
# ============================================================================

UK_LOCATION_TERMS = [
    "united kingdom",
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
    "remote uk",
    "uk remote",
    "remote, uk",
    "remote - uk",
]


# ============================================================================
# HTTP HELPERS
# ============================================================================

def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(HEADERS)
    return session


def normalise_url(url: str) -> str:
    if not url:
        return ""
    return url.strip().rstrip("#")


def get_host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def detect_platform(url: str) -> str:
    host = get_host(url)

    for domain, platform in ATS_DOMAINS.items():
        if host == domain or host.endswith("." + domain):
            return platform

    return "Custom Corporate Web"


def is_ats_url(url: str) -> bool:
    return detect_platform(url) != "Custom Corporate Web"


def same_or_subdomain(host: str, root_host: str) -> bool:
    host = host.lower()
    root_host = root_host.lower()

    return host == root_host or host.endswith("." + root_host)


def looks_like_html(response: requests.Response) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    return (
        "text/html" in content_type
        or "application/xhtml+xml" in content_type
        or not content_type
    )


def fetch_url(
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

        if not looks_like_html(response):
            return None

        return response

    except requests.RequestException:
        return None


# ============================================================================
# CAREERS SOURCE VERIFICATION
# ============================================================================

def verify_careers_endpoint(
    session: requests.Session,
    url: str,
) -> Dict[str, Any]:
    """
    Verify the source and follow redirects.

    200 is not the only valid outcome. A 301/302 that ultimately reaches a
    200 careers page is considered valid because requests follows redirects.
    """

    url = normalise_url(url)

    try:
        response = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )

        final_url = response.url
        status = response.status_code
        platform = detect_platform(final_url)

        return {
            "status_code": status,
            "final_url": final_url,
            "platform": platform,
            "verified": 200 <= status < 400,
            "redirected": final_url.rstrip("/") != url.rstrip("/"),
        }

    except requests.RequestException as exc:
        return {
            "status_code": 0,
            "final_url": url,
            "platform": "Unreachable",
            "verified": False,
            "redirected": False,
            "error": str(exc),
        }


# ============================================================================
# PLAYWRIGHT
# ============================================================================

def render_page(url: str) -> Optional[Dict[str, str]]:
    if not USE_PLAYWRIGHT_FALLBACK or not PLAYWRIGHT_AVAILABLE:
        return None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            page = browser.new_page(
                locale="en-GB",
                user_agent=USER_AGENT,
            )

            page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=30000,
            )

            page.wait_for_timeout(2000)

            html = page.content()
            final_url = page.url

            browser.close()

            return {
                "html": html,
                "url": final_url,
            }

    except Exception:
        return None


# ============================================================================
# KEYWORD MATCHING
# ============================================================================

def keyword_found(keyword: str, text: str) -> bool:
    """
    Match short acronyms as words so:
        IAM -> matches "IAM Engineer"
        IAM -> does NOT accidentally match "diagram"

    Longer phrases are matched case-insensitively.
    """

    if not keyword or not text:
        return False

    if len(keyword) <= 4:
        pattern = rf"(?<![A-Za-z0-9]){re.escape(keyword)}(?![A-Za-z0-9])"
    else:
        pattern = re.escape(keyword)

    return re.search(
        pattern,
        text,
        flags=re.IGNORECASE,
    ) is not None


def matched_keywords(text: str) -> List[str]:
    return [
        keyword
        for keyword in ALL_TARGET_KEYWORDS
        if keyword_found(keyword, text)
    ]


def is_target_job(
    title: str = "",
    description: str = "",
    url: str = "",
) -> Tuple[bool, List[str]]:
    """
    Match against title + description + URL.

    The description matters because jobs such as "Cloud Security Engineer"
    may have IAM/Entra/PAM responsibilities without those terms appearing in
    the title.
    """

    combined = f"{title}\n{description}\n{url}"

    matches = matched_keywords(combined)

    return bool(matches), matches


# ============================================================================
# UK LOCATION
# ============================================================================

def is_uk_location(location: str, text: str = "") -> bool:
    combined = f"{location} {text}".lower()

    return any(
        term in combined
        for term in UK_LOCATION_TERMS
    )


def extract_location_from_jobposting(data: Dict[str, Any]) -> str:
    location = data.get("jobLocation", "")

    def parse_one(value: Any) -> str:
        if not isinstance(value, dict):
            return str(value or "")

        address = value.get("address", value)

        if isinstance(address, dict):
            parts = [
                address.get("addressLocality", ""),
                address.get("addressRegion", ""),
                address.get("postalCode", ""),
                address.get("addressCountry", ""),
            ]
            return ", ".join(
                p for p in parts if p
            )

        return str(address)

    if isinstance(location, list):
        return " | ".join(
            parse_one(item)
            for item in location
        )

    return parse_one(location)


# ============================================================================
# JSON-LD JOBPOSTING EXTRACTION
# ============================================================================

def extract_jsonld_jobs(
    soup: BeautifulSoup,
    base_url: str,
) -> List[Dict[str, Any]]:

    jobs = []

    for script in soup.find_all(
        "script",
        type="application/ld+json",
    ):

        raw = script.string or script.get_text()

        if not raw:
            continue

        try:
            data = json.loads(raw)
        except Exception:
            continue

        items: List[Any] = []

        if isinstance(data, list):
            items = data

        elif isinstance(data, dict):

            graph = data.get("@graph")

            if isinstance(graph, list):
                items = graph
            else:
                items = [data]

        for item in items:

            if not isinstance(item, dict):
                continue

            item_type = item.get("@type")

            if isinstance(item_type, list):
                is_job = "JobPosting" in item_type
            else:
                is_job = item_type == "JobPosting"

            if not is_job:
                continue

            title = str(
                item.get("title", "")
            ).strip()

            description_html = str(
                item.get("description", "")
            )

            description = BeautifulSoup(
                description_html,
                "html.parser",
            ).get_text(
                " ",
                strip=True,
            )

            raw_url = item.get("url") or base_url

            job_url = urljoin(
                base_url,
                str(raw_url),
            )

            location = extract_location_from_jobposting(
                item
            )

            jobs.append({
                "title": title,
                "description": description,
                "location": location,
                "url": job_url,
                "method": "JSON-LD JobPosting",
            })

    return jobs


# ============================================================================
# LINK EXTRACTION
# ============================================================================

JOB_LINK_TERMS = [
    "job",
    "jobs",
    "career",
    "careers",
    "vacanc",
    "opportunit",
    "position",
    "opening",
    "employment",
    "join-us",
    "join us",
    "work-with-us",
    "work with us",
    "apply",
    "requisition",
]


def looks_like_job_link(
    url: str,
    text: str = "",
) -> bool:

    combined = f"{url} {text}".lower()

    return any(
        term in combined
        for term in JOB_LINK_TERMS
    )


def looks_like_pagination_link(
    url: str,
    text: str = "",
) -> bool:

    combined = f"{url} {text}".lower()

    terms = [
        "next",
        "page=",
        "p=",
        "start=",
        "offset=",
        "load more",
        "view all",
        "all jobs",
        "search jobs",
        "see all",
    ]

    return any(
        term in combined
        for term in terms
    )


def extract_links(
    html: str,
    page_url: str,
) -> Tuple[
    List[Dict[str, Any]],
    List[str],
    List[str],
]:

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    jsonld_jobs = extract_jsonld_jobs(
        soup,
        page_url,
    )

    job_links: List[str] = []
    career_page_links: List[str] = []

    seen_jobs: Set[str] = set()
    seen_pages: Set[str] = set()

    for anchor in soup.find_all(
        "a",
        href=True,
    ):

        href = urljoin(
            page_url,
            anchor["href"],
        )

        text = anchor.get_text(
            " ",
            strip=True,
        )

        if href.startswith(
            (
                "mailto:",
                "tel:",
                "javascript:",
                "#",
            )
        ):
            continue

        href = normalise_url(href)

        if looks_like_job_link(
            href,
            text,
        ):
            if href not in seen_jobs:
                seen_jobs.add(href)
                job_links.append(href)

        elif looks_like_pagination_link(
            href,
            text,
        ):
            if href not in seen_pages:
                seen_pages.add(href)
                career_page_links.append(href)

    return (
        jsonld_jobs,
        job_links,
        career_page_links,
    )


# ============================================================================
# CAREERS CRAWLER
# ============================================================================

def crawl_careers_source(
    source: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:

    company = source["company_name"]
    primary_url = source.get("careers_url")
    external_url = source.get(
        "external_job_platform_url"
    )

    seeds = []

    if primary_url:
        seeds.append(primary_url)

    if external_url and external_url not in seeds:
        seeds.append(external_url)

    all_results: List[Dict[str, Any]] = []

    source_audit = {
        "company": company,
        "primary_url": primary_url,
        "external_url": external_url,
        "verified_sources": [],
        "failed_sources": [],
        "discovered_platforms": set(),
    }

    session = make_session()

    # ------------------------------------------------------------------------
    # Verify each official source / configured external careers source.
    # ------------------------------------------------------------------------

    verified_seed_pages: List[Tuple[str, str]] = []

    for seed in seeds:

        verification = verify_careers_endpoint(
            session,
            seed,
        )

        if verification["verified"]:

            final_url = verification["final_url"]
            platform = verification["platform"]

            source_audit["verified_sources"].append({
                "seed": seed,
                "final_url": final_url,
                "platform": platform,
                "status": verification["status_code"],
            })

            source_audit["discovered_platforms"].add(
                platform
            )

            verified_seed_pages.append(
                (seed, final_url)
            )

        else:

            source_audit["failed_sources"].append({
                "seed": seed,
                "status": verification["status_code"],
                "error": verification.get("error", ""),
            })

    if not verified_seed_pages:
        source_audit["discovered_platforms"] = list(
            source_audit["discovered_platforms"]
        )
        return [], source_audit

    # ------------------------------------------------------------------------
    # Crawl source pages.
    # ------------------------------------------------------------------------

    pages_to_visit: List[Tuple[str, int]] = [
        (url, 0)
        for _, url in verified_seed_pages
    ]

    visited_pages: Set[str] = set()
    discovered_job_links: Set[str] = set()

    while pages_to_visit and len(visited_pages) < MAX_CAREER_PAGES_PER_SOURCE:

        page_url, depth = pages_to_visit.pop(0)

        page_url = normalise_url(page_url)

        if not page_url or page_url in visited_pages:
            continue

        visited_pages.add(page_url)

        response = fetch_url(
            session,
            page_url,
        )

        if not response:
            rendered = render_page(page_url)

            if not rendered:
                continue

            html = rendered["html"]
            final_url = rendered["url"]

        else:

            html = response.text
            final_url = response.url

            # If static content is suspiciously tiny, use a browser.
            static_text = BeautifulSoup(
                html,
                "html.parser",
            ).get_text(
                " ",
                strip=True,
            )

            if (
                USE_PLAYWRIGHT_FALLBACK
                and len(static_text) < 700
            ):

                rendered = render_page(
                    final_url
                )

                if rendered:
                    html = rendered["html"]
                    final_url = rendered["url"]

        source_audit["discovered_platforms"].add(
            detect_platform(final_url)
        )

        jsonld_jobs, job_links, page_links = extract_links(
            html,
            final_url,
        )

        # ------------------------------------------------------------
        # Direct JobPosting structured data
        # ------------------------------------------------------------

        for job in jsonld_jobs:

            title = job.get("title", "")
            description = job.get("description", "")
            location = job.get("location", "")
            job_url = job.get("url", final_url)

            matched, keywords = is_target_job(
                title,
                description,
                job_url,
            )

            if not matched:
                continue

            if not is_uk_location(
                location,
                description,
            ):
                continue

            all_results.append({
                "company": company,
                "title": title or "Untitled Job",
                "location": location or "UK location not specified",
                "url": job_url,
                "method": (
                    f"Official careers source -> "
                    f"{detect_platform(final_url)} -> "
                    f"JSON-LD JobPosting"
                ),
                "matched_keywords": ", ".join(
                    keywords
                ),
            })

        # ------------------------------------------------------------
        # Job-looking links
        # ------------------------------------------------------------

        for job_link in job_links:

            if len(discovered_job_links) >= MAX_JOB_LINKS_PER_SOURCE:
                break

            if job_link not in discovered_job_links:
                discovered_job_links.add(job_link)

        # ------------------------------------------------------------
        # Follow likely pagination/search pages.
        # Keep within the same careers/ATS host where possible.
        # ------------------------------------------------------------

        base_host = get_host(final_url)

        for next_url in page_links:

            if len(visited_pages) + len(pages_to_visit) >= MAX_CAREER_PAGES_PER_SOURCE:
                break

            next_host = get_host(next_url)

            if (
                is_ats_url(final_url)
                or same_or_subdomain(
                    next_host,
                    base_host,
                )
            ):

                if next_url not in visited_pages:
                    pages_to_visit.append(
                        (next_url, depth + 1)
                    )

    # ------------------------------------------------------------------------
    # Fetch individual job pages.
    # ------------------------------------------------------------------------

    job_links_to_scan = list(
        discovered_job_links
    )[:MAX_JOB_LINKS_PER_SOURCE]

    for job_url in job_links_to_scan:

        try:

            response = fetch_url(
                session,
                job_url,
                timeout=JOB_REQUEST_TIMEOUT,
            )

            if response:

                html = response.text
                final_job_url = response.url

                text = BeautifulSoup(
                    html,
                    "html.parser",
                ).get_text(
                    " ",
                    strip=True,
                )

                if (
                    USE_PLAYWRIGHT_FALLBACK
                    and len(text) < 700
                ):

                    rendered = render_page(
                        final_job_url
                    )

                    if rendered:
                        html = rendered["html"]
                        final_job_url = rendered["url"]

            else:

                rendered = render_page(
                    job_url
                )

                if not rendered:
                    continue

                html = rendered["html"]
                final_job_url = rendered["url"]

            soup = BeautifulSoup(
                html,
                "html.parser",
            )

            # First try JobPosting structured data.
            json_jobs = extract_jsonld_jobs(
                soup,
                final_job_url,
            )

            if json_jobs:

                for job in json_jobs:

                    title = job.get(
                        "title",
                        "",
                    )

                    description = job.get(
                        "description",
                        "",
                    )

                    location = job.get(
                        "location",
                        "",
                    )

                    matched, keywords = is_target_job(
                        title,
                        description,
                        final_job_url,
                    )

                    if (
                        matched
                        and is_uk_location(
                            location,
                            description,
                        )
                    ):

                        all_results.append({
                            "company": company,
                            "title": title or "Untitled Job",
                            "location": (
                                location
                                or "UK location not specified"
                            ),
                            "url": (
                                job.get(
                                    "url"
                                )
                                or final_job_url
                            ),
                            "method": (
                                "Official careers source -> "
                                f"{detect_platform(final_job_url)} -> "
                                "JobPosting"
                            ),
                            "matched_keywords": ", ".join(
                                keywords
                            ),
                        })

                continue

            # ------------------------------------------------------------
            # Generic HTML job-page extraction.
            # ------------------------------------------------------------

            h1 = soup.find("h1")

            if h1:
                title = h1.get_text(
                    " ",
                    strip=True,
                )
            elif soup.title:
                title = soup.title.get_text(
                    " ",
                    strip=True,
                )
            else:
                title = ""

            description = soup.get_text(
                " ",
                strip=True,
            )

            # Try common location metadata.
            location = ""

            location_selectors = [
                '[class*="location"]',
                '[id*="location"]',
                '[class*="Location"]',
                '[data-testid*="location"]',
            ]

            for selector in location_selectors:

                node = soup.select_one(
                    selector
                )

                if node:

                    candidate = node.get_text(
                        " ",
                        strip=True,
                    )

                    if candidate:
                        location = candidate
                        break

            matched, keywords = is_target_job(
                title,
                description,
                final_job_url,
            )

            if (
                matched
                and is_uk_location(
                    location,
                    description,
                )
            ):

                all_results.append({
                    "company": company,
                    "title": title or "Untitled Job",
                    "location": (
                        location
                        or "UK location not specified"
                    ),
                    "url": final_job_url,
                    "method": (
                        "Official careers source -> "
                        f"{detect_platform(final_job_url)} -> "
                        "HTML job page"
                    ),
                    "matched_keywords": ", ".join(
                        keywords
                    ),
                })

        except Exception:
            continue

    source_audit["discovered_platforms"] = sorted(
        source_audit["discovered_platforms"]
    )

    return all_results, source_audit


# ============================================================================
# DIRECT ATS API SCANNERS
# ============================================================================

def scan_greenhouse(
    company: str,
    board_id: str,
) -> List[Dict[str, Any]]:

    results = []

    try:

        response = requests.get(
            f"https://boards-api.greenhouse.io/v1/boards/"
            f"{board_id}/jobs?content=true",
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            return []

        jobs = response.json().get(
            "jobs",
            [],
        )

        for job in jobs:

            title = str(
                job.get("title", "")
            )

            description = str(
                job.get("content", "")
            )

            location_data = job.get(
                "location",
                {},
            )

            if isinstance(
                location_data,
                dict,
            ):
                location = str(
                    location_data.get(
                        "name",
                        "",
                    )
                )
            else:
                location = str(
                    location_data
                )

            url = job.get(
                "absolute_url",
                "",
            )

            matched, keywords = is_target_job(
                title,
                description,
                url,
            )

            if (
                matched
                and is_uk_location(
                    location,
                    description,
                )
            ):

                results.append({
                    "company": company,
                    "title": title,
                    "location": location,
                    "url": url,
                    "method": "Direct API (Greenhouse)",
                    "matched_keywords": ", ".join(
                        keywords
                    ),
                })

    except Exception:
        pass

    return results


def scan_lever(
    company: str,
    board_id: str,
) -> List[Dict[str, Any]]:

    results = []

    try:

        response = requests.get(
            f"https://api.lever.co/v0/postings/"
            f"{board_id}?mode=json",
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            return []

        jobs = response.json()

        for job in jobs:

            title = str(
                job.get("text", "")
            )

            categories = job.get(
                "categories",
                {},
            )

            location = str(
                categories.get(
                    "location",
                    "",
                )
            )

            description = str(
                job.get(
                    "descriptionPlain",
                    "",
                )
            )

            url = str(
                job.get(
                    "hostedUrl",
                    "",
                )
            )

            matched, keywords = is_target_job(
                title,
                description,
                url,
            )

            if (
                matched
                and is_uk_location(
                    location,
                    description,
                )
            ):

                results.append({
                    "company": company,
                    "title": title,
                    "location": location,
                    "url": url,
                    "method": "Direct API (Lever)",
                    "matched_keywords": ", ".join(
                        keywords
                    ),
                })

    except Exception:
        pass

    return results


def scan_workable(
    company: str,
    board_id: str,
) -> List[Dict[str, Any]]:

    results = []

    try:

        response = requests.get(
            f"https://apply.workable.com/api/v3/accounts/"
            f"{board_id}",
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            return []

        data = response.json()

        jobs = data.get(
            "jobs",
            [],
        )

        for job in jobs:

            title = str(
                job.get(
                    "title",
                    "",
                )
            )

            location = ", ".join(
                p
                for p in [
                    str(job.get("city", "")),
                    str(job.get("state", "")),
                    str(job.get("country", "")),
                ]
                if p and p != "None"
            )

            description = str(
                job.get(
                    "description",
                    "",
                )
            )

            url = str(
                job.get(
                    "url",
                    "",
                )
            )

            matched, keywords = is_target_job(
                title,
                description,
                url,
            )

            if (
                matched
                and is_uk_location(
                    location,
                    description,
                )
            ):

                results.append({
                    "company": company,
                    "title": title,
                    "location": location,
                    "url": url,
                    "method": "Direct API (Workable)",
                    "matched_keywords": ", ".join(
                        keywords
                    ),
                })

    except Exception:
        pass

    return results


def scan_api_board(
    board_info: Dict[str, str],
) -> List[Dict[str, Any]]:

    company = board_info["company"]
    platform = board_info["platform"]
    board = board_info["board"]

    if platform == "greenhouse":
        return scan_greenhouse(
            company,
            board,
        )

    if platform == "lever":
        return scan_lever(
            company,
            board,
        )

    if platform == "workable":
        return scan_workable(
            company,
            board,
        )

    return []


# ============================================================================
# RESULT DEDUPLICATION
# ============================================================================

def canonical_job_url(url: str) -> str:
    """
    Remove obvious tracking parameters while preserving the actual vacancy URL.
    """

    if not url:
        return ""

    parsed = urlparse(url)

    # Keep path. Strip common tracking-only query strings.
    return (
        f"{parsed.scheme}://{parsed.netloc}"
        f"{parsed.path}"
    ).rstrip("/").lower()


def deduplicate_results(
    results: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:

    seen: Set[str] = set()
    output: List[Dict[str, Any]] = []

    for item in results:

        key = canonical_job_url(
            item.get("url", "")
        )

        if not key:
            key = (
                f"{item.get('company','')}|"
                f"{item.get('title','')}"
            ).lower()

        if key in seen:
            continue

        seen.add(key)
        output.append(item)

    return output



# ============================================================================
# ============================================================================
# GOOGLE SHEETS JOB ARCHIVE
# ============================================================================

def send_job_to_google_sheets(
    job: Dict[str, Any],
) -> bool:
    """
    Send a discovered job URL to the Google Apps Script Web App.

    The URL is the authoritative identifier. Google Apps Script is
    responsible for retrieving and archiving the full vacancy.
    """

    if not SEND_RESULTS_TO_GOOGLE_SHEETS:
        return False

    job_url = normalise_url(
        job.get("url", "")
    )

    if not job_url:
        return False

    payload = {
        "action": "archive_job",
        "url": job_url,
        "company": job.get("company", ""),
        "title": job.get("title", ""),
        "location": job.get("location", ""),
        "method": job.get("method", ""),
        "matched_keywords": job.get(
            "matched_keywords",
            "",
        ),
        "discovered_at": datetime.now().isoformat(),
    }

    try:

        response = requests.post(
            GOOGLE_SHEETS_WEBHOOK_URL,
            json=payload,
            headers={
                **HEADERS,
                "Content-Type": "application/json",
            },
            timeout=30,
        )

        if response.status_code != 200:
            console.print(
                f"[yellow]"
                f"Google Sheets returned HTTP "
                f"{response.status_code} for {job_url}"
                f"[/yellow]"
            )
            return False

        try:
            result = response.json()
        except ValueError:
            result = {}

        if result.get("success") is True:
            return True

        console.print(
            f"[yellow]"
            f"Google Sheets did not confirm archive: "
            f"{result}"
            f"[/yellow]"
        )

        return False

    except requests.RequestException as exc:

        console.print(
            f"[yellow]"
            f"Google Sheets connection failed: {exc}"
            f"[/yellow]"
        )

        return False
# CSV EXPORT
# ============================================================================

def export_results_csv(
    matched_results: List[Dict[str, Any]],
    filename: str = CSV_FILENAME,
) -> None:

    if not WRITE_CSV:
        return

    fieldnames = [
        "company",
        "title",
        "location",
        "method",
        "matched_keywords",
        "url",
        "last_verified",
    ]

    try:

        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8-sig",
        ) as handle:

            writer = csv.DictWriter(
                handle,
                fieldnames=fieldnames,
            )

            writer.writeheader()

            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            for item in matched_results:

                row = {
                    field: item.get(
                        field,
                        "",
                    )
                    for field in fieldnames
                }

                row["last_verified"] = timestamp

                writer.writerow(row)

        console.print(
            f"[green]✔ CSV saved: {filename}[/green]"
        )

    except OSError as exc:

        console.print(
            f"[red]Could not write CSV: {exc}[/red]"
        )


# ============================================================================
# SOURCE AUDIT DISPLAY
# ============================================================================

def display_source_audit(
    audits: List[Dict[str, Any]],
) -> None:

    table = Table(
        title="Careers Source Audit"
    )

    table.add_column(
        "Company",
        style="cyan",
        no_wrap=True,
    )

    table.add_column(
        "Status",
        style="green",
    )

    table.add_column(
        "Platform",
        style="yellow",
    )

    table.add_column(
        "Verified URL",
        style="blue",
    )

    table.add_column(
        "Failed",
        style="red",
    )

    for audit in audits:

        verified = audit.get(
            "verified_sources",
            [],
        )

        failed = audit.get(
            "failed_sources",
            [],
        )

        if verified:

            platforms = ", ".join(
                sorted(
                    set(
                        item.get(
                            "platform",
                            "",
                        )
                        for item in verified
                    )
                )
            )

            urls = "\n".join(
                item.get(
                    "final_url",
                    "",
                )
                for item in verified
            )

            status = "[green]VERIFIED[/green]"

        else:

            platforms = "None"
            urls = audit.get(
                "primary_url",
                "",
            )
            status = "[red]FAILED[/red]"

        table.add_row(
            audit.get(
                "company",
                "",
            ),
            status,
            platforms,
            urls,
            str(len(failed)),
        )

    console.print(table)


# ============================================================================
# RESULTS DISPLAY
# ============================================================================

def display_results(
    matched_results: List[Dict[str, Any]],
) -> None:

    if not matched_results:

        console.print(
            "\n[yellow]"
            "No IAM/PAM matches were found from the configured "
            "official company/ATS sources."
            "[/yellow]\n"
        )

        return

    table = Table(
        title=(
            "Verified Enterprise UK IAM / PAM Openings"
        )
    )

    table.add_column(
        "Company",
        style="cyan",
        no_wrap=True,
    )

    table.add_column(
        "Exact Role Title",
        style="magenta",
    )

    table.add_column(
        "UK Location",
        style="green",
    )

    table.add_column(
        "Discovery Source",
        style="yellow",
    )

    table.add_column(
        "Matched Terms",
        style="white",
    )

    table.add_column(
        "Portal Link",
        style="blue",
        max_width=70,
    )

    for item in matched_results:

        table.add_row(
            item.get(
                "company",
                "",
            ),
            item.get(
                "title",
                "",
            ),
            item.get(
                "location",
                "",
            ),
            item.get(
                "method",
                "",
            ),
            item.get(
                "matched_keywords",
                "",
            ),
            item.get(
                "url",
                "",
            ),
        )

    console.print(table)

    console.print(
        f"\n[bold green]"
        f"Found {len(matched_results)} verified IAM/PAM opening(s)."
        f"[/bold green]"
    )


# ============================================================================
# MAIN SCANNER
# ============================================================================

def run_enterprise_scanner() -> None:

    console.print(
        "\n[bold cyan]"
        "🚀 Initializing Enterprise UK IAM/PAM Engine"
        "[/bold cyan]"
    )

    console.print(
        f"[cyan]"
        f"Company careers sources: {len(COMPANY_CAREERS)}"
        f" | API boards: {len(COMPANY_BOARDS)}"
        f" | Manual fallbacks: "
        f"{'ENABLED' if USE_MANUAL_FALLBACKS else 'DISABLED'}"
        f"[/cyan]\n"
    )

    if USE_PLAYWRIGHT_FALLBACK and not PLAYWRIGHT_AVAILABLE:

        console.print(
            "[yellow]"
            "Playwright is not installed. "
            "JavaScript-heavy careers pages may be missed."
            "[/yellow]"
        )

        console.print(
            "[yellow]"
            "Install with: pip install playwright && "
            "playwright install chromium"
            "[/yellow]\n"
        )

    matched_results: List[Dict[str, Any]] = []
    audits: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # 1. Public ATS API boards
    # ------------------------------------------------------------------------

    console.print(
        "[bold]1/3[/bold] Scanning configured public ATS APIs..."
    )

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                scan_api_board,
                board,
            ): board
            for board in COMPANY_BOARDS
        }

        for future in as_completed(
            futures
        ):

            try:
                results = future.result()
                matched_results.extend(
                    results
                )

            except Exception:
                pass

    console.print(
        f"   [green]API scan complete:"
        f" {len(matched_results)} match(es)[/green]"
    )

    # ------------------------------------------------------------------------
    # 2. Official company careers sources
    # ------------------------------------------------------------------------

    console.print(
        "\n[bold]2/3[/bold] Crawling official company careers sources..."
    )

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                crawl_careers_source,
                source,
            ): source
            for source in COMPANY_CAREERS
        }

        completed = 0

        for future in as_completed(
            futures
        ):

            completed += 1

            source = futures[future]

            try:

                results, audit = future.result()

                matched_results.extend(
                    results
                )

                audits.append(
                    audit
                )

                console.print(
                    f"   [{completed:02d}/{len(COMPANY_CAREERS):02d}] "
                    f"{source['company_name']}: "
                    f"{len(results)} match(es)"
                )

            except Exception as exc:

                console.print(
                    f"   [red]"
                    f"{source['company_name']}: "
                    f"scanner error: {exc}"
                    f"[/red]"
                )

    # ------------------------------------------------------------------------
    # 3. Optional manual fallback
    # ------------------------------------------------------------------------

    if USE_MANUAL_FALLBACKS:

        console.print(
            "\n[bold yellow]"
            "3/3 Manual fallbacks ENABLED..."
            "[/bold yellow]"
        )

        for fallback in DIRECT_URL_FALLBACKS:

            matched_results.append({
                "company": fallback["company"],
                "title": fallback["title"],
                "location": fallback["location"],
                "url": fallback["url"],
                "method": (
                    "MANUAL FALLBACK "
                    "(not automated discovery)"
                ),
                "matched_keywords": "manual",
            })

    else:

        console.print(
            "\n[bold]3/3[/bold] Manual individual-job URLs "
            "are disabled."
        )

    # ------------------------------------------------------------------------
    # Deduplicate
    # ------------------------------------------------------------------------

    if DEDUPLICATE_RESULTS:

        matched_results = deduplicate_results(
            matched_results
        )

    # ------------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------------

    matched_results.sort(
        key=lambda item: (
            item.get(
                "company",
                "",
            ).lower(),
            item.get(
                "title",
                "",
            ).lower(),
        )
    )

    console.print()

    display_results(
        matched_results
    )

    export_results_csv(
        matched_results
    )

    console.print()

    display_source_audit(
        audits
    )

    # ------------------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------------------

    verified_count = sum(
        1
        for audit in audits
        if audit.get(
            "verified_sources"
        )
    )

    failed_count = len(audits) - verified_count

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    console.print(
        f"\n[green]"
        f"✔ Scan completed: {timestamp}"
        f"[/green]"
    )

    console.print(
        f"[green]"
        f"✔ Verified careers sources: "
        f"{verified_count}/{len(COMPANY_CAREERS)}"
        f"[/green]"
    )

    if failed_count:
        console.print(
            f"[yellow]"
            f"⚠ Sources requiring review: {failed_count}"
            f"[/yellow]"
        )

    console.print(
        "[cyan]"
        "Discovery policy: official company careers pages + "
        "configured public ATS APIs only."
        "[/cyan]"
    )


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":

    try:
        run_enterprise_scanner()

    except KeyboardInterrupt:

        console.print(
            "\n[yellow]Scan interrupted by user.[/yellow]"
        )

        sys.exit(1)
