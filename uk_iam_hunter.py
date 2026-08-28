"""
UK IAM / PAM JOB HUNTER - v2
=============================

Purpose
-------
Find substantially more UK IAM/PAM vacancies than a simple careers-page crawler.

Discovery layers:
1. Official company career pages already in the company database
2. External career portals linked from those official pages
3. ATS discovery from links, scripts, iframes and page source
4. Common ATS endpoints where they can be discovered automatically
5. robots.txt / sitemap.xml discovery
6. Deep crawling of career/search/result pages
7. Playwright rendering for JavaScript-heavy portals
8. Search-engine discovery (Bing/Google result pages) as a discovery aid
   - ONLY results whose destination is an official company/ATS job page are kept
9. Structured JobPosting JSON-LD extraction
10. Generic job-page extraction
11. Strict UK + IAM/PAM relevance scoring
12. URL/title deduplication
13. CSV export
14. Optional Google Apps Script archiving

IMPORTANT
---------
- This script does NOT use your manually discovered individual vacancy URLs.
- It is designed for permanent UK IAM/PAM searching.
- Search engines are used to discover pages, not as the final source of truth.
- A result is retained only when the actual destination is an official company
  careers page or a recognised ATS host.
- The company database can be expanded without changing the crawler.

Install
-------
pip install requests beautifulsoup4 rich
pip install playwright
playwright install chromium

Optional:
pip install lxml

Run
---
python uk_iam_job_hunter_v2.py

The script creates:
- uk_iam_results_v2.csv
- uk_iam_source_audit_v2.csv
- uk_iam_run_log_v2.csv

Google Apps Script:
Set GOOGLE_APPS_SCRIPT_URL and GOOGLE_APPS_SCRIPT_TOKEN below if you want
newly discovered jobs archived automatically into your Google Sheet/Drive.
ARCHIVE_TO_GOOGLE = False by default so the first test cannot accidentally
populate the archive with bad matches.
"""

from __future__ import annotations

import csv
import html
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

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


# ============================================================================
# CONFIGURATION
# ============================================================================

REQUEST_TIMEOUT = 18
JOB_REQUEST_TIMEOUT = 15
SEARCH_TIMEOUT = 12

MAX_WORKERS = 10

# Deep crawling limits.
MAX_PAGES_PER_SOURCE = 18
MAX_JOB_LINKS_PER_SOURCE = 250
MAX_SEARCH_RESULTS_PER_QUERY = 15
MAX_SEARCH_QUERIES_PER_COMPANY = 10

# Search engine discovery can be disabled if you want pure direct-source mode.
USE_SEARCH_DISCOVERY = True

# Browser rendering is slower but important for modern ATS platforms.
USE_PLAYWRIGHT = True

# First test should be False.
ARCHIVE_TO_GOOGLE = False

GOOGLE_APPS_SCRIPT_URL = (
    "https://script.google.com/macros/s/"
    "AKfycbzAxS5Keh8vArI6xXwWc-SmU6DN-FkTcKDVONmEMCLdfxgrQR-vPoDfloxGK8Z0MVBssg/"
    "exec"
)

GOOGLE_APPS_SCRIPT_TOKEN = "IAMJOBSEARCHAUGUST2026"

RESULT_CSV = "uk_iam_results_v2.csv"
AUDIT_CSV = "uk_iam_source_audit_v2.csv"
RUN_LOG_CSV = "uk_iam_run_log_v2.csv"

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
# ATS DOMAINS
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
    "bamboohr.com": "BambooHR",
    "recruitee.com": "Recruitee",
    "personio.com": "Personio",
    "applytojob.com": "ApplyToJob",
    "phenompeople.com": "Phenom",
    "ultipro.com": "UKG",
    "ukg.com": "UKG",
}


# ============================================================================
# COMPANY DATABASE
# ============================================================================

COMPANY_CAREERS = [
    ("HSBC Holdings plc", "https://www.hsbc.com/careers"),
    ("Lloyds Banking Group plc", "https://www.lloydsbankinggroup.com/careers.html"),
    ("NatWest Group plc", "https://www.natwestgroup.com/careers-at-natwest-group.html"),
    ("Standard Chartered PLC", "https://www.standardchartered.com/en/careers"),
    ("Aviva plc", "https://www.aviva.com/careers/"),
    ("Schroders plc", "https://www.schroders.com/en-gb/uk/institutional/about-us/careers/"),
    ("Man Group plc", "https://www.man.com/careers"),
    ("Vodafone Group", "https://careers.vodafone.com/"),
    ("BT Group", "https://jobs.bt.com/"),
    ("Sky UK", "https://careers.sky.com/jobs"),
    ("Legal & General", "https://careers.legalandgeneral.com/"),
    ("Wise", "https://wise.jobs/"),
    ("BAE Systems", "https://www.baesystems.com/careers/"),
    ("Rolls-Royce", "https://careers.rolls-royce.com/our-locations/uk"),
    ("QinetiQ", "https://www.qinetiq.com/en-gb/careers"),
    ("GSK", "https://www.gsk.com/en-gb/careers/"),
    ("Kingfisher plc", "https://careers.kingfisher.com/"),
    ("Ocado Group", "https://careers.ocadogroup.com/"),
    ("National Grid", "https://www.nationalgrid.com/careers?region=uk"),
    ("Centrica", "https://www.centrica.com/careers"),
    ("SSE", "https://careers.sse.com/"),
    ("AstraZeneca", "https://careers.astrazeneca.com/search-jobs/united-kingdom"),
    ("Unilever UK", "https://careers.unilever.com/en/united-kingdom-and-ireland"),
    ("easyJet", "https://careers.easyjet.com/en"),
    ("Heathrow Airport", "https://www.heathrow.com/company/careers"),
    ("Royal Mail Group", "https://careers.royalmailgroup.com/gb/en"),
    ("DHL International UK", "https://careers.dhl.com/global/en/dhl-uk"),
    ("Serco", "https://www.serco.com/uk/careers"),
    ("Sopra Steria UK", "https://careers.soprasteria.co.uk/uk/en"),
    ("Computacenter", "https://careers.computacenter.com/uk/"),
    ("EY UK", "https://careers.ey.com/?locale=en_GB"),
    ("KPMG UK", "https://kpmg.com/uk/en/careers.html"),
    ("PwC UK", "https://www.pwc.co.uk/careers"),
    ("CGI UK", "https://www.cgi.com/uk/en-gb/careers"),
    ("Goldman Sachs", "https://www.goldmansachs.com/careers/"),
    ("Morgan Stanley", "https://www.morganstanley.com/careers/career-opportunities-search/"),
    ("Apple UK", "https://jobs.apple.com/en-us/search?location=united-kingdom-GBR"),
    ("University of Cambridge", "https://www.jobs.cam.ac.uk/"),
]


# ============================================================================
# KEYWORD MODEL
# ============================================================================

TITLE_STRONG = [
    "iam",
    "identity engineer",
    "identity analyst",
    "identity architect",
    "identity consultant",
    "identity specialist",
    "identity security",
    "identity governance",
    "access management",
    "access governance",
    "privileged access",
    "privileged identity",
    "pam engineer",
    "pam analyst",
    "pam architect",
    "cyberark",
    "sailpoint",
    "saviynt",
    "okta engineer",
    "entra id",
    "identity platform",
    "identity product",
]

IDENTITY_TERMS = [
    "identity and access management",
    "identity access management",
    "identity management",
    "access management",
    "identity governance",
    "access governance",
    "identity security",
    "identity lifecycle",
    "joiner mover leaver",
    "joiner-mover-leaver",
    "jml",
    "iga",
    "entitlement management",
    "access reviews",
    "access certification",
    "provisioning",
    "deprovisioning",
    "scim",
    "sso",
    "single sign-on",
    "federation",
]

PAM_TERMS = [
    "privileged access management",
    "privileged access",
    "privileged identity",
    "privileged account",
    "pam",
    "cyberark",
    "beyondtrust",
    "delinea",
    "one identity",
    "secret server",
    "secrets management",
    "vault",
    "session monitoring",
]

MICROSOFT_TERMS = [
    "entra id",
    "microsoft entra",
    "azure ad",
    "azure active directory",
    "privileged identity management",
    "pim",
    "conditional access",
    "authentication strength",
    "passwordless",
    "microsoft graph",
    "graph api",
    "azure identity",
]

PLATFORM_TERMS = [
    "okta",
    "ping identity",
    "pingfederate",
    "forgerock",
    "saviynt",
    "sailpoint",
    "identitynow",
    "identityiq",
    "hashicorp vault",
]

SECURITY_CONTEXT_TERMS = [
    "zero trust",
    "cyber security",
    "cybersecurity",
    "security operations",
    "security engineering",
    "cloud security",
    "information security",
    "access control",
    "rbac",
    "least privilege",
]

EXCLUDE_TITLE = [
    "intern",
    "internship",
    "graduate scheme",
    "apprentice",
    "apprenticeship",
    "receptionist",
    "sales representative",
    "account executive",
    "marketing",
    "software developer",
    "software engineer",
    "frontend",
    "backend",
    "data scientist",
    "machine learning engineer",
    "mechanical engineer",
]

PERMANENT_TERMS = [
    "permanent",
    "full time",
    "full-time",
    "employee",
]

CONTRACT_TERMS = [
    "contract",
    "contractor",
    "temporary",
    "fixed term",
    "fixed-term",
    "interim",
    "day rate",
    "inside ir35",
    "outside ir35",
]

UK_TERMS = [
    "united kingdom",
    "uk",
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
    "remote uk",
    "uk remote",
    "remote, uk",
    "remote - uk",
]

# Search queries are deliberately varied because one query almost never
# exposes every vacancy on a corporate ATS.
SEARCH_TEMPLATES = [
    '"{company}" IAM jobs UK',
    '"{company}" "identity" jobs UK',
    '"{company}" "identity engineer" UK',
    '"{company}" "identity analyst" UK',
    '"{company}" "identity and access management" UK',
    '"{company}" "access management" UK',
    '"{company}" "privileged access" UK',
    '"{company}" CyberArk UK jobs',
    '"{company}" SailPoint UK jobs',
    '"{company}" Saviynt UK jobs',
]


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Page:
    url: str
    html: str
    final_url: str
    source: str


# ============================================================================
# HTTP
# ============================================================================

def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(HEADERS)
    return session


def normalise_url(url: str) -> str:
    if not url:
        return ""
    return url.strip().rstrip("#")


def host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def root_domain(url: str) -> str:
    h = host(url)
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def ats_platform(url: str) -> str:
    h = host(url)
    for domain, name in ATS_DOMAINS.items():
        if h == domain or h.endswith("." + domain):
            return name
    return ""


def is_ats(url: str) -> bool:
    return bool(ats_platform(url))


def fetch(session: requests.Session, url: str, timeout: int = REQUEST_TIMEOUT) -> Optional[requests.Response]:
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        if r.status_code >= 400:
            return None
        return r
    except requests.RequestException:
        return None


# ============================================================================
# TEXT / HTML
# ============================================================================

def soup_text(html_text: str) -> str:
    soup = BeautifulSoup(html_text, "html.parser")
    for tag in soup(["script", "style", "noscript", "svg"]):
        tag.decompose()
    return re.sub(r"\s+", " ", soup.get_text(" ", strip=True))


def clean_html_description(value: str) -> str:
    return soup_text(value)


def decode_entities(text: str) -> str:
    return html.unescape(text or "")


# ============================================================================
# URL CANONICALISATION
# ============================================================================

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "source", "ref", "referrer", "fbclid", "gclid",
}


def canonical_url(url: str) -> str:
    if not url:
        return ""

    try:
        p = urlparse(url)
        query = [
            (k, v)
            for k, v in parse_qsl(p.query, keep_blank_values=True)
            if k.lower() not in TRACKING_PARAMS
        ]
        path = re.sub(r"/+", "/", p.path).rstrip("/")

        return urlunparse((
            p.scheme.lower() or "https",
            p.netloc.lower(),
            path,
            "",
            urlencode(query),
            "",
        )).lower()
    except Exception:
        return url.strip().rstrip("/").lower()


# ============================================================================
# KEYWORD / RELEVANCE ENGINE
# ============================================================================

def phrase_found(phrase: str, text: str) -> bool:
    if not phrase or not text:
        return False

    if len(phrase) <= 4:
        return re.search(
            rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])",
            text,
            re.I,
        ) is not None

    return phrase.lower() in text.lower()


def matched_terms(text: str, terms: Iterable[str]) -> List[str]:
    return [t for t in terms if phrase_found(t, text)]


def score_job(title: str, description: str, location: str, url: str) -> Tuple[int, List[str], List[str]]:
    t = title.lower()
    d = description.lower()
    l = location.lower()
    u = url.lower()

    title_hits = matched_terms(t, TITLE_STRONG)
    identity_hits = matched_terms(d, IDENTITY_TERMS)
    pam_hits = matched_terms(d, PAM_TERMS)
    ms_hits = matched_terms(d, MICROSOFT_TERMS)
    platform_hits = matched_terms(d, PLATFORM_TERMS)
    security_hits = matched_terms(d, SECURITY_CONTEXT_TERMS)
    uk_hits = matched_terms(f"{l} {d} {u}", UK_TERMS)

    score = 0

    score += min(50, len(title_hits) * 25)
    score += min(25, len(identity_hits) * 5)
    score += min(25, len(pam_hits) * 7)
    score += min(20, len(ms_hits) * 4)
    score += min(15, len(platform_hits) * 5)
    score += min(10, len(security_hits) * 2)

    if title_hits:
        score += 20

    # A role called "Cloud Security Engineer" can be valid if the body is
    # strongly identity/PAM focused, but not merely because "security" occurs.
    body_identity_count = (
        len(identity_hits)
        + len(pam_hits)
        + len(ms_hits)
        + len(platform_hits)
    )

    if body_identity_count >= 3:
        score += 20

    # Strong penalty for obvious unrelated roles.
    exclude_hits = matched_terms(t, EXCLUDE_TITLE)
    score -= len(exclude_hits) * 50

    # Contract-only roles are excluded later, but scoring makes them obvious.
    contract_hits = matched_terms(d, CONTRACT_TERMS)
    permanent_hits = matched_terms(d, PERMANENT_TERMS)

    if contract_hits and not permanent_hits:
        score -= 25

    if not uk_hits:
        score -= 100

    all_hits = (
        title_hits
        + identity_hits
        + pam_hits
        + ms_hits
        + platform_hits
        + security_hits
    )

    return score, all_hits, contract_hits


def is_uk(location: str, description: str, url: str = "") -> bool:
    text = f"{location} {description} {url}".lower()

    # Avoid accepting "UK" simply because the corporate page has a global
    # navigation menu. Prefer actual job/location context where possible.
    return any(phrase_found(term, text) for term in UK_TERMS)


def is_permanent(title: str, description: str) -> bool:
    text = f"{title} {description}".lower()

    if any(phrase_found(term, text) for term in CONTRACT_TERMS):
        if not any(phrase_found(term, text) for term in PERMANENT_TERMS):
            return False

    return True


# ============================================================================
# JSON-LD
# ============================================================================

def jsonld_items(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    output = []

    for script in soup.find_all("script", type="application/ld+json"):
        raw = script.string or script.get_text()
        if not raw:
            continue

        try:
            data = json.loads(raw)
        except Exception:
            continue

        items = []

        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            if isinstance(data.get("@graph"), list):
                items = data["@graph"]
            else:
                items = [data]

        for item in items:
            if isinstance(item, dict):
                output.append(item)

    return output


def location_from_jsonld(value: Any) -> str:
    def one(v: Any) -> str:
        if isinstance(v, str):
            return v

        if not isinstance(v, dict):
            return ""

        addr = v.get("address", v)

        if isinstance(addr, dict):
            parts = [
                addr.get("addressLocality"),
                addr.get("addressRegion"),
                addr.get("postalCode"),
                addr.get("addressCountry"),
            ]
            return ", ".join(str(x) for x in parts if x)

        return str(addr or "")

    if isinstance(value, list):
        return " | ".join(one(x) for x in value)

    return one(value)


def extract_json_jobs(html_text: str, base_url: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html_text, "html.parser")
    results = []

    for item in jsonld_items(soup):
        item_type = item.get("@type", "")
        types = item_type if isinstance(item_type, list) else [item_type]

        if "JobPosting" not in types:
            continue

        title = str(item.get("title", "")).strip()
        description = clean_html_description(str(item.get("description", "")))
        location = location_from_jsonld(item.get("jobLocation", ""))

        raw_url = item.get("url") or base_url
        job_url = urljoin(base_url, str(raw_url))

        employment = item.get("employmentType", "")
        if isinstance(employment, list):
            employment = ", ".join(map(str, employment))

        date_posted = str(item.get("datePosted", "") or "")
        valid_through = str(item.get("validThrough", "") or "")

        results.append({
            "title": title,
            "description": description,
            "location": location,
            "url": job_url,
            "employment_type": str(employment),
            "date_posted": date_posted,
            "valid_through": valid_through,
            "source_type": "JSON-LD",
        })

    return results


# ============================================================================
# LINK DISCOVERY
# ============================================================================

JOB_HINTS = [
    "job", "jobs", "career", "careers", "vacanc", "opportunit",
    "position", "opening", "requisition", "apply", "employment",
    "posting", "search", "viewjob", "jobdetails", "job-detail",
    "jobdetail", "job-id", "jobid", "jobs/view",
]

PAGE_HINTS = [
    "page=", "p=", "start=", "offset=", "next", "load-more",
    "loadmore", "view-all", "all-jobs", "search-jobs",
    "search?query", "jobs?query",
]


def looks_like_job_url(url: str, anchor_text: str = "") -> bool:
    text = f"{url} {anchor_text}".lower()
    return any(x in text for x in JOB_HINTS)


def looks_like_pagination(url: str, anchor_text: str = "") -> bool:
    text = f"{url} {anchor_text}".lower()
    return any(x in text for x in PAGE_HINTS)


def extract_links(html_text: str, page_url: str) -> Tuple[List[str], List[str]]:
    soup = BeautifulSoup(html_text, "html.parser")

    job_links = []
    page_links = []
    seen_jobs = set()
    seen_pages = set()

    for a in soup.find_all("a", href=True):
        href = str(a.get("href", "")).strip()
        if not href:
            continue

        if href.lower().startswith(("mailto:", "tel:", "javascript:")):
            continue

        absolute = normalise_url(urljoin(page_url, href))
        text = a.get_text(" ", strip=True)

        if not absolute.startswith(("http://", "https://")):
            continue

        if looks_like_job_url(absolute, text):
            key = canonical_url(absolute)
            if key and key not in seen_jobs:
                seen_jobs.add(key)
                job_links.append(absolute)

        elif looks_like_pagination(absolute, text):
            key = canonical_url(absolute)
            if key and key not in seen_pages:
                seen_pages.add(key)
                page_links.append(absolute)

    # Also inspect iframes: many ATS systems embed their job portal this way.
    for iframe in soup.find_all("iframe", src=True):
        iframe_url = normalise_url(urljoin(page_url, iframe["src"]))
        if iframe_url.startswith(("http://", "https://")):
            if is_ats(iframe_url) or looks_like_job_url(iframe_url):
                if iframe_url not in page_links:
                    page_links.append(iframe_url)

    return job_links, page_links


# ============================================================================
# ATS / EMBEDDED PORTAL DISCOVERY
# ============================================================================

def discover_ats_urls(html_text: str, base_url: str) -> Set[str]:
    found: Set[str] = set()

    soup = BeautifulSoup(html_text, "html.parser")

    candidates = []

    for a in soup.find_all("a", href=True):
        candidates.append(urljoin(base_url, a["href"]))

    for iframe in soup.find_all("iframe", src=True):
        candidates.append(urljoin(base_url, iframe["src"]))

    # Search raw source too because ATS URLs are frequently inside JavaScript.
    candidates.extend(
        re.findall(
            r'https?://[^"\'<>\s]+',
            html_text,
            flags=re.I,
        )
    )

    for candidate in candidates:
        candidate = html.unescape(candidate).replace("\\/", "/")
        candidate = candidate.rstrip("')]}>,.;")

        if is_ats(candidate):
            found.add(candidate)

    return found


# ============================================================================
# SITEMAPS
# ============================================================================

def discover_sitemaps(session: requests.Session, base_url: str) -> Set[str]:
    found = set()

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    robots_url = origin + "/robots.txt"

    response = fetch(session, robots_url, timeout=10)

    if response:
        for line in response.text.splitlines():
            if line.lower().startswith("sitemap:"):
                value = line.split(":", 1)[1].strip()
                if value.startswith("http"):
                    found.add(value)

    # Always try conventional sitemap names.
    found.add(origin + "/sitemap.xml")
    found.add(origin + "/sitemap_index.xml")

    return found


def extract_sitemap_urls(session: requests.Session, sitemap_url: str) -> Set[str]:
    found = set()
    response = fetch(session, sitemap_url, timeout=12)

    if not response:
        return found

    content = response.text

    # Works for sitemap XML without needing another XML package.
    for match in re.findall(r"<loc>\s*(.*?)\s*</loc>", content, flags=re.I | re.S):
        value = html.unescape(match.strip())
        if value.startswith("http"):
            found.add(value)

    return found


# ============================================================================
# PLAYWRIGHT
# ============================================================================

def render(url: str) -> Optional[Page]:
    if not USE_PLAYWRIGHT or not PLAYWRIGHT_AVAILABLE:
        return None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                locale="en-GB",
                user_agent=USER_AGENT,
                viewport={"width": 1440, "height": 1000},
            )
            page = context.new_page()

            page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=35000,
            )

            # Allow ATS JavaScript to build its results.
            page.wait_for_timeout(3000)

            # Scroll so lazy-loaded jobs can appear.
            for _ in range(3):
                page.mouse.wheel(0, 2500)
                page.wait_for_timeout(700)

            html_text = page.content()
            final_url = page.url

            browser.close()

            return Page(
                url=url,
                html=html_text,
                final_url=final_url,
                source="Playwright",
            )

    except Exception:
        return None


# ============================================================================
# SEARCH ENGINE DISCOVERY
# ============================================================================

def search_query_urls(session: requests.Session, query: str) -> List[str]:
    """
    Search-engine discovery is deliberately best-effort.

    We do not trust search snippets as job data. We only use returned URLs to
    locate a real company/ATS page, which is then fetched and evaluated.
    """

    urls: List[str] = []

    # Bing HTML is relatively straightforward to parse.
    try:
        params = {"q": query, "count": MAX_SEARCH_RESULTS_PER_QUERY}
        response = session.get(
            "https://www.bing.com/search",
            params=params,
            timeout=SEARCH_TIMEOUT,
            headers=HEADERS,
        )

        if response.ok:
            soup = BeautifulSoup(response.text, "html.parser")

            for a in soup.select("li.b_algo h2 a"):
                href = a.get("href")
                if href and href.startswith("http"):
                    urls.append(href)

    except requests.RequestException:
        pass

    # Google fallback. Google markup changes frequently, so this is optional.
    if len(urls) < 5:
        try:
            params = {"q": query, "num": MAX_SEARCH_RESULTS_PER_QUERY}
            response = session.get(
                "https://www.google.com/search",
                params=params,
                timeout=SEARCH_TIMEOUT,
                headers=HEADERS,
            )

            if response.ok:
                soup = BeautifulSoup(response.text, "html.parser")

                for a in soup.find_all("a", href=True):
                    href = a["href"]

                    if href.startswith("/url?q="):
                        href = href.split("/url?q=", 1)[1].split("&", 1)[0]

                    if href.startswith("http"):
                        urls.append(href)

        except requests.RequestException:
            pass

    # Deduplicate while retaining order.
    output = []
    seen = set()

    for url in urls:
        key = canonical_url(url)
        if key and key not in seen:
            seen.add(key)
            output.append(url)

    return output[:MAX_SEARCH_RESULTS_PER_QUERY]


# ============================================================================
# JOB RECORD
# ============================================================================

def make_job(
    company: str,
    title: str,
    description: str,
    location: str,
    url: str,
    method: str,
    employment_type: str = "",
    date_posted: str = "",
    valid_through: str = "",
) -> Optional[Dict[str, Any]]:

    title = decode_entities(title).strip()
    description = decode_entities(description).strip()
    location = decode_entities(location).strip()
    url = normalise_url(url)

    if not title or not url:
        return None

    score, hits, contract_hits = score_job(
        title,
        description,
        location,
        url,
    )

    if score < 35:
        return None

    if not is_uk(location, description, url):
        return None

    if not is_permanent(title, description):
        return None

    # A title-only weak match is not enough. Require either:
    # - strong identity title, or
    # - at least two body identity/PAM/platform signals.
    title_hits = matched_terms(title.lower(), TITLE_STRONG)
    body_hits = (
        matched_terms(description, IDENTITY_TERMS)
        + matched_terms(description, PAM_TERMS)
        + matched_terms(description, MICROSOFT_TERMS)
        + matched_terms(description, PLATFORM_TERMS)
    )

    if not title_hits and len(body_hits) < 2:
        return None

    platform = ats_platform(url) or "Corporate"

    return {
        "company": company,
        "title": title,
        "location": location or "UK",
        "employment_type": employment_type,
        "date_posted": date_posted,
        "valid_through": valid_through,
        "score": score,
        "matched_keywords": ", ".join(dict.fromkeys(hits)),
        "platform": platform,
        "discovery_method": method,
        "url": url,
        "canonical_url": canonical_url(url),
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================================
# SOURCE CRAWLER
# ============================================================================

def crawl_company(company: str, careers_url: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    session = make_session()

    audit = {
        "company": company,
        "seed_url": careers_url,
        "status": "FAILED",
        "final_url": "",
        "ats_found": 0,
        "pages_scanned": 0,
        "job_links_found": 0,
        "search_urls_found": 0,
        "sitemap_urls_found": 0,
        "matches": 0,
        "error": "",
    }

    results: List[Dict[str, Any]] = []
    seen_pages: Set[str] = set()
    job_links: Set[str] = set()
    queue: List[str] = [careers_url]

    # ------------------------------------------------------------------------
    # Seed
    # ------------------------------------------------------------------------
    response = fetch(session, careers_url)

    if response:
        seed_page = Page(
            careers_url,
            response.text,
            response.url,
            "Requests",
        )
        audit["status"] = "VERIFIED"
        audit["final_url"] = response.url
        queue.append(response.url)
    else:
        seed_page = render(careers_url)
        if seed_page:
            audit["status"] = "VERIFIED"
            audit["final_url"] = seed_page.final_url
            queue.append(seed_page.final_url)
        else:
            audit["error"] = "Seed page unavailable"
            return [], audit

    # ------------------------------------------------------------------------
    # Search-engine discovery
    # ------------------------------------------------------------------------
    if USE_SEARCH_DISCOVERY:
        search_urls = []

        for template in SEARCH_TEMPLATES[:MAX_SEARCH_QUERIES_PER_COMPANY]:
            query = template.format(company=company)
            found = search_query_urls(session, query)
            search_urls.extend(found)

        for url in search_urls:
            parsed_host = host(url)

            # Keep only official company host or recognised ATS host.
            if parsed_host == host(careers_url) or is_ats(url):
                if url not in queue:
                    queue.append(url)

        audit["search_urls_found"] = len(search_urls)

    # ------------------------------------------------------------------------
    # Sitemap discovery
    # ------------------------------------------------------------------------
    sitemap_urls = discover_sitemaps(session, careers_url)

    sitemap_job_urls = set()

    for sitemap in list(sitemap_urls)[:5]:
        for item in extract_sitemap_urls(session, sitemap):
            if looks_like_job_url(item):
                sitemap_job_urls.add(item)

    audit["sitemap_urls_found"] = len(sitemap_job_urls)

    for url in list(sitemap_job_urls)[:MAX_JOB_LINKS_PER_SOURCE]:
        job_links.add(url)

    # ------------------------------------------------------------------------
    # Deep page crawl
    # ------------------------------------------------------------------------
    while queue and audit["pages_scanned"] < MAX_PAGES_PER_SOURCE:
        page_url = queue.pop(0)
        key = canonical_url(page_url)

        if not key or key in seen_pages:
            continue

        seen_pages.add(key)

        page = None

        response = fetch(session, page_url)

        if response:
            page = Page(
                page_url,
                response.text,
                response.url,
                "Requests",
            )

            # If static HTML looks empty, render it.
            if len(soup_text(response.text)) < 900:
                rendered = render(response.url)
                if rendered:
                    page = rendered

        else:
            page = render(page_url)

        if not page:
            continue

        audit["pages_scanned"] += 1

        # Discover embedded ATS portals.
        ats_urls = discover_ats_urls(page.html, page.final_url)
        audit["ats_found"] += len(ats_urls)

        for ats_url in ats_urls:
            if ats_url not in seen_pages and len(queue) < MAX_PAGES_PER_SOURCE * 2:
                queue.append(ats_url)

        # Structured jobs directly on the page.
        for job in extract_json_jobs(page.html, page.final_url):
            record = make_job(
                company=company,
                title=job["title"],
                description=job["description"],
                location=job["location"],
                url=job["url"],
                method=f"{page.source} -> JSON-LD",
                employment_type=job.get("employment_type", ""),
                date_posted=job.get("date_posted", ""),
                valid_through=job.get("valid_through", ""),
            )
            if record:
                results.append(record)

        links, page_links = extract_links(
            page.html,
            page.final_url,
        )

        for link in links:
            if len(job_links) >= MAX_JOB_LINKS_PER_SOURCE:
                break
            job_links.add(link)

        # Follow same company domain, ATS domains, and obvious careers pages.
        base_root = root_domain(page.final_url)

        for link in page_links + links:
            if len(queue) >= MAX_PAGES_PER_SOURCE * 2:
                break

            link_host = host(link)

            allowed = (
                link_host == host(careers_url)
                or link_host.endswith("." + host(careers_url))
                or root_domain(link) == base_root
                or is_ats(link)
            )

            if allowed and (
                looks_like_job_url(link)
                or looks_like_pagination(link)
                or "career" in link.lower()
                or "job" in link.lower()
            ):
                if canonical_url(link) not in seen_pages:
                    queue.append(link)

    audit["job_links_found"] = len(job_links)

    # ------------------------------------------------------------------------
    # Fetch individual jobs
    # ------------------------------------------------------------------------
    for job_url in list(job_links)[:MAX_JOB_LINKS_PER_SOURCE]:
        page = None

        response = fetch(
            session,
            job_url,
            timeout=JOB_REQUEST_TIMEOUT,
        )

        if response:
            page = Page(
                job_url,
                response.text,
                response.url,
                "Requests",
            )

            if len(soup_text(response.text)) < 900:
                rendered = render(response.url)
                if rendered:
                    page = rendered
        else:
            page = render(job_url)

        if not page:
            continue

        jobs = extract_json_jobs(
            page.html,
            page.final_url,
        )

        if jobs:
            for job in jobs:
                record = make_job(
                    company=company,
                    title=job["title"],
                    description=job["description"],
                    location=job["location"],
                    url=job["url"] or page.final_url,
                    method=f"{page.source} -> JobPosting",
                    employment_type=job.get("employment_type", ""),
                    date_posted=job.get("date_posted", ""),
                    valid_through=job.get("valid_through", ""),
                )
                if record:
                    results.append(record)

            continue

        # Generic job page.
        soup = BeautifulSoup(page.html, "html.parser")

        h1 = soup.find("h1")
        title = h1.get_text(" ", strip=True) if h1 else ""

        if not title and soup.title:
            title = soup.title.get_text(" ", strip=True)

        description = soup_text(page.html)

        location = ""

        for selector in [
            '[data-testid*="location"]',
            '[class*="location"]',
            '[id*="location"]',
            '[class*="Location"]',
            '[data-automation-id*="location"]',
        ]:
            node = soup.select_one(selector)
            if node:
                location = node.get_text(" ", strip=True)
                if location:
                    break

        record = make_job(
            company=company,
            title=title,
            description=description,
            location=location,
            url=page.final_url,
            method=f"{page.source} -> Generic job page",
        )

        if record:
            results.append(record)

    audit["matches"] = len(results)

    return results, audit


# ============================================================================
# DEDUPLICATION
# ============================================================================

def deduplicate(results: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output = []
    seen_urls = set()
    seen_fuzzy = set()

    for item in results:
        url_key = canonical_url(item.get("url", ""))

        company = re.sub(
            r"[^a-z0-9]+",
            " ",
            item.get("company", "").lower(),
        ).strip()

        title = re.sub(
            r"[^a-z0-9]+",
            " ",
            item.get("title", "").lower(),
        ).strip()

        fuzzy_key = f"{company}|{title}"

        if url_key and url_key in seen_urls:
            continue

        if fuzzy_key in seen_fuzzy:
            continue

        if url_key:
            seen_urls.add(url_key)

        seen_fuzzy.add(fuzzy_key)
        output.append(item)

    return output


# ============================================================================
# GOOGLE APPS SCRIPT
# ============================================================================

def archive_to_google(item: Dict[str, Any]) -> bool:
    if not ARCHIVE_TO_GOOGLE:
        return False

    if not GOOGLE_APPS_SCRIPT_URL or not GOOGLE_APPS_SCRIPT_TOKEN:
        return False

    payload = {
        "token": GOOGLE_APPS_SCRIPT_TOKEN,
        "application_id": "",
        "date_applied": "",
        "company": item.get("company", ""),
        "title": item.get("title", ""),
        "job_reference": "",
        "url": item.get("url", ""),
        "source": item.get("discovery_method", ""),
        "salary": "",
        "location": item.get("location", ""),
        "working_arrangement": "",
        "employment_type": item.get("employment_type", ""),
        "status": "Discovered",
        "matched_keywords": item.get("matched_keywords", ""),
        "match_score": item.get("score", ""),
        "notes": "Discovered by UK IAM Job Hunter v2",
    }

    try:
        response = requests.post(
            GOOGLE_APPS_SCRIPT_URL,
            json=payload,
            timeout=20,
        )
        return response.ok
    except requests.RequestException:
        return False


# ============================================================================
# CSV
# ============================================================================

def write_csv(filename: str, rows: List[Dict[str, Any]], fields: List[str]) -> None:
    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def write_audit(audits: List[Dict[str, Any]]) -> None:
    fields = [
        "company",
        "seed_url",
        "status",
        "final_url",
        "ats_found",
        "pages_scanned",
        "job_links_found",
        "search_urls_found",
        "sitemap_urls_found",
        "matches",
        "error",
    ]
    write_csv(AUDIT_CSV, audits, fields)


def write_run_log(results: List[Dict[str, Any]], audits: List[Dict[str, Any]]) -> None:
    row = {
        "run_time_utc": datetime.now(timezone.utc).isoformat(),
        "companies": len(COMPANY_CAREERS),
        "verified_sources": sum(a["status"] == "VERIFIED" for a in audits),
        "results": len(results),
        "search_discovery": USE_SEARCH_DISCOVERY,
        "playwright": USE_PLAYWRIGHT and PLAYWRIGHT_AVAILABLE,
        "google_archive": ARCHIVE_TO_GOOGLE,
    }

    exists = False
    try:
        with open(RUN_LOG_CSV, "r", encoding="utf-8-sig"):
            exists = True
    except OSError:
        pass

    with open(
        RUN_LOG_CSV,
        "a",
        newline="",
        encoding="utf-8-sig",
    ) as f:
        fields = list(row.keys())
        writer = csv.DictWriter(f, fieldnames=fields)
        if not exists:
            writer.writeheader()
        writer.writerow(row)


# ============================================================================
# DISPLAY
# ============================================================================

def display_results(results: List[Dict[str, Any]]) -> None:
    if not results:
        console.print(
            "\n[yellow]No qualifying UK IAM/PAM vacancies found.[/yellow]"
        )
        return

    table = Table(
        title=f"UK IAM / PAM Jobs Found — {len(results)}"
    )

    table.add_column("Score", style="green", no_wrap=True)
    table.add_column("Company", style="cyan", no_wrap=True)
    table.add_column("Exact Role", style="magenta")
    table.add_column("Location", style="green")
    table.add_column("Platform", style="yellow")
    table.add_column("Matched Terms", style="white", max_width=45)
    table.add_column("URL", style="blue", max_width=65)

    for item in results:
        table.add_row(
            str(item.get("score", "")),
            item.get("company", ""),
            item.get("title", ""),
            item.get("location", ""),
            item.get("platform", ""),
            item.get("matched_keywords", ""),
            item.get("url", ""),
        )

    console.print(table)


def display_audit(audits: List[Dict[str, Any]]) -> None:
    table = Table(title="Deep Source Audit")

    table.add_column("Company", style="cyan", no_wrap=True)
    table.add_column("Status", style="green")
    table.add_column("Pages")
    table.add_column("Job Links")
    table.add_column("ATS")
    table.add_column("Search URLs")
    table.add_column("Sitemap Jobs")
    table.add_column("Matches")

    for a in audits:
        status = (
            "[green]VERIFIED[/green]"
            if a["status"] == "VERIFIED"
            else "[red]FAILED[/red]"
        )

        table.add_row(
            a["company"],
            status,
            str(a["pages_scanned"]),
            str(a["job_links_found"]),
            str(a["ats_found"]),
            str(a["search_urls_found"]),
            str(a["sitemap_urls_found"]),
            str(a["matches"]),
        )

    console.print(table)


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    started = time.time()

    console.print(
        "\n[bold cyan]"
        "🚀 UK IAM / PAM JOB HUNTER v2"
        "[/bold cyan]"
    )

    console.print(
        f"Companies: {len(COMPANY_CAREERS)} | "
        f"Search discovery: {'ON' if USE_SEARCH_DISCOVERY else 'OFF'} | "
        f"Playwright: "
        f"{'ON' if USE_PLAYWRIGHT and PLAYWRIGHT_AVAILABLE else 'OFF'} | "
        f"Google archive: {'ON' if ARCHIVE_TO_GOOGLE else 'OFF'}\n"
    )

    if USE_PLAYWRIGHT and not PLAYWRIGHT_AVAILABLE:
        console.print(
            "[yellow]"
            "Playwright is not installed. Install with:\n"
            "pip install playwright\n"
            "playwright install chromium"
            "[/yellow]\n"
        )

    all_results: List[Dict[str, Any]] = []
    audits: List[Dict[str, Any]] = []

    # Threaded company scanning. Each worker owns its own requests session.
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(crawl_company, company, url): (company, url)
            for company, url in COMPANY_CAREERS
        }

        completed = 0

        for future in as_completed(futures):
            completed += 1
            company, _ = futures[future]

            try:
                results, audit = future.result()
                all_results.extend(results)
                audits.append(audit)

                console.print(
                    f"[{completed:02d}/{len(COMPANY_CAREERS):02d}] "
                    f"{company}: "
                    f"[green]{len(results)} match(es)[/green] "
                    f"| pages={audit['pages_scanned']} "
                    f"| job-links={audit['job_links_found']}"
                )

            except Exception as exc:
                audits.append({
                    "company": company,
                    "seed_url": "",
                    "status": "FAILED",
                    "final_url": "",
                    "ats_found": 0,
                    "pages_scanned": 0,
                    "job_links_found": 0,
                    "search_urls_found": 0,
                    "sitemap_urls_found": 0,
                    "matches": 0,
                    "error": str(exc),
                })

                console.print(
                    f"[red]{company}: {exc}[/red]"
                )

    all_results = deduplicate(all_results)

    # Highest relevance first.
    all_results.sort(
        key=lambda x: (
            -int(x.get("score", 0)),
            x.get("company", "").lower(),
            x.get("title", "").lower(),
        )
    )

    # Archive only after dedupe/relevance filtering.
    archived = 0

    if ARCHIVE_TO_GOOGLE and all_results:
        console.print("\n[bold]Archiving results to Google Apps Script...[/bold]")

        for item in all_results:
            if archive_to_google(item):
                archived += 1

    fields = [
        "company",
        "title",
        "location",
        "employment_type",
        "date_posted",
        "valid_through",
        "score",
        "matched_keywords",
        "platform",
        "discovery_method",
        "url",
        "canonical_url",
        "discovered_at",
    ]

    write_csv(RESULT_CSV, all_results, fields)
    write_audit(audits)
    write_run_log(all_results, audits)

    console.print()
    display_results(all_results)
    console.print()
    display_audit(audits)

    elapsed = time.time() - started
    verified = sum(a["status"] == "VERIFIED" for a in audits)

    console.print(
        f"\n[bold green]"
        f"✔ Scan complete in {elapsed:.1f}s"
        f"[/bold green]"
    )
    console.print(
        f"[green]✔ Qualified UK IAM/PAM vacancies: "
        f"{len(all_results)}[/green]"
    )
    console.print(
        f"[green]✔ Verified company sources: "
        f"{verified}/{len(COMPANY_CAREERS)}[/green]"
    )
    console.print(
        f"[cyan]✔ Results CSV: {RESULT_CSV}[/cyan]"
    )
    console.print(
        f"[cyan]✔ Audit CSV: {AUDIT_CSV}[/cyan]"
    )

    if ARCHIVE_TO_GOOGLE:
        console.print(
            f"[cyan]✔ Google archive submissions: {archived}[/cyan]"
        )

    console.print(
        "\n[bold]Discovery policy:[/bold] "
        "official company/ATS destinations only; "
        "search engines are used to discover those destinations."
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        sys.exit(1)
