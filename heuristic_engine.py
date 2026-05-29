"""
heuristic_engine.py — Kavach Phishing Detection
Heuristic pre-screening engine for Indian-context URLs.
Exposes: analyze_url(url: str) -> dict
"""

import re
import time
import logging
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse

import tldextract
import whois
from dateutil import parser as dateutil_parser

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("kavach.heuristic")

# ─────────────────────────────────────────────
# WHITELIST
# ─────────────────────────────────────────────

WHITELIST: dict[str, str] = {
    # Banking
    "sbi.co.in":                   "sbi.co.in",
    "onlinesbi.sbi":               "onlinesbi.sbi",
    "hdfcbank.com":                "hdfcbank.com",
    "icicibank.com":               "icicibank.com",
    "axisbank.com":                "axisbank.com",
    "pnbindia.in":                 "pnbindia.in",
    "bankofbaroda.in":             "bankofbaroda.in",
    "canarabank.in":               "canarabank.in",
    "unionbankofindia.co.in":      "unionbankofindia.co.in",
    "kotak.com":                   "kotak.com",
    "yesbank.in":                  "yesbank.in",
    "idfcfirstbank.com":           "idfcfirstbank.com",
    # Government
    "gov.in":                      "gov.in",
    "nic.in":                      "nic.in",
    "india.gov.in":                "india.gov.in",
    "incometax.gov.in":            "incometax.gov.in",
    "irctc.co.in":                 "irctc.co.in",
    "uidai.gov.in":                "uidai.gov.in",
    "epfindia.gov.in":             "epfindia.gov.in",
    "npci.org.in":                 "npci.org.in",
    "rbi.org.in":                  "rbi.org.in",
    "sebi.gov.in":                 "sebi.gov.in",
    "mca.gov.in":                  "mca.gov.in",
    "passport.gov.in":             "passport.gov.in",
    # UPI / Payments
    "phonepe.com":                 "phonepe.com",
    "paytm.com":                   "paytm.com",
    "googlepay.com":               "googlepay.com",
    "bhimupi.org.in":              "bhimupi.org.in",
    "upi.npci.org.in":             "upi.npci.org.in",
}

# Map brand keyword → set of official registered domains
BRAND_OFFICIAL_DOMAINS: dict[str, set[str]] = {
    "sbi":          {"sbi.co.in", "onlinesbi.sbi"},
    "hdfc":         {"hdfcbank.com"},
    "icici":        {"icicibank.com"},
    "axis":         {"axisbank.com"},
    "pnb":          {"pnbindia.in"},
    "paytm":        {"paytm.com"},
    "phonepe":      {"phonepe.com"},
    "irctc":        {"irctc.co.in"},
    "uidai":        {"uidai.gov.in"},
    "income-tax":   {"incometax.gov.in"},
    "incometax":    {"incometax.gov.in"},
    "aadhaar":      {"uidai.gov.in"},
    "aadhar":       {"uidai.gov.in"},
    "epfo":         {"epfindia.gov.in"},
    "nps":          {"npci.org.in"},
    "rbi":          {"rbi.org.in"},
}

SUSPICIOUS_TLDS: set[str] = {
    "xyz", "top", "pw", "click", "link", "online", "site",
    "fun", "live", "buzz", "club", "info", "tk", "ml", "ga", "cf", "gq",
}

SUSPICIOUS_KEYWORDS: list[str] = [
    "kyc", "challan", "ebill", "electricity", "blocked", "verify",
    "upi", "update", "aadhar", "aadhaar", "pan", "otp", "reward",
    "prize", "winner", "claim", "urgent", "suspend", "lock",
]

IP_REGEX = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")


# ─────────────────────────────────────────────
# SUB-MODULE 1: WHITELIST CHECK
# ─────────────────────────────────────────────

def _check_whitelist(url: str) -> tuple[bool, str | None]:
    """
    Returns (is_whitelisted, matched_entry).
    Uses tldextract to get the registered domain+suffix, then checks
    if it exactly matches any entry in WHITELIST.
    """
    ext = tldextract.extract(url)
    if not ext.domain or not ext.suffix:
        return False, None

    registered = f"{ext.domain}.{ext.suffix}"  # e.g. "sbi.co.in" or "hdfcbank.com"

    # Direct match
    if registered in WHITELIST:
        return True, WHITELIST[registered]

    # Multi-part suffixes: e.g. onlinesbi.sbi — ext.domain="onlinesbi", ext.suffix="sbi"
    full = registered
    if full in WHITELIST:
        return True, WHITELIST[full]

    return False, None


# ─────────────────────────────────────────────
# SUB-MODULE 2: WHOIS DOMAIN AGE
# ─────────────────────────────────────────────

def _get_whois_data(domain: str) -> dict:
    """
    Returns {"creationDate": str|None, "registrar": str|None, "country": str|None, "domainAge": int|None}
    """
    result = {
        "creationDate": None,
        "registrar": None,
        "country": None,
        "domainAge": None,
    }
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(whois.whois, domain)
            try:
                w = future.result(timeout=8)
            except concurrent.futures.TimeoutError:
                logger.debug("WHOIS timeout for %s", domain)
                return result

        # creation_date can be a list or a single value
        creation = w.creation_date
        if isinstance(creation, list):
            creation = min(creation)  # earliest date

        if creation:
            if isinstance(creation, str):
                creation = dateutil_parser.parse(creation)

            # Normalise to offset-aware
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            delta = now - creation
            result["domainAge"] = max(0, delta.days)
            result["creationDate"] = creation.strftime("%Y-%m-%d")

        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]
        result["registrar"] = str(registrar).strip() if registrar else None

        country = w.country
        if isinstance(country, list):
            country = country[0]
        result["country"] = str(country).strip() if country else None

    except Exception as exc:
        logger.debug("WHOIS lookup failed for %s: %s", domain, exc)

    return result


def _domain_age_score(age_days: int | None) -> int:
    if age_days is None:
        return 5
    if age_days < 7:
        return 40
    if age_days < 30:
        return 25
    if age_days < 90:
        return 10
    return 0


# ─────────────────────────────────────────────
# SUB-MODULE 3: HEURISTIC REGEX ENGINE
# ─────────────────────────────────────────────

def _run_heuristics(url: str) -> tuple[list[str], int]:
    """
    Returns (flags: list[str], raw_score: int).
    No network calls — pure string analysis.
    """
    flags: list[str] = []
    score: int = 0

    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.domain else ""
    url_lower = url.lower()
    parsed = urlparse(url)
    path_lower = (parsed.path + "?" + parsed.query).lower()

    # 1. Typosquatting
    for brand, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        if brand in url_lower:
            if registered_domain not in official_domains:
                flags.append(f"Typosquatting: {brand.upper()} detected on non-official domain")
                score += 25

    # 2. Suspicious TLD
    tld = ext.suffix.lower() if ext.suffix else ""
    # Handle compound TLDs by checking the last component
    tld_last = tld.split(".")[-1]
    if tld_last in SUSPICIOUS_TLDS or tld in SUSPICIOUS_TLDS:
        flags.append(f"Suspicious TLD detected: .{tld_last}")
        score += 15

    # 3. IP address hosting
    if IP_REGEX.match(url):
        flags.append("IP address used instead of domain name")
        score += 30

    # 4. Suspicious keywords in URL path
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path_lower]
    if len(found_keywords) == 1:
        score += 10
    elif len(found_keywords) >= 2:
        score += 20
    for kw in found_keywords:
        flags.append(f"Suspicious keyword in URL: '{kw}'")

    # 5. Excessive subdomains
    subdomain = ext.subdomain or ""
    # count non-empty parts
    subdomain_parts = [p for p in subdomain.split(".") if p]
    if len(subdomain_parts) > 2:
        flags.append(f"Excessive subdomains: {len(subdomain_parts)} levels")
        score += 15

    # 6. URL length
    if len(url) > 100 and len(flags) > 0:
        flags.append(f"Suspicious URL length: {len(url)} characters")
        score += 5

    return flags, score


# ─────────────────────────────────────────────
# SUB-MODULE 4: SCORE NORMALIZATION
# ─────────────────────────────────────────────

def _normalize_score(raw: int, is_whitelisted: bool) -> int:
    if is_whitelisted:
        return 0
    return min(100, max(0, raw))


def _severity_label(score: int) -> str:
    if score <= 20:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"


# ─────────────────────────────────────────────
# MAIN INTERFACE
# ─────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """
    Main entry point for Kavach heuristic pre-screening.

    Args:
        url: The URL to analyze.

    Returns:
        A preliminary_report dict with keys:
          domainAge, heuristicFlags, heuristicScore,
          whoisData, isWhitelisted, whitelistMatch
    """
    url = url.strip()

    # ── Step 1: Whitelist check ──────────────────
    is_whitelisted, whitelist_match = _check_whitelist(url)
    if is_whitelisted:
        logger.info("WHITELISTED: %s → %s", url, whitelist_match)
        return {
            "domainAge": None,
            "heuristicFlags": [],
            "heuristicScore": 0,
            "whoisData": {
                "creationDate": None,
                "registrar": None,
                "country": None,
            },
            "isWhitelisted": True,
            "whitelistMatch": whitelist_match,
        }

    # ── Step 2: Extract registered domain for WHOIS ──
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.domain else ""

    # ── Step 3: WHOIS lookup ─────────────────────
    whois_result = _get_whois_data(registered_domain) if registered_domain else {
        "creationDate": None, "registrar": None, "country": None, "domainAge": None
    }
    domain_age = whois_result.pop("domainAge", None)  # separate from whoisData

    # ── Step 4: Heuristic regex checks ───────────
    flags, heuristic_raw = _run_heuristics(url)

    # ── Step 5: Domain age contributes to score ──
    age_score = _domain_age_score(domain_age)
    if age_score > 0:
        if domain_age is None:
            flags.append("Domain age unknown (slight suspicion)")
        elif domain_age < 7:
            flags.append(f"Very new domain: {domain_age} days old")
        elif domain_age < 30:
            flags.append(f"Recently registered domain: {domain_age} days old")
        elif domain_age < 90:
            flags.append(f"Relatively new domain: {domain_age} days old")

    raw_total = heuristic_raw + age_score
    final_score = _normalize_score(raw_total, is_whitelisted=False)
    severity = _severity_label(final_score)
    logger.info("ANALYZED: %s | score=%d (%s) | flags=%d", url, final_score, severity, len(flags))

    return {
        "domainAge": domain_age,
        "heuristicFlags": flags,
        "heuristicScore": final_score,
        "whoisData": {
            "creationDate": whois_result.get("creationDate"),
            "registrar": whois_result.get("registrar"),
            "country": whois_result.get("country"),
        },
        "isWhitelisted": False,
        "whitelistMatch": None,
    }


# ─────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import json

    TEST_CASES = [
        ("https://www.google.com",                    "LOW risk / safe"),
        ("https://sbi-kyc-update.xyz/verify/upi",     "HIGH/CRITICAL phishing"),
        ("https://onlinesbi.sbi",                     "WHITELISTED"),
    ]

    for url, expected in TEST_CASES:
        print(f"\n{'─'*60}")
        print(f"URL     : {url}")
        print(f"Expected: {expected}")
        t0 = time.time()
        report = analyze_url(url)
        elapsed = time.time() - t0
        print(f"Result  : score={report['heuristicScore']} | "
              f"whitelisted={report['isWhitelisted']} | "
              f"severity={_severity_label(report['heuristicScore'])} | "
              f"time={elapsed:.2f}s")
        print(f"Flags   : {report['heuristicFlags']}")
        print(f"WHOIS   : {report['whoisData']}")
        print(f"Full    :\n{json.dumps(report, indent=2)}")