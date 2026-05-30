import os

# ── MUST be the very first lines, before any other import ────────────────────
os.environ.setdefault(
    "PLAYWRIGHT_BROWSERS_PATH",
    "/opt/render/project/src/.playwright-browsers"
)
# ─────────────────────────────────────────────────────────────────────────────

import asyncio
import sys
import base64
import re
import json
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from playwright.async_api import async_playwright
from google import genai
from google.genai import types
from dotenv import load_dotenv
from urllib.parse import urlparse

# ── Heuristic engine ──────────────────────────────────────────────────────────
try:
    from heuristic_engine import analyze_url as heuristic_analyze
    HEURISTIC_AVAILABLE = True
    print("✓ Heuristic engine loaded successfully")
except ImportError:
    HEURISTIC_AVAILABLE = False
    print("⚠ heuristic_engine.py not found — heuristic scoring disabled")

# ── Key manager ───────────────────────────────────────────────────────────────
from key_manager import key_manager

# ─────────────────────────────────────────────────────────────────────────────

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

load_dotenv()

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ──────────────────────────────────────────────────────────────────────
allowed_origin = os.getenv("ALLOWED_ORIGIN", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[allowed_origin],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API key auth ──────────────────────────────────────────────────────────────
API_KEY = os.getenv("KAVACH_API_KEY", "")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(key: str = Depends(api_key_header)):
    if API_KEY and key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API key.")
    return key

class AnalyzeRequest(BaseModel):
    url: str
    preliminary_report: dict = {}

# ─────────────────────────────────────────────────────────────────────────────
# TRUSTED DOMAIN WHITELIST
# ─────────────────────────────────────────────────────────────────────────────

TRUSTED_DOMAINS = {
    # Shopping
    "amazon.in", "amazon.com", "flipkart.com", "myntra.com", "meesho.com",
    "snapdeal.com", "tatacliq.com", "ajio.com", "nykaa.com",
    # Banks
    "sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "kotakbank.com", "yesbank.in",
    "pnbindia.in", "canarabank.com", "bankofbaroda.in", "unionbankofindia.co.in",
    # Payments / UPI
    "phonepe.com", "paytm.com", "googlepay.com", "bhimupi.org.in",
    # Government
    "irctc.co.in", "uidai.gov.in", "incometax.gov.in", "mca.gov.in",
    "passportindia.gov.in", "epfindia.gov.in", "rbi.org.in", "sebi.gov.in",
    "india.gov.in", "digilocker.gov.in", "cowin.gov.in",
    # Telecom / Utility
    "airtel.in", "jio.com", "bsnl.in", "vodafoneidea.com",
    # Tech / Social
    "google.com", "youtube.com", "instagram.com", "facebook.com",
    "linkedin.com", "twitter.com", "x.com", "github.com",
    "microsoft.com", "apple.com", "netflix.com", "hotstar.com",
    # Misc
    "zomato.com", "swiggy.com", "ola.com", "uber.com", "makemytrip.com",
    "goibibo.com", "bookmyshow.com", "bigbasket.com", "blinkit.com",
}

def is_trusted_domain(url: str) -> bool:
    hostname = urlparse(url).hostname or ""
    hostname = hostname.replace("www.", "")
    return hostname in TRUSTED_DOMAINS

# ─────────────────────────────────────────────────────────────────────────────
# GEMINI SYSTEM PROMPT
# ─────────────────────────────────────────────────────────────────────────────

GEMINI_SYSTEM_PROMPT = """
CRITICAL: YOU MUST RESPOND ONLY IN THE ENGLISH LANGUAGE.
DO NOT USE HINDI. DO NOT USE HINGLISH. DO NOT TRANSLITERATE HINDI INTO ENGLISH LETTERS.
ALL OUTPUT MUST BE PLAIN ENGLISH WORDS ONLY.
You are a Cyber-Forensics Expert specializing in Indian phishing attacks.
Analyze the screenshot and the provided URL carefully.

KNOWN INDIAN PHISHING PATTERNS TO CHECK:
1. Visual Impersonation — Fake SBI, HDFC, ICICI, Axis, PNB, Canara, BOB, Kotak, Yes Bank logos/UI
2. Government portal fakes — Fake IRCTC, UIDAI, Income Tax, EPF, Passport, RBI, SEBI, MCA portals
3. UPI/Payment scams — Fake PhonePe, Paytm, Google Pay, BHIM interfaces asking for UPI PIN
4. KYC scams — "Your account will be blocked", "Complete KYC now", "Aadhaar linking required"
5. Prize/Lottery scams — "You won", "Claim your reward", "Lucky draw winner"
6. Electricity/Utility scams — Fake BESCOM, MSEB, TATA Power, Reliance Energy bill payment pages
7. Job/Offer scams — Fake government job portals, fake scholarship pages
8. Refund scams — Fake income tax refund, IRCTC refund, insurance claim pages

RECENTLY MIGRATED OFFICIAL INDIAN DOMAINS (DO NOT flag these as phishing):
- sbi.bank.in is the NEW official domain for State Bank of India (migrated from sbi.co.in)
- hdfcbank.com, axisbank.com, icicibank.com are legitimate
- .bank.in is a reserved, RBI-regulated TLD — only real Indian banks can register it
- If the domain ends in .bank.in and the branding matches, treat it as LEGITIMATE

DOMAIN MATCHING RULE — MOST IMPORTANT:
- If the page domain exactly matches the brand shown (e.g. amazon.in showing Amazon's website),
  it is NOT impersonation. NEVER flag a brand's own official domain as phishing.
- Minor spelling errors on a verified official domain should NOT trigger is_phishing = true.
  Typos alone on legitimate domains should only slightly raise confidence, never flip the verdict.
- If the domain IS the brand (amazon.in IS Amazon), set is_phishing = false regardless of typos.

RED FLAGS TO LOOK FOR:
- Official brand logo but URL is NOT the official domain
- Hindi/regional language urgency text mixed with English
- Aadhaar, PAN, OTP, UPI PIN, CVV input fields on suspicious domains
- Countdown timers creating artificial urgency
- Poor grammar or spelling in official-looking pages
- Form submissions going to unknown endpoints

1. Visual Impersonation — Analyze the VISUAL CONTENT FIRST before looking at the URL.
   Does the page look like a known brand? Check logos, color schemes, layout, button styles.
   If it visually matches a known brand, flag it regardless of the domain.

2. High-pressure language — "Account Blocked", "KYC Pending", "Verify immediately",
   countdown timers, urgency messages.

3. Fake forms — Input fields asking for Aadhaar, PAN, UPI PIN, OTP, CVV, passwords.
   Flag ANY password or OTP field on a non-official domain.

4. URL mismatch — After analyzing visuals, check if the domain matches the brand.
   A page that LOOKS like Amazon but is NOT on amazon.com or amazon.in is phishing.
   A page that LOOKS like SBI but is NOT on sbi.co.in or onlinesbi.sbi is phishing.
   Github.io, netlify.app, vercel.app hosting official-looking bank/shopping pages = phishing.

IMPORTANT RULES:
- If is_phishing is false, reasoning must clearly state the site appears legitimate and safe.
- Never use the word "impersonates" when is_phishing is false.
- brand_impersonated must be null if is_phishing is false.
- red_flags must be empty array if is_phishing is false.
- For safe sites, reasoning should be reassuring: confirm the domain matches the brand and no suspicious elements were found.
- For phishing sites, be specific about WHICH brand is being impersonated and WHAT data is being harvested.
ONLY GIVE THE VERDICT IN ENGLISH, AND NO OTHER LANGUAGE.

ADDITIONAL RED FLAGS TO LOOK FOR:
- Spelling mistakes anywhere on the page — misspelled navigation items, button labels,
  product names, or UI text (e.g. "Fasion" instead of "Fashion", "Electonics", "Custmer Service")
- Grammar errors in official-looking text
- UI elements that look slightly off from the real brand — wrong font weight,
  misaligned logo, slightly wrong shade of orange/blue
- Navigation items missing compared to real Amazon (e.g. missing "Prime", "Today's Deals")
- Extra or unusual navigation items not present on real Amazon
- Incorrect copyright year in footer
- Missing or fake "Secure" padlock indicators
- Placeholder text left in (e.g. "Lorem ipsum", "[Your text here]")
- Prices in wrong currency or unrealistic discounts
- Any text that reads awkwardly or is clearly machine-translated

SPELLING ERRORS RULE:
- Only list spelling errors in red_flags if is_phishing is TRUE.
- If is_phishing is false, red_flags must be empty — do not list spelling errors for legitimate sites.
- When is_phishing is true, for EVERY spelling mistake found add it as a separate red flag:
  "Spelling error: '[wrong spelling]' should be '[correct spelling]'"
- Be exhaustive — list every single spelling error you can find on the page when phishing is confirmed.

Respond ONLY in this exact JSON format:
{
  "is_phishing": true or false,
  "confidence": 0-100,
  "brand_impersonated": "name of brand or null",
  "red_flags": ["flag1", "flag2"],
  "reasoning": "one line explanation"
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# SANDBOX
# ─────────────────────────────────────────────────────────────────────────────

def detonate_sync(target_url: str):
    from playwright.sync_api import sync_playwright
    import time

    redirect_chain = []
    final_url = target_url
    screenshot_base64 = None
    page_title = ""
    outgoing_links = []
    error = None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--single-process",
                ]
            )
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
                viewport={"width": 390, "height": 844},
                locale="en-IN",
                timezone_id="Asia/Kolkata",
            )
            page = context.new_page()
            page.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")

            def handle_response(response):
                if response.status in [301, 302, 303, 307, 308]:
                    redirect_chain.append(response.url)
            page.on("response", handle_response)

            page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
            time.sleep(3)

            final_url = page.url
            page_title = page.title()
            screenshot_bytes = page.screenshot(full_page=True)
            screenshot_base64 = base64.b64encode(screenshot_bytes).decode("utf-8")
            outgoing_links = page.eval_on_selector_all("a[href]", "elements => elements.map(el => el.href)")
            browser.close()

    except Exception as e:
        error = str(e)
        print(f"DETONATE ERROR: {error}")

    return {
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "page_title": page_title,
        "screenshot_base64": screenshot_base64,
        "outgoing_links": outgoing_links[:20],
        "error": error
    }


async def detonate(target_url: str):
    import concurrent.futures
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        result = await loop.run_in_executor(pool, detonate_sync, target_url)
    return result

# ─────────────────────────────────────────────────────────────────────────────
# GEMINI VISION
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_with_gemini(screenshot_base64: str, final_url: str, _retry: bool = False):
    current_key = await key_manager.get_key()
    if not current_key:
        print("❌ No Gemini keys available")
        return {
            "ai_available": False,
            "is_phishing": None,
            "confidence": None,
            "brand_impersonated": None,
            "red_flags": [],
            "reasoning": "AI analysis is temporarily unavailable due to high demand. Please try again shortly."
        }

    # ── Key identity logging ──────────────────────────────────────────────────
    try:
        key_num = key_manager.keys.index(current_key) + 1
    except (ValueError, AttributeError):
        key_num = "?"
    print(f"🔑 Using Gemini Key #{key_num} (vision)")

    client = genai.Client(api_key=current_key)

    try:
        response = await client.aio.models.generate_content(
            model="gemini-2.5-flash",
            contents=[
                GEMINI_SYSTEM_PROMPT,
                f"The final URL of this page is: {final_url}",
                f"Carefully read EVERY word visible on this page. List ALL spelling mistakes as separate red flags.",
                types.Part.from_bytes(
                    data=base64.b64decode(screenshot_base64),
                    mime_type="image/png"
                )
            ],
            config=types.GenerateContentConfig(
                safety_settings=[
                    types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH",        threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_HARASSMENT",         threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT",  threshold="BLOCK_NONE"),
                ]
            )
        )

        raw = response.text.strip()
        raw = re.sub(r"```json|```", "", raw).strip()
        result = json.loads(raw)

        # Sanitize brand_impersonated
        if result.get("brand_impersonated") in ("null", "none", "None", ""):
            result["brand_impersonated"] = None

        # Only replace reasoning if it contains non-English characters
        reasoning = result.get("reasoning", "")
        non_ascii = sum(1 for c in reasoning if ord(c) > 127)
        if non_ascii > len(reasoning) * 0.1:
            brand = result.get("brand_impersonated")
            red_flags = result.get("red_flags", [])
            if result.get("is_phishing"):
                result["reasoning"] = (
                    f"This page shows signs of phishing."
                    + (f" It appears to impersonate {brand}." if brand else "")
                    + (f" {', '.join(red_flags[:2])} detected." if red_flags else " Suspicious URL structure detected.")
                )
            else:
                result["reasoning"] = "This page appears legitimate. No phishing indicators detected."

        print(f"✅ Gemini Key #{key_num} (vision) succeeded")
        return result

    except Exception as e:
        err = str(e)
        print(f"❌ Gemini Key #{key_num} (vision) failed: {e}")
        # Detect quota/rate-limit errors and rotate to next key
        if any(signal in err.lower() for signal in ["quota", "429", "exhausted", "rate limit", "resource_exhausted"]):
            print(f"   ↳ Quota hit — rotating to next key")
            await key_manager.mark_exhausted(current_key)
            if not _retry:
                return await analyze_with_gemini(screenshot_base64, final_url, _retry=True)

    return {
        "ai_available": False,
        "is_phishing": None,
        "confidence": None,
        "brand_impersonated": None,
        "red_flags": [],
        "reasoning": "AI analysis is temporarily unavailable due to high demand. Please try again shortly."
    }


async def analyze_url_text_with_gemini(url: str, technical_flags: list, heuristic_flags: list, _retry: bool = False) -> dict:
    current_key = await key_manager.get_key()
    if not current_key:
        print("❌ No Gemini keys available (text fallback)")
        return {
            "ai_available": False,
            "is_phishing": None,
            "confidence": None,
            "brand_impersonated": None,
            "red_flags": [],
            "reasoning": "All Gemini API keys exhausted. Cannot analyze at this time."
        }

    # ── Key identity logging ──────────────────────────────────────────────────
    try:
        key_num = key_manager.keys.index(current_key) + 1
    except (ValueError, AttributeError):
        key_num = "?"
    print(f"🔑 Using Gemini Key #{key_num} (text fallback)")

    client = genai.Client(api_key=current_key)

    try:
        flags_text = "\n".join(f"- {f}" for f in technical_flags + heuristic_flags) or "None detected."
        prompt = f"""
YOU MUST RESPOND ONLY IN ENGLISH. NO HINDI. NO OTHER LANGUAGES. ENGLISH ONLY.

You are a Cyber-Forensics Expert analyzing a URL that could not be loaded.

URL: {url}

Automated flags already detected:
{flags_text}

Based on the URL structure, domain name, TLD, and path keywords analyze if this is phishing.

Respond ONLY in this exact JSON format with English text only:
{{
  "is_phishing": true or false,
  "confidence": 0-100,
  "brand_impersonated": null,
  "red_flags": ["flag1", "flag2"],
  "reasoning": "one sentence in English only"
}}
"""
        response = await client.aio.models.generate_content(
            model="gemini-2.5-flash",
            contents=[prompt],
        )
        raw = response.text.strip()
        raw = re.sub(r"```json|```", "", raw).strip()
        result = json.loads(raw)

        if result.get("brand_impersonated") in ("null", "none", "None", ""):
            result["brand_impersonated"] = None

        reasoning = result.get("reasoning", "")
        non_ascii = sum(1 for c in reasoning if ord(c) > 127)
        if non_ascii > len(reasoning) * 0.1:
            brand = result.get("brand_impersonated")
            red_flags = result.get("red_flags", [])
            if result.get("is_phishing"):
                result["reasoning"] = (
                    f"This page shows signs of phishing."
                    + (f" It appears to impersonate {brand}." if brand else "")
                    + (f" {', '.join(red_flags[:2])} detected." if red_flags else " Suspicious URL structure detected.")
                )
            else:
                result["reasoning"] = "This URL does not show clear phishing indicators based on structure and domain analysis."

        print(f"✅ Gemini Key #{key_num} (text fallback) succeeded")
        return result

    except Exception as e:
        err = str(e)
        print(f"❌ Gemini Key #{key_num} (text fallback) failed: {e}")
        # Detect quota/rate-limit errors and rotate to next key
        if any(signal in err.lower() for signal in ["quota", "429", "exhausted", "rate limit", "resource_exhausted"]):
            print(f"   ↳ Quota hit — rotating to next key")
            await key_manager.mark_exhausted(current_key)
            if not _retry:
                return await analyze_url_text_with_gemini(url, technical_flags, heuristic_flags, _retry=True)

    return {
        "ai_available": False,
        "is_phishing": None,
        "confidence": None,
        "brand_impersonated": None,
        "red_flags": [],
        "reasoning": "AI analysis is temporarily unavailable due to high demand. Please try again shortly."
    }

# ─────────────────────────────────────────────────────────────────────────────
# HEURISTIC ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def run_heuristic_engine(final_url: str) -> dict:
    if not HEURISTIC_AVAILABLE:
        return {}
    try:
        report = heuristic_analyze(final_url)
        print(f"HEURISTIC: score={report.get('heuristicScore', 0)} | "
              f"flags={len(report.get('heuristicFlags', []))} | "
              f"whitelisted={report.get('isWhitelisted', False)}")
        return report
    except Exception as e:
        print(f"HEURISTIC ENGINE ERROR: {e}")
        return {}

# ─────────────────────────────────────────────────────────────────────────────
# SCORING
# ─────────────────────────────────────────────────────────────────────────────

def get_technical_flags(final_url: str) -> list:
    flags = []

    parsed = urlparse(final_url)
    hostname = parsed.hostname or ""
    subdomain = hostname.split('.')[0] if hostname.count('.') >= 2 else ""

    indian_brands = ["sbi", "hdfc", "icici", "irctc", "amazon", "flipkart",
                     "paytm", "phonepe", "gpay", "uidai", "incometax", "pnb",
                     "axis", "kotak", "yesbank", "canara", "bob", "boi"]

    for brand in indian_brands:
        if brand in subdomain.lower() or (brand in hostname.lower() and brand not in hostname.split('.')[-2]):
            flags.append(f"Brand name '{brand}' used in subdomain — classic phishing pattern")
            break

    abuse_platforms = ["github.io", "netlify.app", "vercel.app", "pages.dev",
                       "web.app", "firebaseapp.com", "glitch.me", "repl.co"]
    for platform in abuse_platforms:
        if hostname.endswith(platform):
            flags.append(f"Hosted on {platform} — free hosting platform commonly abused for phishing clones")
            break

    return flags


def calculate_risk_score(gemini_result: dict, preliminary_report: dict, technical_flags: list) -> float:
    is_phishing = gemini_result.get("is_phishing", False)

    if not is_phishing:
        return 5.0

    # ── Pillar 1: Gemini (50%) ───────────────────
    raw_confidence = gemini_result.get("confidence", 0)
    boosted_confidence = min(100, raw_confidence * 1.5)
    gemini_score = boosted_confidence * 0.5

    # ── Pillar 2: Domain age (25%) ───────────────
    domain_age_score = 0
    domain_age = preliminary_report.get("domainAge", None)
    if domain_age is not None:
        if domain_age < 7:
            domain_age_score = 100
        elif domain_age < 30:
            domain_age_score = 80
        elif domain_age < 90:
            domain_age_score = 50
        elif domain_age < 365:
            domain_age_score = 20
    domain_age_weighted = domain_age_score * 0.25

    # ── Pillar 3: Technical + Heuristic flags (25%) ──────────
    heuristic_flags = preliminary_report.get("heuristicFlags", [])
    all_flags = technical_flags + heuristic_flags
    tech_score = min(len(all_flags) * 20, 100) * 0.25

    # ── Heuristic score bonus ─────────────────────
    heuristic_raw = preliminary_report.get("heuristicScore", 0)
    heuristic_bonus = (heuristic_raw / 100) * 25

    total = gemini_score + domain_age_weighted + tech_score + heuristic_bonus
    return round(min(total, 100), 2)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────

WARNING_TITLES = [
    "deceptive site", "dangerous", "stop!", "warning",
    "phishing", "malware", "this site", "blocked",
    "disabled", "threat", "reported attack"
]

@app.post("/analyze")
@limiter.limit("10/minute")
async def analyze(request: Request, body: AnalyzeRequest, _: str = Depends(verify_api_key)):
    if not body.url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL. Must start with http or https.")

    # ── Step 1: Detonate in sandbox ──────────────────────────────────────────
    sandbox_data = await detonate(body.url)

    if sandbox_data["error"] and not sandbox_data["screenshot_base64"]:
        preliminary_report = run_heuristic_engine(body.url)
        technical_flags = get_technical_flags(body.url)
        heuristic_flags = preliminary_report.get("heuristicFlags", [])

        gemini_result = await analyze_url_text_with_gemini(body.url, technical_flags, heuristic_flags)

        # ── AI unavailable guard (text-only path) ────────────────────────────
        if gemini_result.get("ai_available") is False:
            return {
                "finalUrl": body.url,
                "pageTitle": "",
                "redirectChain": [],
                "screenshotBase64": None,
                "forensicData": {
                    "geminiAnalysis": gemini_result,
                    "technicalFlags": technical_flags,
                    "heuristicAnalysis": {
                        "score": preliminary_report.get("heuristicScore", 0),
                        "flags": heuristic_flags,
                        "domainAge": preliminary_report.get("domainAge", None),
                        "whoisData": preliminary_report.get("whoisData", {}),
                        "isWhitelisted": preliminary_report.get("isWhitelisted", False),
                        "whitelistMatch": preliminary_report.get("whitelistMatch", None),
                    },
                    "outgoingLinks": [],
                },
                "redFlags": [],
                "totalRiskScore": None,
                "verdict": "AI_UNAVAILABLE"
            }

        total_risk_score = calculate_risk_score(gemini_result, preliminary_report, technical_flags)
        all_red_flags = list(set(
            gemini_result.get("red_flags", []) + technical_flags + heuristic_flags
        ))

        return {
            "finalUrl": body.url,
            "pageTitle": "",
            "redirectChain": [],
            "screenshotBase64": None,
            "forensicData": {
                "geminiAnalysis": gemini_result,
                "technicalFlags": technical_flags,
                "heuristicAnalysis": {
                    "score": preliminary_report.get("heuristicScore", 0),
                    "flags": heuristic_flags,
                    "domainAge": preliminary_report.get("domainAge", None),
                    "whoisData": preliminary_report.get("whoisData", {}),
                    "isWhitelisted": preliminary_report.get("isWhitelisted", False),
                    "whitelistMatch": preliminary_report.get("whitelistMatch", None),
                },
                "outgoingLinks": [],
            },
            "redFlags": all_red_flags,
            "totalRiskScore": total_risk_score,
            "verdict": (
                "DANGEROUS"  if total_risk_score >= 30 else
                "SUSPICIOUS" if total_risk_score >= 15 else
                "LIKELY SAFE"
            )
        }

    final_url = sandbox_data["final_url"]

    # ── Step 2: Run heuristics on FINAL URL ──────────────────────────────────
    preliminary_report = run_heuristic_engine(final_url)

    if body.preliminary_report:
        preliminary_report = {**preliminary_report, **body.preliminary_report}

    # ── Step 3: Gemini Vision analysis ───────────────────────────────────────
    gemini_result = {}
    if sandbox_data["screenshot_base64"]:
        if is_trusted_domain(final_url):
            print(f"✓ TRUSTED DOMAIN: {final_url} — skipping Gemini")
            gemini_result = {
                "is_phishing": False,
                "confidence": 99,
                "brand_impersonated": None,
                "red_flags": [],
                "reasoning": "Verified official domain. No phishing indicators detected."
            }
        else:
            gemini_result = await analyze_with_gemini(sandbox_data["screenshot_base64"], final_url)

    # ── Step 4: Technical flags ───────────────────────────────────────────────
    technical_flags = get_technical_flags(final_url)

    # ── Step 4.5: Page title warning detection ────────────────────────────────
    title_lower = sandbox_data["page_title"].lower()
    if any(w in title_lower for w in WARNING_TITLES):
        technical_flags.append("Page title contains security warning — link may have been flagged by another service")

    # ── AI unavailable guard (screenshot path) ────────────────────────────────
    if gemini_result.get("ai_available") is False:
        return {
            "finalUrl": final_url,
            "pageTitle": sandbox_data["page_title"],
            "redirectChain": sandbox_data["redirect_chain"],
            "screenshotBase64": sandbox_data["screenshot_base64"],
            "forensicData": {
                "geminiAnalysis": gemini_result,
                "technicalFlags": technical_flags,
                "heuristicAnalysis": {
                    "score": preliminary_report.get("heuristicScore", 0),
                    "flags": preliminary_report.get("heuristicFlags", []),
                    "domainAge": preliminary_report.get("domainAge", None),
                    "whoisData": preliminary_report.get("whoisData", {}),
                    "isWhitelisted": preliminary_report.get("isWhitelisted", False),
                    "whitelistMatch": preliminary_report.get("whitelistMatch", None),
                },
                "outgoingLinks": sandbox_data["outgoing_links"],
            },
            "redFlags": [],
            "totalRiskScore": None,
            "verdict": "AI_UNAVAILABLE"
        }

    # ── Step 5: Final risk score ──────────────────────────────────────────────
    total_risk_score = calculate_risk_score(gemini_result, preliminary_report, technical_flags)

    # Override verdict if page title is a warning
    title_lower = sandbox_data.get("page_title", "").lower()
    if any(w in title_lower for w in WARNING_TITLES):
        if total_risk_score < 40:
            total_risk_score = 45.0

    # ── Step 6: Merge red flags ───────────────────────────────────────────────
    heuristic_flags = preliminary_report.get("heuristicFlags", [])
    is_phishing = gemini_result.get("is_phishing", False)

    all_red_flags = list(set(gemini_result.get("red_flags", []) + technical_flags))
    if is_phishing:
        all_red_flags = list(set(all_red_flags + heuristic_flags))

    # ── Step 7: Build response ────────────────────────────────────────────────
    return {
        "finalUrl": final_url,
        "pageTitle": sandbox_data["page_title"],
        "redirectChain": sandbox_data["redirect_chain"],
        "screenshotBase64": sandbox_data["screenshot_base64"],
        "forensicData": {
            "geminiAnalysis": gemini_result,
            "technicalFlags": technical_flags,
            "heuristicAnalysis": {
                "score": preliminary_report.get("heuristicScore", 0),
                "flags": heuristic_flags,
                "domainAge": preliminary_report.get("domainAge", None),
                "whoisData": preliminary_report.get("whoisData", {}),
                "isWhitelisted": preliminary_report.get("isWhitelisted", False),
                "whitelistMatch": preliminary_report.get("whitelistMatch", None),
            },
            "outgoingLinks": sandbox_data["outgoing_links"],
        },
        "redFlags": all_red_flags,
        "totalRiskScore": total_risk_score,
        "verdict": (
            "DANGEROUS"  if (total_risk_score >= 70 or
                             (total_risk_score >= 55 and gemini_result.get("brand_impersonated"))) else
            "SUSPICIOUS" if total_risk_score >= 40 else
            "LIKELY SAFE"
        )
    }


@app.get("/health")
def health():
    return {
        "status": "PhishSense backend is running",
        "heuristicEngine": HEURISTIC_AVAILABLE
    }


@app.get("/keys/status")
async def keys_status(_: str = Depends(verify_api_key)):
    return key_manager.status


@app.post("/keys/reset")
async def keys_reset(_: str = Depends(verify_api_key)):
    await key_manager.reset()
    return {"message": "All API keys have been reset.", "status": key_manager.status}