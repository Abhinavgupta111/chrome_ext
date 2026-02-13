from __future__ import annotations

import re
import socket
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from urllib.parse import urlparse
from difflib import SequenceMatcher

import dns.resolver
import dns.exception

from analyzer import analyze_email


# =====================================
# CONFIGURATION
# =====================================

TRUSTED_DOMAINS = [
    "paypal.com",
    "microsoft.com",
    "amazon.com",
    "google.com",
]

RISKY_TLDS = [".xyz", ".top", ".click", ".ru", ".zip"]
SIMILARITY_THRESHOLD = 0.8

resolver = dns.resolver.Resolver()
resolver.timeout = 2.0  # Reduced timeout for faster failure
resolver.lifetime = 2.0
socket.setdefaulttimeout(2.0)

_dns_cache = {}
_cache_lock = threading.Lock()

# Max workers for parallel DNS queries
MAX_WORKERS = 5


# =====================================
# DATA STRUCTURE
# =====================================

@dataclass
class URLSecurityReport:
    url: str
    domain: str
    score: int
    verdict: str
    reasons: List[str]


# =====================================
# URL EXTRACTION
# =====================================

def extract_urls(text: str) -> List[str]:
    """Extract unique URLs from text"""
    pattern = re.compile(r"""(?ix)
        (https?://[^\s<>()"']+)
        |
        (www\.[^\s<>()"']+)
    """)
    matches = pattern.findall(text or "")
    urls = []
    seen = set()

    for http_url, www_url in matches:
        url = http_url or f"http://{www_url}"
        if url not in seen:
            urls.append(url)
            seen.add(url)

    return urls


# =====================================
# DOMAIN UTILITIES
# =====================================

def get_domain(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def effective_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


# =====================================
# LOOKALIKE DETECTION (FAST PATH)
# =====================================

def detect_lookalike(domain: str) -> Optional[str]:
    """Detect lookalike domains - uses fast string matching"""
    eff = effective_domain(domain)

    # Quick exact match check
    for trusted in TRUSTED_DOMAINS:
        if eff == trusted or eff.endswith("." + trusted):
            return None

    # Only check similarity if domain looks similar
    # Skip expensive similarity check for obviously different domains
    if len(eff) < 3 or len(eff) > 20:
        return None

    best_ratio = 0.0
    best_match = None

    for trusted in TRUSTED_DOMAINS:
        # Skip if lengths are too different
        if abs(len(eff) - len(trusted)) > 3:
            continue
        
        ratio = SequenceMatcher(None, eff, trusted).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_match = trusted

    if best_match and best_ratio >= SIMILARITY_THRESHOLD:
        return f"Domain looks similar to trusted domain '{best_match}'"

    return None


# =====================================
# CACHED DNS CHECKS (THREAD-SAFE)
# =====================================

def _get_cache(key: str) -> Optional[bool]:
    with _cache_lock:
        return _dns_cache.get(key)


def _set_cache(key: str, value: bool):
    with _cache_lock:
        _dns_cache[key] = value


def has_spf(domain: str) -> bool:
    key = f"spf_{domain}"
    cached = _get_cache(key)
    if cached is not None:
        return cached

    try:
        answers = resolver.resolve(domain, "TXT")
        for r in answers:
            if "v=spf1" in r.to_text().lower():
                _set_cache(key, True)
                return True
    except Exception:
        pass

    _set_cache(key, False)
    return False


def has_dmarc(domain: str) -> bool:
    key = f"dmarc_{domain}"
    cached = _get_cache(key)
    if cached is not None:
        return cached

    try:
        answers = resolver.resolve("_dmarc." + domain, "TXT")
        for r in answers:
            if "v=dmarc1" in r.to_text().lower():
                _set_cache(key, True)
                return True
    except Exception:
        pass

    _set_cache(key, False)
    return False


def has_dkim(domain: str) -> bool:
    key = f"dkim_{domain}"
    cached = _get_cache(key)
    if cached is not None:
        return cached

    # Only check 3 most common selectors (reduced from 5)
    selectors = ["default", "selector1", "selector2"]

    for selector in selectors:
        try:
            answers = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            for r in answers:
                if "v=dkim1" in r.to_text().lower():
                    _set_cache(key, True)
                    return True
        except Exception:
            continue

    _set_cache(key, False)
    return False


def domain_resolves(domain: str) -> bool:
    """Quick DNS resolution check"""
    key = f"ip_{domain}"
    cached = _get_cache(key)
    if cached is not None:
        return cached

    try:
        socket.gethostbyname(domain)
        _set_cache(key, True)
        return True
    except Exception:
        _set_cache(key, False)
        return False


# =====================================
# SUSPICIOUS DOMAIN HEURISTICS (FAST)
# =====================================

def suspicious_domain_pattern(domain: str) -> bool:
    """Quick heuristic checks - no DNS"""
    if len(domain) > 30:
        return True
    if any(domain.endswith(tld) for tld in RISKY_TLDS):
        return True
    # Only count consecutive digits
    max_consecutive_digits = 0
    consecutive = 0
    for c in domain:
        if c.isdigit():
            consecutive += 1
            max_consecutive_digits = max(max_consecutive_digits, consecutive)
        else:
            consecutive = 0
    
    if max_consecutive_digits >= 4:
        return True
    
    return False


# =====================================
# PARALLEL DNS BATCH PROCESSOR
# =====================================

def _check_dns_records(domain: str) -> tuple:
    """Check all DNS records for a domain in parallel"""
    try:
        spf = has_spf(domain)
        dmarc = has_dmarc(domain)
        dkim = has_dkim(domain)
        resolves = domain_resolves(domain)
        return (spf, dmarc, dkim, resolves)
    except Exception:
        return (False, False, False, False)


# =====================================
# UNIFIED ANALYSIS ENGINE (OPTIMIZED)
# =====================================

def analyze_url(url: str) -> URLSecurityReport:
    """Analyze single URL with optimized path"""
    domain = get_domain(url)
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    score = 0
    reasons = []

    # --- FAST CHECKS FIRST (no DNS) ---
    
    # Scheme check
    if scheme == "http":
        score += 1
        reasons.append("Uses HTTP instead of HTTPS")

    # IP address check
    if is_ip_address(domain):
        score += 2
        reasons.append("Uses IP address instead of domain")

    # Lookalike check (fast string matching)
    lookalike = detect_lookalike(domain)
    if lookalike:
        score += 2
        reasons.append(lookalike)

    # Suspicious pattern check (no network calls)
    if suspicious_domain_pattern(domain):
        score += 2
        reasons.append("Suspicious domain pattern")

    # --- SKIP DNS CHECKS IF ALREADY HIGH SCORE ---
    # If score is already 6+, domain is likely phishing
    if score >= 6:
        verdict = "Phishing"
    else:
        # --- LAZY DNS CHECKS (only if needed) ---
        spf = has_spf(domain)
        dmarc = has_dmarc(domain)
        dkim = has_dkim(domain)
        resolves = domain_resolves(domain)

        if not spf:
            score += 1
            reasons.append("No SPF record")

        if not dmarc:
            score += 2
            reasons.append("No DMARC record")

        if not dkim:
            score += 1
            reasons.append("No DKIM record")

        if not resolves:
            score += 1
            reasons.append("Domain does not resolve")

        # --- Verdict ---
        if score <= 2:
            verdict = "Safe"
        elif score <= 5:
            verdict = "Suspicious"
        else:
            verdict = "Phishing"

    return URLSecurityReport(url, domain, score, verdict, reasons)


def analyze_urls_parallel(urls: List[str]) -> List[URLSecurityReport]:
    """Analyze multiple URLs in parallel"""
    if len(urls) <= 1:
        return [analyze_url(url) for url in urls]
    
    reports = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(analyze_url, url): url for url in urls}
        for future in as_completed(futures):
            try:
                reports.append(future.result())
            except Exception as e:
                url = futures[future]
                # Fallback: create safe report on error
                reports.append(URLSecurityReport(url, get_domain(url), 1, "Suspicious", [str(e)]))
    
    return reports


# =====================================
# EMAIL PIPELINE ENTRY
# =====================================

def analyze_email_security(email_file: str) -> Dict[str, object]:
    result = analyze_email(email_file)

    body = result["body"]
    urls = extract_urls(body)

    # Use parallel analysis for multiple URLs
    reports = analyze_urls_parallel(urls)

    return {
        "total_urls": len(reports),
        "reports": [asdict(r) for r in reports],
    }


# =====================================
# RUN
# =====================================

if __name__ == "__main__":
    import time
    
    email_file = "email2.eml"

    print("Starting URL security analysis...")
    start = time.time()
    
    final_report = analyze_email_security(email_file)
    
    elapsed = time.time() - start
    
    print(f"\n=== FINAL SECURITY REPORT ===")
    print(f"Total URLs: {final_report['total_urls']}")
    print(f"Time taken: {elapsed:.2f}s")
    print(f"\nReports:")
    for report in final_report['reports']:
        print(f"  - {report['domain']}: {report['verdict']} (score: {report['score']})")

