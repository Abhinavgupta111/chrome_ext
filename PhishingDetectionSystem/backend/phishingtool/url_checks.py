"""
url_checks.py
Analyzes extracted URLs for phishing indicators
Rule-based detection only
"""

import re

SUSPICIOUS_TLDS = [".ru", ".tk", ".xyz", ".top", ".gq", ".ml", ".cf"]


# --------------------------------------------------
# Detect IP-based URL
# --------------------------------------------------
def is_ip_url(domain):

    if not domain:
        return False

    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))


# --------------------------------------------------
# Detect suspicious TLD
# --------------------------------------------------
def has_suspicious_tld(domain):

    if not domain:
        return False

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True

    return False


# --------------------------------------------------
# Detect long URLs
# --------------------------------------------------
def is_long_url(url):
    return len(url) > 75


# --------------------------------------------------
# Detect excessive subdomains
# --------------------------------------------------
def too_many_subdomains(domain):

    if not domain:
        return False

    return domain.count(".") > 3


# --------------------------------------------------
# Detect HTTP instead of HTTPS
# --------------------------------------------------
def is_insecure_scheme(scheme):

    if not scheme:
        return False

    return scheme.lower() == "http"


# --------------------------------------------------
# Main URL Analyzer
# --------------------------------------------------
def run_url_checks(urls):

    results = {
        "total_urls": len(urls),
        "ip_based_url": False,
        "suspicious_tld_url": False,
        "long_url_detected": False,
        "too_many_subdomains": False,
        "insecure_http": False
    }

    for url in urls:

        domain = url.get("domain")
        full_url = url.get("full_url")
        scheme = url.get("scheme")

        if is_ip_url(domain):
            results["ip_based_url"] = True

        if has_suspicious_tld(domain):
            results["suspicious_tld_url"] = True

        if is_long_url(full_url):
            results["long_url_detected"] = True

        if too_many_subdomains(domain):
            results["too_many_subdomains"] = True

        if is_insecure_scheme(scheme):
            results["insecure_http"] = True

    # Overall URL risk flag
    results["url_suspicious"] = any([
        results["ip_based_url"],
        results["suspicious_tld_url"],
        results["long_url_detected"],
        results["too_many_subdomains"],
        results["insecure_http"]
    ])

    return results
