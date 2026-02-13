"""
domain_checks.py
Analyzes domain alignment and spoofing indicators
Pure rule-based checks
"""

# Common suspicious TLDs (can expand later)
SUSPICIOUS_TLDS = [
    ".ru", ".tk", ".xyz", ".top", ".gq", ".ml", ".cf"
]


# --------------------------------------------------
# Check suspicious TLD
# --------------------------------------------------
def has_suspicious_tld(domain):

    if not domain:
        return False

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True

    return False


# --------------------------------------------------
# Detect basic lookalike patterns
# --------------------------------------------------
def looks_like_spoofed(domain):

    if not domain:
        return False

    # Common phishing tricks
    suspicious_patterns = [
        "micros0ft",
        "paypa1",
        "g00gle",
        "arnazon",
        "faceb00k"
    ]

    for pattern in suspicious_patterns:
        if pattern in domain:
            return True

    return False


# --------------------------------------------------
# Main domain analyzer
# --------------------------------------------------
def run_domain_checks(metadata):

    from_domain = metadata.get("from_domain")
    reply_to_domain = metadata.get("reply_to_domain")
    return_path_domain = metadata.get("return_path_domain")
    message_id_domain = metadata.get("message_id_domain")

    results = {
        "reply_to_mismatch": metadata.get("reply_to_mismatch"),
        "return_path_mismatch": metadata.get("return_path_mismatch"),
        "message_id_mismatch": metadata.get("message_id_mismatch"),
        "suspicious_tld": has_suspicious_tld(from_domain),
        "spoofed_domain_pattern": looks_like_spoofed(from_domain)
    }

    results["domain_suspicious"] = (
        results["reply_to_mismatch"]
        or results["return_path_mismatch"]
        or results["message_id_mismatch"]
        or results["suspicious_tld"]
        or results["spoofed_domain_pattern"]
    )

    return results
