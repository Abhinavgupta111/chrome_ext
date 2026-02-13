"""
scoring.py
Final phishing risk scoring engine
Combines results from all analysis modules
"""


# --------------------------------------------------
# Weight configuration
# --------------------------------------------------
WEIGHTS = {

    # Authentication
    "spf_fail": 15,
    "dkim_fail": 15,
    "dmarc_fail": 20,

    # Domain
    "domain_suspicious": 15,

    # URLs
    "url_suspicious": 15,

    # Attachments
    "attachment_suspicious": 20,

    # Infrastructure
    "infrastructure_suspicious": 10,

    # Headers
    "header_suspicious": 10,

    # Timing
    "timing_suspicious": 10,

    # MIME
    "suspicious_encoding": 5
}


# --------------------------------------------------
# Score calculator
# --------------------------------------------------
def calculate_risk_score(all_results):

    score = 0
    triggered = []

    # AUTH
    auth = all_results.get("authentication", {})
    if auth.get("spf_fail"):
        score += WEIGHTS["spf_fail"]
        triggered.append("SPF fail")

    if auth.get("dkim_fail"):
        score += WEIGHTS["dkim_fail"]
        triggered.append("DKIM fail")

    if auth.get("dmarc_fail"):
        score += WEIGHTS["dmarc_fail"]
        triggered.append("DMARC fail")

    # DOMAIN
    domain = all_results.get("domain", {})
    if domain.get("domain_suspicious"):
        score += WEIGHTS["domain_suspicious"]
        triggered.append("Domain anomaly")

    # URL
    url = all_results.get("url", {})
    if url.get("url_suspicious"):
        score += WEIGHTS["url_suspicious"]
        triggered.append("Suspicious URL")

    # ATTACHMENT
    att = all_results.get("attachment", {})
    if att.get("attachment_suspicious"):
        score += WEIGHTS["attachment_suspicious"]
        triggered.append("Malicious attachment")

    # INFRA
    infra = all_results.get("infrastructure", {})
    if infra.get("infrastructure_suspicious"):
        score += WEIGHTS["infrastructure_suspicious"]
        triggered.append("Infrastructure anomaly")

    # HEADER
    header = all_results.get("header", {})
    if header.get("header_suspicious"):
        score += WEIGHTS["header_suspicious"]
        triggered.append("Header anomaly")

    # TIMING
    timing = all_results.get("timing", {})
    if timing.get("timing_suspicious"):
        score += WEIGHTS["timing_suspicious"]
        triggered.append("Timing anomaly")

    # MIME
    mime = all_results.get("mime", {})
    if mime.get("suspicious_encoding"):
        score += WEIGHTS["suspicious_encoding"]
        triggered.append("Suspicious encoding")

    # Cap score
    score = min(score, 100)

    # Verdict logic
    if score >= 70:
        verdict = "PHISHING"
    elif score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "score": score,
        "verdict": verdict,
        "triggers": triggered
    }
