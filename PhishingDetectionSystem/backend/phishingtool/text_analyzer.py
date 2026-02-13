"""
text_analyzer.py
Analyzer for raw text input (e.g., from Chrome Extension) using the existing ML and heuristic models.
"""

import sys
import os
import re
from urllib.parse import urlparse

# Add parent directory to path to allow importing if needed (though running from main.py handles this)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import from local modules
try:
    from .huggingface_analyzer import analyze_email_body_with_transformers
except ImportError:
    # Fallback if running as script or different structure
    from phishingtool.huggingface_analyzer import analyze_email_body_with_transformers

from .url_checks import run_url_checks
from .scoring import calculate_risk_score

def extract_urls_from_text(text):
    if not text:
        return []

    url_pattern = r'(https?://[^\s<>"\'()]+|www\.[^\s<>"\'()]+)'
    found_urls = re.findall(url_pattern, text)

    urls = []
    for url in found_urls:
        if not url.startswith("http"):
            url = "http://" + url

        parsed = urlparse(url)

        urls.append({
            "full_url": url,
            "domain": parsed.netloc,
            "path": parsed.path,
            "scheme": parsed.scheme
        })

    return urls

def analyze_text_payload(data):
    """
    Analyze text payload from Chrome Extension.
    
    Expected data format:
    {
        "subject": "Email Subject",
        "body": "Email Body Content",
        "sender": "Sender Name <sender@example.com>"
    }
    """
    subject = data.get("subject", "")
    body = data.get("body", "")
    sender = data.get("sender", "")
    
    # 1. ML Analysis
    ml_result = analyze_email_body_with_transformers(body)
    
    # 2. URL Analysis
    urls = extract_urls_from_text(body)
    url_results = run_url_checks(urls)
    
    # 3. Construct results compatible with scoring engine
    # We will simulate other checks as "safe" or "unknown" since we don't have full headers
    all_results = {
        "authentication": {}, # No auth headers
        "domain": {},         # No domain checks (unless we parse sender)
        "url": url_results,
        "attachment": {},     # No attachments
        "infrastructure": {}, # No infra IPs
        "header": {},         # No headers
        "timing": {},         # No timing info
        "mime": {}            # No MIME info
    }
    
    # 4. Calculate Risk Score
    # We need to adapt the scoring because we are missing many signals.
    # We will rely heavily on ML and URL checks.
    
    risk_score_base = calculate_risk_score(all_results)
    
    # Boost score with ML result
    ml_score_val = ml_result.get("model_score", 0) # 0-10
    
    # Scale ML score to 0-100 impact
    # If ML is very confident it is phishing (score > 8), we should guarantee high risk.
    
    final_score = risk_score_base["score"]
    
    triggers = risk_score_base["triggers"]
    
    if ml_score_val > 5:
        final_score += (ml_score_val * 5) # Max 50 points from ML
        triggers.append(f"ML Detected Phishing (Score: {ml_score_val})")
    
    final_score = min(final_score, 100)
    
    # Determine Verdict
    if final_score >= 70:
        verdict = "PHISHING"
        risk_level = "HIGH"
    elif final_score >= 40:
        verdict = "SUSPICIOUS"
        risk_level = "MEDIUM"
    else:
        verdict = "SAFE"
        risk_level = "LOW"

    return {
        "status": "success",
        "data": {
            "score": final_score,
            "verdict": verdict,
            "risk_level": risk_level,
            "ml_analysis": ml_result,
            "url_analysis": url_results,
            "triggers": triggers
        }
    }
