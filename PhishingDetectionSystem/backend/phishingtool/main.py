"""
main.py
Central controller of phishing detection system
"""

import sys

from .parser import analyze_email
from .auth_checks import run_auth_checks
from .infrastructure_checks import run_infrastructure_checks
from .mime_checks import run_mime_checks
from .domain_checks import run_domain_checks
from .url_checks import run_url_checks
from .attachment_checks import run_attachment_checks
from .header_checks import run_header_checks
from .timing_checks import run_timing_checks
from .scoring import calculate_risk_score


def main(email_path):

    # 1️⃣ Parse email
    parsed_data = analyze_email(email_path)

    metadata = parsed_data["metadata"]
    urls = parsed_data["urls"]
    attachments = parsed_data["attachments"]
    raw_msg = parsed_data["raw_msg"]

    # 2️⃣ Run All Modules
    auth_results = run_auth_checks(metadata.get("authentication"))
    infra_results = run_infrastructure_checks(metadata)
    mime_results = run_mime_checks(raw_msg)
    domain_results = run_domain_checks(metadata)
    url_results = run_url_checks(urls)
    attachment_results = run_attachment_checks(attachments)
    header_results = run_header_checks(metadata)
    timing_results = run_timing_checks(metadata)

    # 3️⃣ Combine All Results
    all_results = {
        "authentication": auth_results,
        "domain": domain_results,
        "url": url_results,
        "attachment": attachment_results,
        "infrastructure": infra_results,
        "header": header_results,
        "timing": timing_results,
        "mime": mime_results
    }

    # 4️⃣ Calculate Final Score
    final_score = calculate_risk_score(all_results)

    # Risk level mapping
    score = final_score["score"]
    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # 5️⃣ Console Output (CLI Mode)
    print("\n========== PHISHING ANALYSIS ==========\n")
    print("FROM:", metadata.get("from"))
    print("ORIGIN IP:", metadata.get("originating_ip"))

    print("\n--- Authentication ---")
    print("SPF:", metadata.get("authentication", {}).get("spf"))
    print("DKIM:", metadata.get("authentication", {}).get("dkim"))
    print("DMARC:", metadata.get("authentication", {}).get("dmarc"))

    print("\n--- FINAL VERDICT ---")
    print("Risk Score:", score)
    print("Verdict:", final_score["verdict"])
    print("Triggers:", final_score["triggers"])

    # 6️⃣ Structured JSON Output (API + Frontend)
    return {
        "status": "success",
        "data": {
            "score": score,
            "verdict": final_score["verdict"],
            "risk_level": risk_level,
            "category": "Phishing" if score > 60 else "Suspicious" if score > 30 else "Legitimate",

            "headers": {
                "from": metadata.get("from"),
                "subject": metadata.get("subject"),
                "to": metadata.get("to")
            },

            "authentication": {
                "spf": metadata.get("authentication", {}).get("spf"),
                "dkim": metadata.get("authentication", {}).get("dkim"),
                "dmarc": metadata.get("authentication", {}).get("dmarc")
            },

            "origin": {
                "ip": metadata.get("originating_ip")
            },

            "analysis": {
                "domain_suspicious": domain_results.get("domain_suspicious"),
                "url_suspicious": url_results.get("url_suspicious"),
                "attachment_suspicious": attachment_results.get("attachment_suspicious"),
                "header_suspicious": header_results.get("header_suspicious"),
                "timing_suspicious": timing_results.get("timing_suspicious"),
                "infrastructure_suspicious": infra_results.get("infrastructure_suspicious")
            },

            "triggers": final_score["triggers"]
        }
    }


# CLI execution support
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python main.py <email_file>")
        sys.exit(1)

    email_file = sys.argv[1]
    main(email_file)
