"""
auth_checks.py
Handles SPF, DKIM, DMARC, ARC authentication validation
Pure rule-based logic (no AI)
"""

import re


# --------------------------------------------------
# Extract authentication results from header string
# --------------------------------------------------
def parse_authentication_results(auth_header: str) -> dict:
    """
    Parses Authentication-Results header.
    Returns dictionary with SPF, DKIM, DMARC, ARC results.
    """

    results = {
        "spf_result": None,
        "dkim_result": None,
        "dmarc_result": None,
        "arc_result": None,
        "dkim_domain": None
    }

    if not auth_header:
        return results

    # SPF
    spf_match = re.search(r"spf=(\w+)", auth_header, re.IGNORECASE)
    if spf_match:
        results["spf_result"] = spf_match.group(1).lower()

    # DKIM
    dkim_match = re.search(r"dkim=(\w+)", auth_header, re.IGNORECASE)
    if dkim_match:
        results["dkim_result"] = dkim_match.group(1).lower()

    # DMARC
    dmarc_match = re.search(r"dmarc=(\w+)", auth_header, re.IGNORECASE)
    if dmarc_match:
        results["dmarc_result"] = dmarc_match.group(1).lower()

    # ARC
    arc_match = re.search(r"arc=(\w+)", auth_header, re.IGNORECASE)
    if arc_match:
        results["arc_result"] = arc_match.group(1).lower()

    # DKIM Signing Domain (header.d=example.com)
    dkim_domain_match = re.search(
        r"header\.d=([^\s;]+)", auth_header, re.IGNORECASE)
    if dkim_domain_match:
        results["dkim_domain"] = dkim_domain_match.group(1).lower()

    return results


# --------------------------------------------------
# Evaluate authentication risk flags
# --------------------------------------------------
def evaluate_authentication(auth_data: dict) -> dict:
    """
    Converts authentication results into risk flags.
    """

    evaluation = {
        "spf_fail": False,
        "dkim_fail": False,
        "dmarc_fail": False,
        "auth_suspicious": False
    }

    if auth_data["spf_result"] == "fail":
        evaluation["spf_fail"] = True

    if auth_data["dkim_result"] == "fail":
        evaluation["dkim_fail"] = True

    if auth_data["dmarc_result"] == "fail":
        evaluation["dmarc_fail"] = True

    # If any major auth fails → suspicious
    if (
        evaluation["spf_fail"] or
        evaluation["dkim_fail"] or
        evaluation["dmarc_fail"]
    ):
        evaluation["auth_suspicious"] = True

    return evaluation


# --------------------------------------------------
# Master function for this module
# --------------------------------------------------
def run_auth_checks(auth_data: dict) -> dict:
    """
    Accepts already parsed authentication dictionary
    """

    if not auth_data:
        auth_data = {}

    spf = auth_data.get("spf")
    dkim = auth_data.get("dkim")
    dmarc = auth_data.get("dmarc")

    return {
        "spf_fail": spf == "fail",
        "dkim_fail": dkim == "fail",
        "dmarc_fail": dmarc == "fail",
        "auth_suspicious": (
            spf == "fail" or
            dkim == "fail" or
            dmarc == "fail"
        )
    }
