"""
infrastructure_checks.py
Analyzes email routing + infrastructure indicators
Pure rule-based analysis
"""

import re
import ipaddress


# --------------------------------------------------
# Detect private IP presence in received headers
# --------------------------------------------------
def has_private_ip(received_headers):
    for header in received_headers:
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', header)

        for ip in ips:
            try:
                if ipaddress.ip_address(ip).is_private:
                    return True
            except:
                continue

    return False


# --------------------------------------------------
# Extract HELO domain mismatch
# --------------------------------------------------
def helo_mismatch(helo, from_domain):
    if not helo or not from_domain:
        return False

    return from_domain.lower() not in helo.lower()


# --------------------------------------------------
# Detect suspicious relay count
# --------------------------------------------------
def relay_anomaly(received_count):

    # Normal emails usually have 2–6 hops
    if received_count <= 1:
        return True  # injected mail

    if received_count > 15:
        return True  # abnormal relay chain

    return False


# --------------------------------------------------
# Main infrastructure analyzer
# --------------------------------------------------
def run_infrastructure_checks(metadata):

    received_headers = metadata.get("received_headers", [])
    received_count = metadata.get("received_count", 0)
    helo = metadata.get("helo")
    from_domain = metadata.get("from_domain")
    origin_ip = metadata.get("originating_ip")

    results = {
        "originating_ip": origin_ip,
        "relay_count": received_count,
        "private_ip_present": has_private_ip(received_headers),
        "helo_mismatch": helo_mismatch(helo, from_domain),
        "relay_anomaly": relay_anomaly(received_count)
    }

    # Overall infrastructure risk flag
    results["infrastructure_suspicious"] = (
        results["private_ip_present"]
        or results["helo_mismatch"]
        or results["relay_anomaly"]
    )

    return results
