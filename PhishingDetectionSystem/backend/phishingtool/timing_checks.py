"""
timing_checks.py
Analyzes timestamp consistency in Received headers
Detects forged or manipulated email timing
"""

import re
from datetime import datetime


# --------------------------------------------------
# Extract timestamps from Received headers
# --------------------------------------------------
def extract_timestamps(received_headers):

    timestamps = []

    for header in received_headers:

        # Matches standard email timestamp formats
        match = re.search(
            r"\w{3},\s\d{1,2}\s\w{3}\s\d{4}\s\d{2}:\d{2}:\d{2}",
            header
        )

        if match:
            try:
                parsed_time = datetime.strptime(
                    match.group(),
                    "%a, %d %b %Y %H:%M:%S"
                )
                timestamps.append(parsed_time)
            except:
                continue

    return timestamps


# --------------------------------------------------
# Detect time travel anomaly
# --------------------------------------------------
def has_time_travel(timestamps):

    if len(timestamps) < 2:
        return False

    for i in range(len(timestamps) - 1):
        if timestamps[i] < timestamps[i + 1]:
            return True

    return False


# --------------------------------------------------
# Calculate total delivery delay
# --------------------------------------------------
def total_delivery_time(timestamps):

    if len(timestamps) < 2:
        return None

    return abs((timestamps[0] - timestamps[-1]).total_seconds())


# --------------------------------------------------
# Detect suspicious delivery speed
# --------------------------------------------------
def suspicious_delivery(total_seconds):

    if total_seconds is None:
        return False

    # unrealistically fast delivery
    if total_seconds < 1:
        return True

    # extremely slow routing
    if total_seconds > 86400:
        return True

    return False


# --------------------------------------------------
# Main timing analyzer
# --------------------------------------------------
def run_timing_checks(metadata):

    received_headers = metadata.get("received_headers", [])

    timestamps = extract_timestamps(received_headers)

    travel_flag = has_time_travel(timestamps)
    total_time = total_delivery_time(timestamps)
    delay_flag = suspicious_delivery(total_time)

    results = {
        "timestamp_count": len(timestamps),
        "time_travel_detected": travel_flag,
        "total_delivery_seconds": total_time,
        "suspicious_delivery_time": delay_flag
    }

    results["timing_suspicious"] = travel_flag or delay_flag

    return results
