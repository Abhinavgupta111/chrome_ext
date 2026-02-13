"""
header_checks.py
Validates header integrity and detects anomalies
Rule-based detection
"""


# Required headers every legitimate email should have
REQUIRED_HEADERS = [
    "from",
    "date",
    "subject",
    "message_id"
]


# --------------------------------------------------
# Check missing required headers
# --------------------------------------------------
def missing_required_headers(metadata):

    missing = []

    for field in REQUIRED_HEADERS:
        if not metadata.get(field):
            missing.append(field)

    return missing


# --------------------------------------------------
# Detect duplicate headers
# --------------------------------------------------
def duplicate_headers(metadata):

    duplicates = []

    for key, value in metadata.items():
        if isinstance(value, list) and len(value) > 1:
            duplicates.append(key)

    return duplicates


# --------------------------------------------------
# Detect invalid Message-ID format
# --------------------------------------------------
def invalid_message_id(message_id):

    if not message_id:
        return True

    if "<" not in message_id or "@" not in message_id:
        return True

    return False


# --------------------------------------------------
# Detect suspicious header length
# --------------------------------------------------
def unusually_long_headers(metadata):

    long_headers = []

    for key, value in metadata.items():

        if isinstance(value, str) and len(value) > 500:
            long_headers.append(key)

    return long_headers


# --------------------------------------------------
# Main header analyzer
# --------------------------------------------------
def run_header_checks(metadata):

    missing = missing_required_headers(metadata)
    duplicates = duplicate_headers(metadata)
    invalid_msgid = invalid_message_id(metadata.get("message_id"))
    long_headers = unusually_long_headers(metadata)

    results = {
        "missing_headers": missing,
        "duplicate_headers": duplicates,
        "invalid_message_id": invalid_msgid,
        "unusually_long_headers": long_headers
    }

    results["header_suspicious"] = any([
        missing,
        duplicates,
        invalid_msgid,
        long_headers
    ])

    return results
