"""
mime_checks.py
Analyzes MIME structure and encoding anomalies
Pure structural analysis (no AI)
"""

# --------------------------------------------------
# Detect encoding types used
# --------------------------------------------------


def detect_encodings(msg):

    encodings = set()

    for part in msg.walk():
        encoding = part.get("Content-Transfer-Encoding")
        if encoding:
            encodings.add(encoding.lower())

    return list(encodings)


# --------------------------------------------------
# Count MIME parts
# --------------------------------------------------
def count_mime_parts(msg):

    if not msg.is_multipart():
        return 1

    return sum(1 for _ in msg.walk())


# --------------------------------------------------
# Detect suspicious encoding usage
# --------------------------------------------------
def suspicious_encoding(encodings):

    # Base64 is common, but too many encoded parts is suspicious
    if "base64" in encodings and len(encodings) > 2:
        return True

    return False


# --------------------------------------------------
# Detect if email is multipart
# --------------------------------------------------
def is_multipart_email(msg):
    return msg.is_multipart()


# --------------------------------------------------
# Main MIME analyzer
# --------------------------------------------------
def run_mime_checks(msg):

    encodings = detect_encodings(msg)
    part_count = count_mime_parts(msg)
    multipart_flag = is_multipart_email(msg)

    results = {
        "mime_type": msg.get_content_type(),
        "is_multipart": multipart_flag,
        "mime_part_count": part_count,
        "encodings_used": encodings,
        "suspicious_encoding": suspicious_encoding(encodings)
    }

    return results
