"""
attachment_checks.py
Analyzes attachments for malicious indicators
Rule-based detection
"""

import os


# Dangerous file extensions
EXECUTABLE_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".scr", ".js", ".vbs", ".ps1"
]

MACRO_EXTENSIONS = [
    ".docm", ".xlsm", ".pptm"
]


# --------------------------------------------------
# Get extension safely
# --------------------------------------------------
def get_extension(filename):

    if not filename:
        return None

    return os.path.splitext(filename.lower())[1]


# --------------------------------------------------
# Detect double extension
# --------------------------------------------------
def has_double_extension(filename):

    if not filename:
        return False

    parts = filename.split(".")
    return len(parts) > 2


# --------------------------------------------------
# Detect executable attachment
# --------------------------------------------------
def is_executable(ext):
    return ext in EXECUTABLE_EXTENSIONS


# --------------------------------------------------
# Detect macro-enabled file
# --------------------------------------------------
def has_macro(ext):
    return ext in MACRO_EXTENSIONS


# --------------------------------------------------
# Main attachment analyzer
# --------------------------------------------------
def run_attachment_checks(attachments):

    results = {
        "attachment_count": len(attachments),
        "dangerous_extension": False,
        "double_extension": False,
        "macro_file": False,
        "filenames": []
    }

    for att in attachments:

        filename = att.get("filename")
        ext = get_extension(filename)

        results["filenames"].append(filename)

        if has_double_extension(filename):
            results["double_extension"] = True

        if is_executable(ext):
            results["dangerous_extension"] = True

        if has_macro(ext):
            results["macro_file"] = True

    # Overall risk
    results["attachment_suspicious"] = any([
        results["dangerous_extension"],
        results["double_extension"],
        results["macro_file"]
    ])

    return results
