from email import policy
from email.parser import BytesParser
import sys
import re
from urllib.parse import urlparse

# Fix Windows encoding issue
sys.stdout.reconfigure(encoding='utf-8')


# -------------------------------
# Helper: Extract domain from email header
# -------------------------------
def extract_domain(email_header):
    if email_header and "@" in email_header:
        return email_header.split("@")[-1].replace(">", "").strip()
    return None


# -------------------------------
# 1️⃣ Load email file
# -------------------------------
def load_email(file):
    with open(file, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


# -------------------------------
# 2️⃣ Extract metadata (Header Analysis)
# -------------------------------
def extract_metadata(msg):
    from_header = msg.get("From")
    return_path = msg.get("Return-Path")

    metadata = {
        "from": from_header,
        "to": msg.get("To"),
        "cc": msg.get("Cc"),
        "bcc": msg.get("Bcc"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "return_path": return_path,
        "reply_to": msg.get("Reply-To"),
        "message_id": msg.get("Message-ID"),
        "authentication_results": msg.get("Authentication-Results"),
        "received": msg.get_all("Received") or [],
        "content_type": msg.get("Content-Type"),
        "mime_version": msg.get("MIME-Version"),
        "x_mailer": msg.get("X-Mailer"),
        "x_originating_ip": msg.get("X-Originating-IP")
    }

    # Domain extraction
    metadata["from_domain"] = extract_domain(from_header)
    metadata["return_path_domain"] = extract_domain(return_path)

    # Header mismatch detection (Phishing Indicator)
    metadata["reply_to_mismatch"] = (
        metadata["reply_to"] is not None
        and metadata["reply_to"] != from_header
    )

    return metadata


# -------------------------------
# 3️⃣ Decode Email Body (Handles text + HTML)
# -------------------------------
def decode_body(msg):
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition:
                continue

            if content_type == "text/plain":
                body += part.get_content()

            elif content_type == "text/html":
                body += part.get_content()

    else:
        body = msg.get_content()

    return body


# -------------------------------
# 4️⃣ Extract URLs from Email Body
# -------------------------------
def extract_urls(body):
    if not body:
        return []

    # Detect:
    # https://example.com
    # http://example.com
    # www.example.com
    url_pattern = r'(https?://[^\s<>"\'()]+|www\.[^\s<>"\'()]+)'

    found_urls = re.findall(url_pattern, body)

    urls = []
    for url in found_urls:

        # Normalize URLs like www.example.com
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


# -------------------------------
# 5️⃣ Master Function (Used by Team)
# -------------------------------
def analyze_email(file):
    msg = load_email(file)

    metadata = extract_metadata(msg)
    body = decode_body(msg)
    urls = extract_urls(body)

    return {
        "metadata": metadata,
        "body": body,
        "urls": urls
    }


# -------------------------------
# Local Testing Block
# -------------------------------
if __name__ == "__main__":
    result = analyze_email("email2.eml")

    print("=== METADATA ===")
    for key, value in result["metadata"].items():
        print(f"{key}: {value}")

    print("\n=== BODY ===")
    print(result["body"])

    print("\n=== URLS FOUND ===")
    for url in result["urls"]:
        print(url)
