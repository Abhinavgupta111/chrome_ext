from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import sys
import re
import hashlib
from urllib.parse import urlparse
import ipaddress

sys.stdout.reconfigure(encoding='utf-8')


# -------------------------------
# Helper: Extract domain safely
# -------------------------------
def extract_domain(address):
    if not address:
        return None
    name, email_addr = parseaddr(address)
    if "@" in email_addr:
        return email_addr.split("@")[-1].lower().strip()
    return None


# -------------------------------
# Helper: Extract domain from Message-ID
# -------------------------------
def extract_message_id_domain(message_id):
    if message_id and "@" in message_id:
        return message_id.split("@")[-1].replace(">", "").strip().lower()
    return None


# -------------------------------
# Helper: Extract first public IP
# -------------------------------
def extract_origin_ip(received_headers):
    for header in received_headers:
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', header)
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private:
                    return ip
            except:
                continue
    return None


# -------------------------------
# Helper: Parse Authentication-Results
# -------------------------------
def parse_authentication(auth_header):
    results = {
        "spf": None,
        "dkim": None,
        "dmarc": None
    }

    if not auth_header:
        return results

    if "spf=" in auth_header:
        results["spf"] = re.search(r'spf=(\w+)', auth_header)
        results["spf"] = results["spf"].group(1) if results["spf"] else None

    if "dkim=" in auth_header:
        results["dkim"] = re.search(r'dkim=(\w+)', auth_header)
        results["dkim"] = results["dkim"].group(1) if results["dkim"] else None

    if "dmarc=" in auth_header:
        results["dmarc"] = re.search(r'dmarc=(\w+)', auth_header)
        results["dmarc"] = results["dmarc"].group(
            1) if results["dmarc"] else None

    return results


# -------------------------------
# Load Email
# -------------------------------
def load_email(file):
    with open(file, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


# -------------------------------
# Extract Metadata
# -------------------------------
def extract_metadata(msg):
    received_headers = msg.get_all("Received") or []
    auth_header = msg.get("Authentication-Results")

    metadata = {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "cc": msg.get("Cc"),
        "bcc": msg.get("Bcc"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "reply_to": msg.get("Reply-To"),
        "return_path": msg.get("Return-Path"),
        "message_id": msg.get("Message-ID"),
        "mime_version": msg.get("MIME-Version"),
        "content_type": msg.get_content_type(),
        "x_mailer": msg.get("X-Mailer"),
        "user_agent": msg.get("User-Agent"),
        "received_headers": received_headers,
        "received_count": len(received_headers),
    }

    # Domains
    metadata["from_domain"] = extract_domain(metadata["from"])
    metadata["reply_to_domain"] = extract_domain(metadata["reply_to"])
    metadata["return_path_domain"] = extract_domain(metadata["return_path"])
    metadata["message_id_domain"] = extract_message_id_domain(
        metadata["message_id"])

    # Authentication
    metadata["authentication"] = parse_authentication(auth_header)

    # Origin IP
    metadata["originating_ip"] = extract_origin_ip(received_headers)

    # HELO extraction
    helo_match = None
    for header in received_headers:
        match = re.search(r'helo=([^\s;]+)', header, re.IGNORECASE)
        if match:
            helo_match = match.group(1)
            break
    metadata["helo"] = helo_match

    # Domain mismatch checks
    metadata["reply_to_mismatch"] = (
        metadata["reply_to_domain"] and
        metadata["from_domain"] and
        metadata["reply_to_domain"] != metadata["from_domain"]
    )

    metadata["return_path_mismatch"] = (
        metadata["return_path_domain"] and
        metadata["from_domain"] and
        metadata["return_path_domain"] != metadata["from_domain"]
    )

    metadata["message_id_mismatch"] = (
        metadata["message_id_domain"] and
        metadata["from_domain"] and
        metadata["message_id_domain"] != metadata["from_domain"]
    )

    return metadata


# -------------------------------
# Decode Body
# -------------------------------
def decode_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() in ["text/plain", "text/html"]:
                body += part.get_content()
    else:
        body = msg.get_content()
    return body


# -------------------------------
# Extract Attachments
# -------------------------------
def extract_attachments(msg):
    attachments = []

    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True)
            filename = part.get_filename()
            size = len(payload) if payload else 0

            sha256_hash = hashlib.sha256(
                payload).hexdigest() if payload else None

            attachments.append({
                "filename": filename,
                "mime_type": part.get_content_type(),
                "size_bytes": size,
                "sha256": sha256_hash
            })

    return attachments


# -------------------------------
# Extract URLs
# -------------------------------
def extract_urls(body):
    if not body:
        return []

    url_pattern = r'(https?://[^\s<>"\'()]+|www\.[^\s<>"\'()]+)'
    found_urls = re.findall(url_pattern, body)

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


# -------------------------------
# MASTER ANALYZER
# -------------------------------
def analyze_email(file):
    msg = load_email(file)

    metadata = extract_metadata(msg)
    body = decode_body(msg)
    urls = extract_urls(body)
    attachments = extract_attachments(msg)

    return {
        "metadata": metadata,
        "body_length": len(body),
        "urls": urls,
        "url_count": len(urls),
        "attachments": attachments,
        "attachment_count": len(attachments),
        "raw_msg": msg   # ADD THIS
    }




