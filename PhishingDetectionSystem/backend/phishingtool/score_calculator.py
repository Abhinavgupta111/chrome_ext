"""
Score Calculator for Email Phishing Detection
Combines analysis from ALL phishingtool modules to calculate a comprehensive phishing risk score (0-10).
Integrated modules: analyzer, attachment_checks, auth_checks, domain_checks, 
header_checks, infrastructure_checks, mime_checks, timing_checks, url_checks, 
huggingface_analyzer, url_ml_analyzer, and infrastructure_analysis.
"""

import json
from datetime import datetime


# ============================================================
# ATTACHMENT SCORING
# ============================================================
def calculate_attachment_score(msg):
    """
    Calculate phishing score based on attachment analysis.
    
    :param msg: email message object
    :return: score (0-10)
    """
    try:
        from attachment_checks import (
            get_extension, has_double_extension, is_executable, 
            is_macro_enabled, is_archive
        )
        
        score = 0
        
        for part in msg.walk():
            filename = part.get_filename()
            if not filename:
                continue
            
            ext = get_extension(filename)
            
            # Double extension is suspicious
            if has_double_extension(filename):
                score += 2
            
            # Executable file
            if ext and is_executable(ext):
                score += 3
            
            # Macro-enabled document
            if ext and is_macro_enabled(ext):
                score += 2.5
            
            # Archive file (could contain malware)
            if ext and is_archive(ext):
                score += 1.5
        
        return min(score, 10)
    except Exception as e:
        print(f"Attachment check error: {e}")
        return 0


# ============================================================
# AUTHENTICATION SCORING (SPF, DKIM, DMARC, ARC)
# ============================================================
def calculate_auth_score(msg, metadata):
    """
    Calculate phishing score based on authentication checks.
    
    :param msg: email message object
    :param metadata: email metadata dict
    :return: score (0-10)
    """
    try:
        from auth_checks import parse_authentication_results
        
        score = 0
        auth_header = msg.get("Authentication-Results", "")
        auth_results = parse_authentication_results(auth_header)
        
        # SPF failures
        if auth_results.get("spf_result") == "fail":
            score += 2.5
        elif auth_results.get("spf_result") == "softfail":
            score += 1
        
        # DKIM failures
        if auth_results.get("dkim_result") == "fail":
            score += 2.5
        elif auth_results.get("dkim_result") == "neutral":
            score += 0.5
        
        # DMARC failures
        if auth_results.get("dmarc_result") == "fail":
            score += 3
        elif auth_results.get("dmarc_result") == "quarantine":
            score += 2
        
        # No authentication records at all
        if not auth_header:
            score += 2
        
        return min(score, 10)
    except Exception as e:
        print(f"Auth check error: {e}")
        return 0


# ============================================================
# HEADER SCORING
# ============================================================
def calculate_header_score(metadata):
    """
    Calculate phishing score based on header analysis.
    
    :param metadata: email metadata dict
    :return: score (0-10)
    """
    try:
        from header_checks import (
            missing_required_headers, duplicate_headers, 
            invalid_message_id, unusually_long_headers
        )
        
        score = 0
        
        # Missing required headers
        missing = missing_required_headers(metadata)
        score += len(missing) * 0.5
        
        # Duplicate headers
        duplicates = duplicate_headers(metadata)
        score += len(duplicates) * 1.5
        
        # Invalid Message-ID
        if invalid_message_id(metadata.get("message_id")):
            score += 1.5
        
        # Unusually long headers
        long_headers = unusually_long_headers(metadata)
        score += len(long_headers) * 1
        
        return min(score, 10)
    except Exception as e:
        print(f"Header check error: {e}")
        return 0


# ============================================================
# DOMAIN SCORING
# ============================================================
def calculate_domain_score(metadata):
    """
    Calculate phishing score based on domain analysis.
    
    :param metadata: email metadata dict
    :return: score (0-10)
    """
    try:
        from domain_checks import has_suspicious_tld, looks_like_spoofed
        
        score = 0
        from_domain = metadata.get("from_domain", "")
        return_path_domain = metadata.get("return_path_domain", "")
        
        # Check From domain
        if from_domain:
            if has_suspicious_tld(from_domain):
                score += 2
            if looks_like_spoofed(from_domain):
                score += 2.5
        
        # Check Return-Path domain
        if return_path_domain:
            if has_suspicious_tld(return_path_domain):
                score += 1.5
            if looks_like_spoofed(return_path_domain):
                score += 2
        
        # Domain mismatch
        if from_domain != return_path_domain:
            score += 1.5
        
        return min(score, 10)
    except Exception as e:
        print(f"Domain check error: {e}")
        return 0


# ============================================================
# URL SCORING
# ============================================================
def calculate_url_score(email_body):
    """
    Calculate phishing score based on URL checks.
    
    :param email_body: email body text
    :return: score (0-10)
    """
    try:
        from url_analyzer import extract_urls, get_domain
        from url_checks import (
            is_ip_url, has_suspicious_tld, is_long_url, 
            too_many_subdomains, is_insecure_scheme
        )
        from urllib.parse import urlparse
        
        score = 0
        urls = extract_urls(email_body)
        
        for url in urls:
            parsed = urlparse(url)
            domain = get_domain(url) if get_domain else parsed.netloc
            
            # IP-based URL
            if is_ip_url(domain):
                score += 2
            
            # Suspicious TLD
            if has_suspicious_tld(domain):
                score += 1.5
            
            # Long URL (could hide actual destination)
            if is_long_url(url):
                score += 1
            
            # Too many subdomains
            if too_many_subdomains(domain):
                score += 1
            
            # Insecure HTTP
            if is_insecure_scheme(parsed.scheme):
                score += 1
        
        return min(score, 10)
    except Exception as e:
        print(f"URL check error: {e}")
        return 0


# ============================================================
# INFRASTRUCTURE SCORING
# ============================================================
def calculate_infrastructure_score(msg, metadata):
    """
    Calculate phishing score based on infrastructure analysis.
    
    :param msg: email message object
    :param metadata: email metadata dict
    :return: score (0-10)
    """
    try:
        from infrastructure_checks import (
            has_private_ip, helo_mismatch, relay_anomaly
        )
        
        score = 0
        received_headers = msg.get_all("Received") or []
        received_count = len(received_headers)
        helo = metadata.get("helo")
        from_domain = metadata.get("from_domain")
        
        # Private IP presence
        if has_private_ip(received_headers):
            score += 2
        
        # HELO mismatch
        if helo_mismatch(helo, from_domain):
            score += 1.5
        
        # Relay anomaly
        if relay_anomaly(received_count):
            score += 2
        
        return min(score, 10)
    except Exception as e:
        print(f"Infrastructure check error: {e}")
        return 0


# ============================================================
# MIME SCORING
# ============================================================
def calculate_mime_score(msg):
    """
    Calculate phishing score based on MIME structure analysis.
    
    :param msg: email message object
    :return: score (0-10)
    """
    try:
        from mime_checks import detect_encodings, count_mime_parts, suspicious_encoding
        
        score = 0
        
        # Detect suspicious encodings
        encodings = detect_encodings(msg)
        if suspicious_encoding(encodings):
            score += 2
        
        # Too many MIME parts
        part_count = count_mime_parts(msg)
        if part_count > 10:
            score += 1.5
        
        return min(score, 10)
    except Exception as e:
        print(f"MIME check error: {e}")
        return 0


# ============================================================
# TIMING SCORING
# ============================================================
def calculate_timing_score(msg):
    """
    Calculate phishing score based on timing analysis.
    
    :param msg: email message object
    :return: score (0-10)
    """
    try:
        from timing_checks import (
            extract_timestamps, has_time_travel, 
            total_delivery_time, suspicious_delivery
        )
        
        score = 0
        received_headers = msg.get_all("Received") or []
        
        # Extract timestamps
        timestamps = extract_timestamps(received_headers)
        
        if timestamps:
            # Time travel anomaly (backward timestamps)
            if has_time_travel(timestamps):
                score += 2.5
            
            # Suspicious delivery speed
            total_time = total_delivery_time(timestamps)
            if suspicious_delivery(total_time):
                score += 2
        
        return min(score, 10)
    except Exception as e:
        print(f"Timing check error: {e}")
        return 0


# ============================================================
# METADATA SCORING (Original)
# ============================================================
def calculate_metadata_score(metadata):
    """
    Calculate phishing score based on email metadata.
    
    :param metadata: email metadata dict from analyzer
    :return: score (0-10)
    """
    score = 0
    
    # Check for header mismatches (phishing indicator)
    if metadata.get("reply_to_mismatch"):
        score += 2.5
    
    # Check for missing or suspicious headers
    if not metadata.get("authentication_results"):
        score += 1.5
    
    # Check for unusual mailer or headers
    if metadata.get("x_mailer") and "unknown" in str(metadata.get("x_mailer", "")).lower():
        score += 1
    
    # Domain mismatch between From and Return-Path
    from_domain = metadata.get("from_domain")
    return_path_domain = metadata.get("return_path_domain")
    if from_domain and return_path_domain and from_domain != return_path_domain:
        score += 2
    
    return min(score, 10)


# ============================================================
# IP SCORING (Original)
# ============================================================
def calculate_ip_score(ip_analysis):
    """
    Calculate phishing score based on IP analysis.
    
    :param ip_analysis: IP analysis dict from infrastructure_analysis
    :return: score (0-10)
    """
    score = 0
    
    ips = ip_analysis.get("ips", [])
    originating_ip = ip_analysis.get("originating_ip")
    
    # Multiple IPs can indicate spoofing
    if len(ips) > 5:
        score += 1.5
    
    # No originating IP found (suspicious)
    if not originating_ip:
        score += 2
    
    return min(score, 10)


# ============================================================
# URL SECURITY SCORING (Original)
# ============================================================
def calculate_url_security_score(email_body):
    """
    Calculate phishing score based on ML model for URL authenticity.
    Uses fast ML-based analysis instead of DNS queries.
    
    :param email_body: email body text from analyzer
    :return: tuple (overall_score, spf_results, dmarc_results, dkim_results)
    """
    if not email_body:
        return 0, [], [], []
    
    try:
        from url_analyzer import extract_urls, has_spf, has_dmarc, has_dkim
        from url_ml_analyzer import get_url_security_score_from_ml
        
        urls = extract_urls(email_body)
        if not urls:
            return 0, [], [], []
        
        # Use ML model for fast URL authenticity scoring
        url_score, ml_details = get_url_security_score_from_ml(urls)
        
        # Still check DNS auth records for reporting
        spf_results = []
        dmarc_results = []
        dkim_results = []
        
        for url in urls:
            from url_analyzer import get_domain
            domain = get_domain(url)
            spf_results.append(has_spf(domain))
            dmarc_results.append(has_dmarc(domain))
            dkim_results.append(has_dkim(domain))
        
        return url_score, spf_results, dmarc_results, dkim_results
    except Exception as e:
        print(f"URL security check error: {e}")
        return 0, [], [], []


# ============================================================
# TRANSFORMER SCORING (Original)
# ============================================================
def calculate_transformer_score(email_body):
    """
    Calculate phishing score using Hugging Face transformer model.
    
    :param email_body: email body text from analyzer
    :return: score (0-10)
    """
    if not email_body:
        return 0
    
    try:
        from huggingface_analyzer import get_transformer_score
        
        score = get_transformer_score(email_body)
        return min(score, 10)
    except Exception as e:
        print(f"Transformer check error: {e}")
        return 0


# ============================================================
# COMPREHENSIVE PHISHING SCORE CALCULATOR
# ============================================================
def calculate_comprehensive_phishing_score(email_file_path):
    """
    Calculate overall phishing risk score from ALL analysis modules.
    
    :param email_file_path: path to email file
    :return: dict with overall score and all component scores
    """
    try:
        from analyzer import analyze_email, load_email
        from infrastructure_analysis import analyze_received_headers
        
        # Load email
        msg = load_email(email_file_path)
        email_result = analyze_email(email_file_path)
        ip_analysis = analyze_received_headers(msg)
        
        metadata = email_result.get("metadata", {})
        body = email_result.get("body", "")
        
        # Calculate ALL component scores
        attachment_score = calculate_attachment_score(msg)
        auth_score = calculate_auth_score(msg, metadata)
        header_score = calculate_header_score(metadata)
        domain_score = calculate_domain_score(metadata)
        url_score = calculate_url_score(body)
        infrastructure_score = calculate_infrastructure_score(msg, metadata)
        mime_score = calculate_mime_score(msg)
        timing_score = calculate_timing_score(msg)
        metadata_score = calculate_metadata_score(metadata)
        ip_score = calculate_ip_score(ip_analysis)
        url_security_score, spf_results, dmarc_results, dkim_results = calculate_url_security_score(body)
        transformer_score = calculate_transformer_score(body)
        
        # Weighted overall score
        # Each major category gets weighted
        # Total weight = 100%
        overall_score = (
            (attachment_score * 0.08) +      # 8%
            (auth_score * 0.12) +             # 12%
            (header_score * 0.08) +           # 8%
            (domain_score * 0.10) +           # 10%
            (url_score * 0.08) +              # 8%
            (infrastructure_score * 0.08) +   # 8%
            (mime_score * 0.06) +             # 6%
            (timing_score * 0.06) +           # 6%
            (metadata_score * 0.08) +         # 8%
            (ip_score * 0.07) +               # 7%
            (url_security_score * 0.10) +     # 10%
            (transformer_score * 0.03)        # 3%
        )
        
        # Determine if SPF, DMARC, DKIM are present
        spf_present = any(spf_results) if spf_results else False
        dmarc_present = any(dmarc_results) if dmarc_results else False
        dkim_present = any(dkim_results) if dkim_results else False
        
        return {
            "overall_score": round(overall_score, 2),
            "risk_level": get_risk_level(overall_score),
            "spf": spf_present,
            "dmarc": dmarc_present,
            "dkim": dkim_present,
            "originating_ip": ip_analysis.get("originating_ip"),
            "from_address": metadata.get("from"),
            "to_address": metadata.get("to"),
            "component_scores": {
                "attachment_score": attachment_score,
                "authentication_score": auth_score,
                "header_score": header_score,
                "domain_score": domain_score,
                "url_score": url_score,
                "infrastructure_score": infrastructure_score,
                "mime_score": mime_score,
                "timing_score": timing_score,
                "metadata_score": metadata_score,
                "ip_analysis_score": ip_score,
                "url_security_score": url_security_score,
                "transformer_score": transformer_score
            },
            "details": {
                "header_mismatch": metadata.get("reply_to_mismatch", False),
                "domain_mismatch": metadata.get("from_domain") != metadata.get("return_path_domain"),
                "total_ips_found": len(ip_analysis.get("ips", [])),
            }
        }
    except Exception as e:
        print(f"Error in comprehensive phishing score calculation: {e}")
        return None


# ============================================================
# LEGACY FUNCTION (kept for compatibility)
# ============================================================
def calculate_phishing_score(email_result, ip_analysis):
    """
    Legacy function - kept for backward compatibility.
    Now it's recommended to use calculate_comprehensive_phishing_score() instead.
    
    :param email_result: result from analyze_email()
    :param ip_analysis: result from analyze_received_headers()
    :return: dict with overall score and component scores
    """
    
    metadata = email_result.get("metadata", {})
    body = email_result.get("body", "")
    
    # Calculate individual component scores
    metadata_score = calculate_metadata_score(metadata)
    ip_score = calculate_ip_score(ip_analysis)
    url_score, spf_results, dmarc_results, dkim_results = calculate_url_security_score(body)
    transformer_score = calculate_transformer_score(body)
    
    # Weighted average
    overall_score = (
        (url_score * 0.30) +
        (transformer_score * 0.25) +
        (metadata_score * 0.25) +
        (ip_score * 0.20)
    )
    
    # Determine if SPF, DMARC, DKIM are present
    spf_present = any(spf_results) if spf_results else False
    dmarc_present = any(dmarc_results) if dmarc_results else False
    dkim_present = any(dkim_results) if dkim_results else False
    
    return {
        "overall_score": round(overall_score, 2),
        "risk_level": get_risk_level(overall_score),
        "spf": spf_present,
        "dmarc": dmarc_present,
        "dkim": dkim_present,
        "originating_ip": ip_analysis.get("originating_ip"),
        "component_scores": {
            "url_security_score": url_score,
            "transformer_score": transformer_score,
            "metadata_score": metadata_score,
            "ip_score": ip_score
        },
        "details": {
            "header_mismatch": metadata.get("reply_to_mismatch", False),
            "domain_mismatch": metadata.get("from_domain") != metadata.get("return_path_domain"),
            "total_ips_found": len(ip_analysis.get("ips", [])),
        }
    }


# ============================================================
# RISK LEVEL DETERMINATION
# ============================================================
def get_risk_level(score):
    """
    Determine risk level based on score.
    
    :param score: phishing score (0-10)
    :return: risk level string
    """
    if score >= 8:
        return "CRITICAL"
    elif score >= 6:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    elif score >= 2:
        return "LOW"
    else:
        return "MINIMAL"


# ============================================================
# JSON EXPORT
# ============================================================
def save_to_json(phishing_score, filename="phishing_assessment.json"):
    """
    Save phishing assessment results to JSON file.
    
    :param phishing_score: dict with phishing assessment results
    :param filename: output JSON filename
    :return: filename of saved JSON file
    """
    output_data = {
        "timestamp": datetime.now().isoformat(),
        "assessment": phishing_score
    }
    
    with open(filename, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    return filename


# ============================================================
# MAIN EXECUTION
# ============================================================
if __name__ == "__main__":
    # Example usage with comprehensive scoring
    phishing_score = calculate_comprehensive_phishing_score("email2.eml")
    
    if phishing_score:
        print("=" * 70)
        print("COMPREHENSIVE PHISHING RISK ASSESSMENT REPORT")
        print("=" * 70)
        
        print(f"\n📊 OVERALL SCORE: {phishing_score['overall_score']}/10")
        print(f"🚨 RISK LEVEL: {phishing_score['risk_level']}")
        
        print("\n📋 DETAILED COMPONENT SCORES:")
        scores = phishing_score['component_scores']
        for component, score in scores.items():
            component_name = component.replace("_", " ").title()
            print(f"  • {component_name}: {score}")
        
        print("\n🔐 AUTHENTICATION RECORDS:")
        print(f"  • SPF: {'✓ Present' if phishing_score['spf'] else '✗ Not Found'}")
        print(f"  • DMARC: {'✓ Present' if phishing_score['dmarc'] else '✗ Not Found'}")
        print(f"  • DKIM: {'✓ Present' if phishing_score['dkim'] else '✗ Not Found'}")
        
        print("\n🌐 NETWORK INFORMATION:")
        print(f"  • Originating IP: {phishing_score['originating_ip']}")
        print(f"  • Domain Mismatch: {'⚠ Yes' if phishing_score['details']['domain_mismatch'] else '✓ No'}")
        print(f"  • Header Mismatch: {'⚠ Yes' if phishing_score['details']['header_mismatch'] else '✓ No'}")
        print(f"  • Total IPs Found: {phishing_score['details']['total_ips_found']}")
        
        print("\n" + "=" * 70)
        
        # Save to JSON file
        json_file = save_to_json(phishing_score)
        print(f"\n✅ Results saved to: {json_file}")
    else:
        print("❌ Error: Failed to calculate phishing score")