"""
Performance Profiler for Email Phishing Analyzer
Measures time spent in each component to identify bottlenecks
"""

import sys
import os
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Store timing data
timings = {}


def time_it(component_name):
    """Decorator to measure execution time of functions"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start = time.time()
            result = func(*args, **kwargs)
            elapsed = time.time() - start
            
            if component_name not in timings:
                timings[component_name] = []
            timings[component_name].append(elapsed)
            
            return result
        return wrapper
    return decorator


def print_timing_report():
    """Print a formatted timing report"""
    print("\n" + "=" * 70)
    print("⏱️  PERFORMANCE PROFILING REPORT")
    print("=" * 70)
    
    # Calculate totals
    total_time = sum(sum(times) for times in timings.values())
    
    # Sort by total time
    sorted_components = sorted(
        timings.items(),
        key=lambda x: sum(x[1]),
        reverse=True
    )
    
    print(f"\n📊 TOTAL ANALYSIS TIME: {total_time:.3f} seconds\n")
    
    # Display each component
    for component, times in sorted_components:
        total = sum(times)
        avg = total / len(times)
        percentage = (total / total_time) * 100 if total_time > 0 else 0
        
        bar_length = int(percentage / 2)
        bar = "█" * bar_length + "░" * (50 - bar_length)
        
        print(f"{component:40} {percentage:5.1f}% [{bar}]")
        print(f"{'':40} Total: {total:.3f}s | Avg: {avg:.3f}s | Calls: {len(times)}")
        print()
    
    print("=" * 70)
    print("💡 Recommendations:")
    
    # Analyze bottlenecks
    if timings.get('ML URL Authenticity Analysis'):
        ml_time = sum(timings['ML URL Authenticity Analysis'])
        if ml_time / total_time > 0.3:
            print("  ⚠️  ML URL analysis is taking >30% of time - consider GPU acceleration or model optimization")
        else:
            print(f"  ✅ ML URL analysis is efficient (~{(ml_time/total_time)*100:.1f}% of total time)")
    
    if timings.get('DNS/SPF/DMARC/DKIM Checks (Cached)'):
        dns_time = sum(timings['DNS/SPF/DMARC/DKIM Checks (Cached)'])
        if dns_time / total_time > 0.2:
            print(f"  📌 DNS checks are using {(dns_time/total_time)*100:.1f}% of time (now cached and minimal)")
    
    if timings.get('Hugging Face Model Inference'):
        model_time = sum(timings['Hugging Face Model Inference'])
        if model_time / total_time > 0.3:
            print("  ⚠️  Email body model inference is taking >30% of time - consider quantization")
    
    if timings.get('Email Parsing'):
        parse_time = sum(timings['Email Parsing'])
        if parse_time / total_time > 0.2:
            print("  📌 Email parsing completed efficiently")
    
    # Performance improvement message
    if timings.get('ML URL Authenticity Analysis') and timings.get('DNS/SPF/DMARC/DKIM Checks (Cached)'):
        ml_time = sum(timings.get('ML URL Authenticity Analysis', []))
        dns_time = sum(timings.get('DNS/SPF/DMARC/DKIM Checks (Cached)', []))
        improvement = ((dns_time - ml_time) / dns_time) * 100 if dns_time > 0 else 0
        if improvement > 0:
            print(f"\n  🚀 ML URL Analysis provides ~{improvement:.1f}% speedup over traditional DNS lookups")


def profile_full_analysis(email_file='email2.eml'):
    """Profile the complete email analysis pipeline"""
    
    print("\n🚀 Starting Performance Profiling...\n")
    
    # ========== EMAIL PARSING ==========
    @time_it('Email Parsing')
    def parse_email():
        from analyzer import load_email, analyze_email
        msg = load_email(email_file)
        result = analyze_email(email_file)
        return msg, result
    
    msg, email_result = parse_email()
    
    # ========== IP ANALYSIS ==========
    @time_it('IP Analysis (Received Headers)')
    def analyze_ip():
        from infrastructure_analysis import analyze_received_headers
        return analyze_received_headers(msg)
    
    ip_analysis = analyze_ip()
    
    # ========== URL EXTRACTION ==========
    @time_it('URL Extraction')
    def extract_urls():
        from url_analyzer import extract_urls
        return extract_urls(email_result.get("body", ""))
    
    urls = extract_urls()
    
    # ========== ML-BASED URL AUTHENTICITY ANALYSIS ==========
    if urls:
        @time_it('ML URL Authenticity Analysis')
        def analyze_urls_with_ml():
            from url_ml_analyzer import analyze_urls_with_ml_parallel
            return analyze_urls_with_ml_parallel(urls)
        
        ml_url_results = analyze_urls_with_ml()
    
    # ========== DNS/SPF/DMARC/DKIM CHECKS (Cached) ==========
    if urls:
        @time_it('DNS/SPF/DMARC/DKIM Checks (Cached)')
        def dns_checks():
            from url_analyzer import has_spf, has_dmarc, has_dkim, get_domain
            domains = list(set([get_domain(url) for url in urls]))
            results = []
            for domain in domains:
                results.append({
                    'domain': domain,
                    'spf': has_spf(domain),
                    'dmarc': has_dmarc(domain),
                    'dkim': has_dkim(domain)
                })
            return results
        
        dns_results = dns_checks()
    
    # ========== TRANSFORMER MODEL ==========
    @time_it('Hugging Face Model Inference')
    def run_transformer():
        from huggingface_analyzer import analyze_email_body_with_transformers
        return analyze_email_body_with_transformers(email_result.get("body", ""))
    
    transformer_result = run_transformer()
    
    # ========== SCORE CALCULATION ==========
    @time_it('Score Calculation')
    def calculate_scores():
        from score_calculator import calculate_phishing_score
        return calculate_phishing_score(email_result, ip_analysis)
    
    phishing_score = calculate_scores()
    
    # Print results
    print_timing_report()
    
    # Print analysis results
    print("\n📊 ANALYSIS RESULTS:")
    print(f"  Overall Score: {phishing_score['overall_score']}/10")
    print(f"  Risk Level: {phishing_score['risk_level']}")
    print(f"  URLs Found: {len(urls)}")
    print(f"  Transformer Score: {phishing_score['component_scores']['transformer_score']:.2f}")
    
    # Print ML URL Analysis Details
    if urls and 'ml_url_results' in locals():
        print(f"\n🤖 ML URL ANALYSIS RESULTS:")
        malicious_count = sum(1 for r in ml_url_results if not r.is_legitimate)
        print(f"  Total URLs Analyzed: {len(ml_url_results)}")
        print(f"  Suspicious URLs: {malicious_count}")
        print(f"  Legitimate URLs: {len(ml_url_results) - malicious_count}")
        
        for result in ml_url_results:
            status = "⚠️ SUSPICIOUS" if not result.is_legitimate else "✅ LEGITIMATE"
            print(f"    {status} | {result.url} | Score: {result.score}/10 | Confidence: {result.confidence:.2%}")
    
    return phishing_score, timings


if __name__ == "__main__":
    try:
        profile_full_analysis()
    except Exception as e:
        print(f"\n❌ Error during profiling: {e}")
        import traceback
        traceback.print_exc()
