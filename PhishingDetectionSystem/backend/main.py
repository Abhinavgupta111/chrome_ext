#!/usr/bin/env python3
"""
Email Phishing Analyzer - Flask Web Server
Comprehensive phishing detection using ML models + rule-based analysis
Integrated with score_calculator (combines ALL phishingtool modules)
"""

import sys
import os

from flask_cors import CORS
from flask import Flask, request, jsonify
from datetime import datetime
from waitress import serve

# Initialize Flask app
app = Flask(__name__)

# Security: CORS Policy (Restrict to extension if possible, for now default)
CORS(app)

# Security: Input Validation
from werkzeug.utils import secure_filename

app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Reduced to 5MB (plenty for .eml)
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@app.route('/analyze_text', methods=['POST'])
def analyze_text_route():
    """Analyze text payload from Chrome Extension."""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        # 🔥 IMPORT TEXT ANALYZER
        from phishingtool.text_analyzer import analyze_text_payload
        
        # 🔥 RUN ANALYSIS
        result = analyze_text_payload(data)
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': 'An internal error occurred during analysis.'}), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'Email Phishing Analyzer - Text Analysis Only',
        'modules': [
            'Text Analysis', 'URL Security', 'Transformer'
        ]
    }), 200


if __name__ == "__main__":
    print("🚀 Starting Independent Phishing Detection Backend")
    print("📊 Features: Text Analysis for Chrome Extension")
    print("📱 POST text to: http://localhost:5000/analyze_text")
    print("💚 GET health check: http://localhost:5000/health")
    print("Press CTRL+C to stop the server\n")
    serve(app, host='0.0.0.0', port=5000)
