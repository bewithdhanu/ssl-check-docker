#!/usr/bin/env python3
"""
Domain Checker Web Service
REST API wrapper for domain checker functionality.
"""

from flask import Flask, request, jsonify
from domain_checker import check_ssl_certificate
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "domain-checker"}), 200

@app.route('/check', methods=['POST', 'GET'])
def check_domains():
    """
    Check domain(s) endpoint.
    
    POST /check
    Body: {
        "domains": ["example.com", "google.com"]
    }
    
    GET /check?domains=example.com,google.com
    """
    domains = []
    
    if request.method == 'POST':
        data = request.get_json() or {}
        domains_input = data.get('domains', [])
        
        # Handle both list and comma-separated string
        if isinstance(domains_input, str):
            domains = [d.strip() for d in domains_input.split(',') if d.strip()]
        elif isinstance(domains_input, list):
            domains = [str(d).strip() for d in domains_input if str(d).strip()]
    else:
        # GET request
        domains_param = request.args.get('domains', '')
        if domains_param:
            domains = [d.strip() for d in domains_param.split(',') if d.strip()]
    
    if not domains:
        return jsonify({
            "error": "No domains provided",
            "usage": {
                "POST": {"domains": ["example.com", "google.com"]},
                "GET": "/check?domains=example.com,google.com"
            }
        }), 400
    
    # Check domains in parallel
    results = []
    with ThreadPoolExecutor(max_workers=min(len(domains), 10)) as executor:
        future_to_domain = {executor.submit(check_ssl_certificate, domain): domain for domain in domains}
        for future in as_completed(future_to_domain):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                domain = future_to_domain[future]
                results.append({"domain": domain, "error": str(e)})
    
    # Sort results to match input order
    domain_order = {domain: idx for idx, domain in enumerate(domains)}
    results.sort(key=lambda x: domain_order.get(x.get("domain"), 999))
    
    return jsonify(results), 200

@app.route('/', methods=['GET'])
def index():
    """API documentation endpoint."""
    return jsonify({
        "service": "Domain Checker API",
        "version": "1.0.0",
        "endpoints": {
            "GET /": "API documentation",
            "GET /health": "Health check",
            "POST /check": "Check domain(s) - send JSON body with 'domains' array",
            "GET /check": "Check domain(s) - use 'domains' query parameter (comma-separated)"
        },
        "examples": {
            "POST /check": {
                "domains": ["example.com", "google.com"]
            },
            "GET /check": "/check?domains=example.com,google.com"
        }
    }), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    app.run(host=host, port=port, debug=False)

