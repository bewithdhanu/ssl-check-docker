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
    """
    Health check endpoint.
    
    Returns:
    - 200: Service is healthy
    """
    return jsonify({
        "status": "healthy",
        "service": "domain-checker",
        "status_code": 200
    }), 200

@app.route('/check', methods=['POST', 'GET'])
def check_domains():
    """
    Check domain(s) endpoint.
    
    POST /check
    Body: {
        "domains": ["example.com", "google.com"]
    }
    
    GET /check?domains=example.com,google.com
    
    Returns:
    - 200: Success (all or some domains checked successfully)
    - 400: Bad Request (no domains provided, invalid input, too many domains)
    - 500: Internal Server Error (unexpected server error)
    """
    try:
        domains = []
        
        if request.method == 'POST':
            if not request.is_json:
                return jsonify({
                    "error": "Content-Type must be application/json",
                    "status_code": 400
                }), 400
            
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
                "status_code": 400,
                "usage": {
                    "POST": {"domains": ["example.com", "google.com"]},
                    "GET": "/check?domains=example.com,google.com"
                }
            }), 400
        
        # Validate domain count (prevent abuse)
        if len(domains) > 100:
            return jsonify({
                "error": "Too many domains. Maximum 100 domains per request.",
                "status_code": 400
            }), 400
        
        # Store original input for each domain
        original_inputs = domains.copy()
        
        # Check domains in parallel
        results = []
        with ThreadPoolExecutor(max_workers=min(len(domains), 10)) as executor:
            future_to_domain = {executor.submit(check_ssl_certificate, domain, domain): domain for domain in domains}
            for future in as_completed(future_to_domain):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    domain = future_to_domain[future]
                    results.append({"domain": domain, "input": domain, "error": str(e)})
        
        # Sort results to match input order
        domain_order = {domain: idx for idx, domain in enumerate(domains)}
        results.sort(key=lambda x: domain_order.get(x.get("domain"), 999))
        
        # Return 200 even if some domains had errors (partial success is still success)
        # Individual domain errors are included in the results
        return jsonify(results), 200
        
    except Exception as e:
        # Unexpected server error
        return jsonify({
            "error": "Internal server error",
            "message": str(e),
            "status_code": 500
        }), 500

@app.route('/', methods=['GET'])
def index():
    """
    API documentation endpoint.
    
    Returns:
    - 200: API documentation
    """
    return jsonify({
        "service": "Domain Checker API",
        "version": "1.0.0",
        "status_code": 200,
        "endpoints": {
            "GET /": "API documentation",
            "GET /health": "Health check (200: healthy)",
            "POST /check": "Check domain(s) - send JSON body with 'domains' array",
            "GET /check": "Check domain(s) - use 'domains' query parameter (comma-separated)"
        },
        "status_codes": {
            "200": "Success",
            "400": "Bad Request - No domains provided, invalid input, or too many domains (>100)",
            "500": "Internal Server Error - Unexpected server error"
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

