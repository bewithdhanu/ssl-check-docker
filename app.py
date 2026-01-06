#!/usr/bin/env python3
"""
Domain Checker Web Service
REST API wrapper for domain checker functionality using FastAPI.
"""

from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Union
from domain_checker import check_ssl_certificate, clear_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import os

app = FastAPI(
    title="Domain Checker API",
    description="API for checking SSL certificates, domain expiry, health status, and website logos",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Pydantic models for request/response
class ClearCacheRequest(BaseModel):
    domains: Optional[Union[List[str], str]] = Field(default=None, description="List of domains to clear cache for (empty clears all)")

@app.get("/", include_in_schema=False)
async def root():
    """Redirect root to Swagger UI."""
    return RedirectResponse(url="/docs")

@app.get("/health", tags=["Health"])
async def health():
    """
    Health check endpoint.
    
    Returns:
    - 200: Service is healthy
    """
    return {
        "status": "healthy",
        "service": "domain-checker",
        "status_code": 200
    }

@app.get("/check", tags=["Domain Checker"])
async def check_domains(
    domains: str = Query(..., description="Comma-separated list of domains or URLs to check"),
    force: bool = Query(False, description="Bypass cache if true"),
    http_retries: int = Query(1, ge=0, le=10, description="Number of retries for HTTP checks"),
    ssl_retries: int = Query(1, ge=0, le=10, description="Number of retries for SSL checks"),
    domain_retries: int = Query(1, ge=0, le=10, description="Number of retries for domain checks"),
    timeout: int = Query(30, ge=1, le=300, description="HTTP timeout in seconds")
):
    """
    Check domain(s) endpoint.
    
    Uses GET method with query parameters only.
    
    Returns:
    - 200: Success (all or some domains checked successfully)
    - 400: Bad Request (no domains provided, invalid input, too many domains)
    - 500: Internal Server Error (unexpected server error)
    """
    try:
        # Parse comma-separated domains
        domains_list = [d.strip() for d in domains.split(',') if d.strip()]
        
        if not domains_list:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "No domains provided",
                    "status_code": 400,
                    "usage": "/check?domains=example.com,google.com&force=true&http_retries=1&ssl_retries=1&domain_retries=1&timeout=30"
                }
            )
        
        # Validate domain count (prevent abuse)
        if len(domains_list) > 100:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Too many domains. Maximum 100 domains per request.",
                    "status_code": 400
                }
            )
        
        # Validate retries and timeout (already validated by Pydantic, but double-check)
        if http_retries < 0 or http_retries > 10:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Invalid http_retries value. Must be between 0 and 10.",
                    "status_code": 400
                }
            )
        
        if ssl_retries < 0 or ssl_retries > 10:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Invalid ssl_retries value. Must be between 0 and 10.",
                    "status_code": 400
                }
            )
        
        if domain_retries < 0 or domain_retries > 10:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Invalid domain_retries value. Must be between 0 and 10.",
                    "status_code": 400
                }
            )
        
        if timeout < 1 or timeout > 300:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Invalid timeout value. Must be between 1 and 300 seconds.",
                    "status_code": 400
                }
            )
        
        # Check domains in parallel
        results = []
        with ThreadPoolExecutor(max_workers=min(len(domains_list), 10)) as executor:
            future_to_domain = {
                executor.submit(check_ssl_certificate, domain, domain, force, http_retries, ssl_retries, domain_retries, timeout): domain 
                for domain in domains_list
            }
            for future in as_completed(future_to_domain):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    domain = future_to_domain[future]
                    # Ensure all required fields are present even in error case
                    error_result = {
                        "domain": domain,
                        "input": domain,
                        "request_sent_datetime": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                        "ssl_expiry_date": None,
                        "ssl_days_left": None,
                        "ssl_status": None,
                        "ssl_error": f"Unexpected error: {str(e)}",
                        "health_status": None,
                        "response_time_ms": None,
                        "http_status_code": None,
                        "domain_expiry_date": None,
                        "domain_days_left": None,
                        "domain_error": None,
                        "website_logo": None
                    }
                    results.append(error_result)
        
        # Sort results to match input order
        domain_order = {domain: idx for idx, domain in enumerate(domains_list)}
        results.sort(key=lambda x: domain_order.get(x.get("domain"), 999))
        
        # Return 200 even if some domains had errors (partial success is still success)
        # Individual domain errors are included in the results
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        # Unexpected server error
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Internal server error",
                "message": str(e),
                "status_code": 500
            }
        )

@app.post("/cache/clear", tags=["Cache Management"])
@app.delete("/cache/clear", tags=["Cache Management"])
async def clear_cache_endpoint(
    request: Optional[ClearCacheRequest] = Body(None, description="Request body for POST requests"),
    domains: Optional[str] = Query(None, description="Comma-separated list of domains (for GET/DELETE requests)")
):
    """
    Clear cache for specific domain(s) or all domains.
    
    Supports POST (JSON body) and DELETE (query parameters) methods.
    
    Returns:
    - 200: Success - Cache cleared
    - 500: Internal Server Error
    """
    try:
        domains_list = []
        
        # Handle POST request with JSON body
        if request and request.domains:
            domains_input = request.domains
            if isinstance(domains_input, str):
                domains_list = [d.strip() for d in domains_input.split(',') if d.strip()]
            elif isinstance(domains_input, list):
                domains_list = [str(d).strip() for d in domains_input if str(d).strip()]
        # Handle DELETE/GET request with query parameters
        elif domains:
            domains_list = [d.strip() for d in domains.split(',') if d.strip()]
        
        # Clear cache (if domains_list is empty, clears all)
        result = clear_cache(domains_list if domains_list else None)
        result["status_code"] = 200
        
        return result
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Failed to clear cache",
                "message": str(e),
                "status_code": 500
            }
        )

@app.get("/api-docs", tags=["Documentation"], include_in_schema=False)
async def api_docs():
    """
    API documentation endpoint (JSON format).
    
    Returns:
    - 200: API documentation
    """
    return {
        "service": "Domain Checker API",
        "version": "1.0.0",
        "status_code": 200,
        "endpoints": {
            "GET /": "Redirects to Swagger UI",
            "GET /docs": "Swagger UI documentation",
            "GET /redoc": "ReDoc documentation",
            "GET /health": "Health check (200: healthy)",
            "GET /check": "Check domain(s) - use 'domains' query parameter (comma-separated)",
            "POST /cache/clear": "Clear cache for specific domain(s) or all - send JSON body with optional 'domains' array",
            "DELETE /cache/clear": "Clear cache for specific domain(s) or all - use 'domains' query parameter (comma-separated)"
        },
        "status_codes": {
            "200": "Success",
            "400": "Bad Request - No domains provided, invalid input, or too many domains (>100)",
            "500": "Internal Server Error - Unexpected server error"
        },
        "examples": {
            "GET /check": "/check?domains=example.com,google.com&force=true&http_retries=1&ssl_retries=1&domain_retries=1&timeout=30",
            "GET /check (full URL)": "/check?domains=https://pro.example.com/path?query=value&http_retries=2&ssl_retries=1&domain_retries=1&timeout=60",
            "POST /cache/clear": {
                "domains": ["example.com", "google.com"]
            },
            "DELETE /cache/clear": "/cache/clear?domains=example.com,google.com",
            "POST /cache/clear (clear all)": "{}"
        }
    }

if __name__ == '__main__':
    import uvicorn
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    uvicorn.run(app, host=host, port=port)
