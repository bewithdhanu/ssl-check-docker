# Domain Checker Docker Image

A Docker image that checks SSL certificate expiry dates, domain expiry, health status, response time, and website logos for one or more domains. Available as both a CLI tool and a FastAPI REST API web service with built-in Swagger UI.

## Features

- **SSL Certificate Check**: Check SSL certificate expiry dates for single or multiple domains
- **Domain Expiry Check**: Check domain registration expiry dates using WHOIS with referral following and RDAP fallback
- **Health Check**: Verify if domains are reachable (UP/DOWN status) with HTTP status codes
- **Response Time**: Measure HTTP/HTTPS response time in milliseconds
- **Website Logo Extraction**: Extract website logos from HTML (favicon, apple-touch-icon, og:image, etc.)
- **Smart Caching**: Reduces API calls by caching results for SSL, domain expiry, and logos
  - **Unified Cache**: All checks cached for 1 hour
  - Significantly improves performance for repeated checks
  - Domain expiry cache is shared across all subdomains (e.g., `pro.example.com` uses cached expiry from `example.com`)
- **Retry Logic**: Configurable retries for HTTP, SSL, and domain checks (default: 1 retry each)
- **Full URL Support**: Supports full URLs with paths and query parameters
- **WHOIS Robustness**: Follows WHOIS referrals, uses TLD-specific fallbacks, and RDAP as fallback
- Returns expiry dates in YYYY-MM-DD HH:MM:SS format (UTC)
- Calculates days until expiration for both SSL certificates and domain registrations
- Status indicators: `OK` (valid), `EXPIRING` (within 30 days), or `EXPIRED`
- Handles errors gracefully with detailed error messages
- Built-in Swagger UI for interactive API documentation

## Quick Start

### CLI Usage

Pull and run the Docker image:

```bash
docker run --rm bewithdhanu/domain-checker example.com
```

### Web Service Usage

Run as a web service:

```bash
docker run -d -p 5000:5000 --name domain-checker bewithdhanu/domain-checker
```

Then access the API:

```bash
# Health check
curl http://localhost:5000/health

# Check domain (GET only)
curl "http://localhost:5000/check?domains=example.com"

# Check multiple domains
curl "http://localhost:5000/check?domains=example.com,google.com&force=true"

# Check with custom retries and timeout
curl "http://localhost:5000/check?domains=example.com&http_retries=2&ssl_retries=1&domain_retries=3&timeout=60"

# Check full URL with path
curl "http://localhost:5000/check?domains=https://pro.example.com/path?query=value"

# Access Swagger UI
# Open http://localhost:5000/docs in your browser
```

### Swagger UI

FastAPI provides built-in interactive API documentation:

- **Swagger UI**: `http://localhost:5000/docs` - Interactive API documentation with "Try it out" feature
- **ReDoc**: `http://localhost:5000/redoc` - Alternative API documentation format
- **Root**: `http://localhost:5000/` - Redirects to Swagger UI

### Deploy to Coolify

See [COOLIFY_DEPLOYMENT.md](./COOLIFY_DEPLOYMENT.md) for detailed deployment instructions.

## Building the Docker Image

```bash
docker build -t domain-checker .
```

## Usage

### Single Domain

```bash
docker run --rm bewithdhanu/domain-checker example.com
```

### Multiple Domains

```bash
docker run --rm bewithdhanu/domain-checker example.com google.com yahoo.com
```

### Using Environment Variable

```bash
docker run --rm -e DOMAINS="example.com,google.com,yahoo.com" bewithdhanu/domain-checker --env
```

### Using Cache with Volume (Persistent Cache)

To persist cache across container runs, mount a volume:

```bash
# Create a volume for cache persistence
docker volume create domain-checker-cache

# Run with persistent cache
docker run --rm -v domain-checker-cache:/tmp/ssl-checker-cache bewithdhanu/domain-checker example.com

# Or use a host directory
docker run --rm -v $(pwd)/cache:/tmp/ssl-checker-cache bewithdhanu/domain-checker example.com
```

### Custom Cache Directory

You can specify a custom cache directory using the `CACHE_DIR` environment variable:

```bash
docker run --rm -e CACHE_DIR=/app/cache -v $(pwd)/cache:/app/cache bewithdhanu/domain-checker example.com
```

## API Endpoints

### GET /check

Check domain(s) with query parameters only.

**Parameters:**
- `domains` (required): Comma-separated list of domains or full URLs
- `force` (optional, default: `false`): Bypass cache if `true`
- `http_retries` (optional, default: `1`): Number of retries for HTTP/health checks (0-10)
- `ssl_retries` (optional, default: `1`): Number of retries for SSL checks (0-10)
- `domain_retries` (optional, default: `1`): Number of retries for domain expiry checks (0-10)
- `timeout` (optional, default: `30`): HTTP timeout in seconds (1-300)

**Example:**
```bash
curl "http://localhost:5000/check?domains=example.com,google.com&force=false&http_retries=2&ssl_retries=1&domain_retries=1&timeout=30"
```

### GET /health

Health check endpoint.

**Example:**
```bash
curl http://localhost:5000/health
```

### POST /cache/clear

Clear cache for specific domain(s) or all domains.

**Body (optional):**
```json
{
  "domains": ["example.com", "google.com"]
}
```

**Example:**
```bash
# Clear specific domains
curl -X POST http://localhost:5000/cache/clear \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "google.com"]}'

# Clear all cache
curl -X POST http://localhost:5000/cache/clear \
  -H "Content-Type: application/json" \
  -d '{}'
```

### DELETE /cache/clear

Clear cache using query parameters.

**Example:**
```bash
# Clear specific domains
curl -X DELETE "http://localhost:5000/cache/clear?domains=example.com,google.com"

# Clear all cache
curl -X DELETE http://localhost:5000/cache/clear
```

## Output Format

The script outputs a JSON array with comprehensive domain information:

```json
[
    {
        "domain": "example.com",
        "input": "example.com",
        "request_sent_datetime": "2026-01-05 12:00:00",
        "ssl_expiry_date": "2026-08-13 23:59:59",
        "ssl_days_left": 220,
        "ssl_status": "OK",
        "ssl_error": null,
        "health_status": "UP",
        "response_time_ms": 145.23,
        "http_status_code": 200,
        "domain_expiry_date": "2027-05-15 12:00:00",
        "domain_days_left": 450,
        "domain_error": null,
        "website_logo": "https://example.com/favicon.ico"
    },
    {
        "domain": "google.com",
        "input": "google.com",
        "request_sent_datetime": "2026-01-05 12:00:00",
        "ssl_expiry_date": "2025-12-01 23:59:59",
        "ssl_days_left": 60,
        "ssl_status": "EXPIRING",
        "ssl_error": null,
        "health_status": "UP",
        "response_time_ms": 89.45,
        "http_status_code": 200,
        "domain_expiry_date": "2028-09-14 04:00:00",
        "domain_days_left": 1200,
        "domain_error": null,
        "website_logo": "https://www.google.com/images/branding/googleg/1x/googleg_standard_color_128dp.png"
    }
]
```

### Output Fields

- `domain`: The domain name being checked (main domain, not subdomain)
- `input`: Original user input (preserved as-is, can be full URL)
- `request_sent_datetime`: Timestamp when the request was sent (YYYY-MM-DD HH:MM:SS UTC)
- `ssl_expiry_date`: SSL certificate expiry date in YYYY-MM-DD HH:MM:SS format (UTC)
- `ssl_days_left`: Number of days until SSL certificate expires
- `ssl_status`: SSL certificate status (`OK`, `EXPIRING`, `EXPIRED`, `DNS_ERROR`, `SSL_ERROR`, `SITE_DOWN`, or `ERROR`)
- `ssl_error`: SSL error message (if any)
- `health_status`: Domain health status (`UP`, `DOWN`, or `UNKNOWN`)
- `response_time_ms`: HTTP/HTTPS response time in milliseconds
- `http_status_code`: HTTP status code (e.g., 200, 404, 500)
- `domain_expiry_date`: Domain registration expiry date in YYYY-MM-DD HH:MM:SS format (UTC) - if available
- `domain_days_left`: Number of days until domain registration expires - if available
- `domain_error`: Domain expiry error message (if any)
- `website_logo`: URL of the website logo/favicon (if found)

**Note**: All fields are always present in the response. If data is unavailable, fields will be `null`.

### Error Handling

If an error occurs for a specific check, the output will include error messages for that check while still providing other available information:

```json
[
    {
        "domain": "invalid-domain.example",
        "input": "invalid-domain.example",
        "request_sent_datetime": "2026-01-05 12:00:00",
        "ssl_expiry_date": null,
        "ssl_days_left": null,
        "ssl_status": "DNS_ERROR",
        "ssl_error": "DNS resolution failed: [Errno -2] Name or service not known",
        "health_status": "DOWN",
        "response_time_ms": null,
        "http_status_code": null,
        "domain_expiry_date": null,
        "domain_days_left": null,
        "domain_error": "WHOIS data not available for this domain",
        "website_logo": null
    }
]
```

Note: Each check (SSL, health, domain expiry, logo) is independent, so if one fails, others may still succeed.

## Status Values

### SSL Status
- `OK`: Certificate is valid and has more than 30 days until expiration
- `EXPIRING`: Certificate expires within 30 days
- `EXPIRED`: Certificate has already expired
- `DNS_ERROR`: DNS resolution failed
- `SSL_ERROR`: SSL handshake failed
- `SITE_DOWN`: Connection timeout - site appears to be down
- `ERROR`: Unexpected SSL error

### Health Status
- `UP`: Domain is reachable and responding (HTTP status 200-499)
- `DOWN`: Domain is not reachable or not responding properly
- `UNKNOWN`: Health check could not be determined

## Requirements

- Docker
- Python 3.11+ (included in the image)
- `whois` command-line tool (included in the image)
- Internet connection (to check SSL certificates, domain expiry, and health status)

## Caching Behavior

The script implements intelligent caching to reduce API calls and improve performance:

### Unified Cache Strategy

All checks (SSL, domain expiry, and logos) are cached for **1 hour** by default.

1. **First Check**: Always performs real checks
2. **Subsequent Checks**: 
   - Uses cache if last check was **< 1 hour ago**
   - Refreshes cache if last check was **>= 1 hour ago**
3. **Force Refresh**: Use `force=true` parameter to bypass cache

### Domain Expiry Cache Sharing

- All subdomains share the same domain expiry cache
- Example: Checking `pro.example.com` uses cached expiry from `example.com`
- Reduces WHOIS queries significantly

### Cache Location

- Default: `/tmp/ssl-checker-cache`
- Use volume mounts to persist cache across container runs

### Benefits

- **Fast responses** for cached results
- **Reduced load** on WHOIS servers and target domains
- **Shared caching** across subdomains reduces redundant WHOIS lookups
- **Configurable refresh** via `force` parameter

## Retry Logic

The API supports separate retry configuration for each check type:

- **HTTP Retries** (`http_retries`): Retries for HTTP/health checks (default: 1, range: 0-10)
- **SSL Retries** (`ssl_retries`): Retries for SSL certificate checks (default: 1, range: 0-10)
- **Domain Retries** (`domain_retries`): Retries for domain expiry (WHOIS) checks (default: 1, range: 0-10)

Retries are only performed for transient failures (timeouts, connection errors). Permanent errors (rate limits, not found) are not retried.

## Full URL Support

The API supports full URLs with paths and query parameters:

- **SSL Check**: Extracts subdomain from URL (e.g., `pro.example.com` from `https://pro.example.com/path?query=value`)
- **Domain Expiry Check**: Extracts main domain from URL (e.g., `example.com` from `https://pro.example.com/path`)
- **Health Check**: Uses full URL if provided

**Example:**
```bash
curl "http://localhost:5000/check?domains=https://pro.example.com/api/v1/users?page=1"
```

## WHOIS Robustness

The domain expiry check includes multiple fallback mechanisms:

1. **Standard WHOIS**: Initial query using system `whois` command
2. **Referral Following**: Automatically follows WHOIS server referrals
3. **TLD-Specific Fallback**: Uses known TLD-specific WHOIS servers when default lookup fails
4. **RDAP Fallback**: Uses Registration Data Access Protocol (RDAP) when WHOIS fails

This ensures maximum reliability for domain expiry information retrieval.

## Website Logo Extraction

The API automatically extracts website logos by checking:

1. Apple Touch Icon (`<link rel="apple-touch-icon">`)
2. Favicon (`<link rel="icon">` or `<link rel="shortcut icon">`)
3. Open Graph Image (`<meta property="og:image">`)
4. Twitter Image (`<meta name="twitter:image">`)
5. Image tags with logo-related classes/IDs
6. Default `/favicon.ico` path

Logos are cached for 1 hour along with other checks.

## Example Output

```bash
$ docker run --rm bewithdhanu/domain-checker example.com google.com

[
  {
    "domain": "example.com",
    "input": "example.com",
    "request_sent_datetime": "2026-01-05 12:00:00",
    "ssl_expiry_date": "2026-08-13 23:59:59",
    "ssl_days_left": 220,
    "ssl_status": "OK",
    "ssl_error": null,
    "health_status": "UP",
    "response_time_ms": 145.23,
    "http_status_code": 200,
    "domain_expiry_date": "2027-05-15 12:00:00",
    "domain_days_left": 450,
    "domain_error": null,
    "website_logo": "https://example.com/favicon.ico"
  },
  {
    "domain": "google.com",
    "input": "google.com",
    "request_sent_datetime": "2026-01-05 12:00:00",
    "ssl_expiry_date": "2025-12-01 23:59:59",
    "ssl_days_left": 60,
    "ssl_status": "EXPIRING",
    "ssl_error": null,
    "health_status": "UP",
    "response_time_ms": 89.45,
    "http_status_code": 200,
    "domain_expiry_date": "2028-09-14 04:00:00",
    "domain_days_left": 1200,
    "domain_error": null,
    "website_logo": "https://www.google.com/images/branding/googleg/1x/googleg_standard_color_128dp.png"
  }
]
```

## Notes

- **Domain Expiry**: Domain expiry information is retrieved via WHOIS lookup with referral following and RDAP fallback. Some domains may not provide this information, or it may be rate-limited by WHOIS servers.
- **Health Check**: The health check tries HTTPS first, then falls back to HTTP if HTTPS fails. SSL verification is disabled for health checks.
- **Response Time**: Measured from connection initiation to first byte received.
- **Timezone**: All dates are in UTC timezone.
- **Cache**: Cache is ephemeral by default (lost when container stops). Use volumes for persistence.
- **API**: Built with FastAPI, providing automatic OpenAPI/Swagger documentation at `/docs`.
- **Full URLs**: Supports full URLs with paths and query parameters. SSL checks use subdomain, domain expiry checks use main domain.

## Technology Stack

- **Framework**: FastAPI (Python web framework)
- **Server**: Uvicorn (ASGI server)
- **Documentation**: Built-in Swagger UI and ReDoc
- **Python**: 3.11+
- **Dependencies**: FastAPI, Uvicorn, Python standard library

## License

This project is open source and available for use.
