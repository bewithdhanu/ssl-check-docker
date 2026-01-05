# Domain Checker Docker Image

A Docker image that checks SSL certificate expiry dates, domain expiry, health status, and response time for one or more domains. Available as both a CLI tool and a REST API web service.

## Features

- **SSL Certificate Check**: Check SSL certificate expiry dates for single or multiple domains
- **Domain Expiry Check**: Check domain registration expiry dates using WHOIS
- **Health Check**: Verify if domains are reachable (UP/DOWN status)
- **Response Time**: Measure HTTP/HTTPS response time in milliseconds
- **Smart Caching**: Reduces API calls by caching results for both SSL and domain expiry
  - **SSL Certificate Caching**: 
    - Uses cache if SSL certificate expires in >= 2 days
    - Refreshes cache only when SSL expires in < 2 days AND last check was >= 1 hour ago
  - **Domain Expiry Caching**:
    - Uses cache if domain expires in >= 2 days
    - Refreshes cache only when domain expires in < 2 days AND last check was >= 1 hour ago
  - Significantly improves performance for repeated checks
  - Domain expiry cache is shared across all subdomains (e.g., `pro.example.com` uses cached expiry from `example.com`)
- Returns expiry dates in YYYY-MM-DD HH:MM:SS format (UTC)
- Calculates days until expiration for both SSL certificates and domain registrations
- Status indicators: `OK` (valid), `EXPIRING` (within 30 days), or `EXPIRED`
- Handles errors gracefully
- Supports command-line arguments or environment variables

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

# Check domain
curl "http://localhost:5000/check?domains=example.com"

# Check multiple domains (POST)
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "google.com"]}'
```

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

## Output Format

The script outputs a JSON array with comprehensive domain information:

```json
[
    {
        "domain": "example.com",
        "ssl_expiry_date": "2026-08-13 23:59:59",
        "ssl_days_left": 220,
        "ssl_status": "OK",
        "health_status": "UP",
        "response_time_ms": 145.23,
        "domain_expiry_date": "2027-05-15 12:00:00",
        "domain_days_left": 450
    },
    {
        "domain": "google.com",
        "ssl_expiry_date": "2025-12-01 23:59:59",
        "ssl_days_left": 60,
        "ssl_status": "EXPIRING",
        "health_status": "UP",
        "response_time_ms": 89.45,
        "domain_expiry_date": "2028-09-14 04:00:00",
        "domain_days_left": 1200
    }
]
```

### Output Fields

- `domain`: The domain name being checked
- `ssl_expiry_date`: SSL certificate expiry date in YYYY-MM-DD HH:MM:SS format (UTC)
- `ssl_days_left`: Number of days until SSL certificate expires
- `ssl_status`: SSL certificate status (`OK`, `EXPIRING`, or `EXPIRED`)
- `health_status`: Domain health status (`UP`, `DOWN`, or `UNKNOWN`)
- `response_time_ms`: HTTP/HTTPS response time in milliseconds
- `domain_expiry_date`: Domain registration expiry date in YYYY-MM-DD HH:MM:SS format (UTC) - if available
- `domain_days_left`: Number of days until domain registration expires - if available

### Error Handling

If an error occurs for a specific check, the output will include error messages for that check while still providing other available information:

```json
[
    {
        "domain": "invalid-domain.example",
        "ssl_error": "DNS resolution failed: [Errno -2] Name or service not known",
        "health_status": "DOWN",
        "response_time_ms": null
    }
]
```

Note: Each check (SSL, health, domain expiry) is independent, so if one fails, others may still succeed.

## Status Values

### SSL Status
- `OK`: Certificate is valid and has more than 30 days until expiration
- `EXPIRING`: Certificate expires within 30 days
- `EXPIRED`: Certificate has already expired

### Health Status
- `UP`: Domain is reachable and responding (HTTP status 200-499)
- `DOWN`: Domain is not reachable or not responding properly
- `UNKNOWN`: Health check could not be determined

## Requirements

- Docker
- Python 3.11+ (included in the image)
- `whois` command-line tool (included in the image)
- Internet connection (to check SSL certificates, domain expiry, and health status)

## Example Output

```bash
$ docker run --rm bewithdhanu/domain-checker example.com google.com

[
  {
    "domain": "example.com",
    "ssl_expiry_date": "2026-08-13 23:59:59",
    "ssl_days_left": 220,
    "ssl_status": "OK",
    "health_status": "UP",
    "response_time_ms": 145.23,
    "domain_expiry_date": "2027-05-15 12:00:00",
    "domain_days_left": 450
  },
  {
    "domain": "google.com",
    "ssl_expiry_date": "2025-12-01 23:59:59",
    "ssl_days_left": 60,
    "ssl_status": "EXPIRING",
    "health_status": "UP",
    "response_time_ms": 89.45
  }
]
```

## Caching Behavior

The script implements intelligent caching to reduce API calls and improve performance for both SSL certificates and domain expiry:

### SSL Certificate Caching

1. **First Check**: Always performs real SSL certificate check
2. **Subsequent Checks**:
   - If SSL certificate expires in **>= 2 days**: Uses cached result (no SSL checks)
   - If SSL certificate expires in **< 2 days**: 
     - Uses cache if last check was **< 1 hour ago**
     - Refreshes cache if last check was **>= 1 hour ago**

### Domain Expiry Caching

1. **First Check**: Always performs real WHOIS lookup for main domain
2. **Subsequent Checks**:
   - If domain expires in **>= 2 days**: Uses cached result (no WHOIS calls)
   - If domain expires in **< 2 days**: 
     - Uses cache if last check was **< 1 hour ago**
     - Refreshes cache if last check was **>= 1 hour ago**
3. **Subdomain Sharing**: All subdomains share the same domain expiry cache
   - Example: Checking `pro.example.com` uses cached expiry from `example.com`
   - Reduces WHOIS queries significantly

### Benefits

- **Fast responses** for stable certificates and domains
- **Regular updates** for certificates/domains nearing expiration
- **Reduced load** on WHOIS servers and target domains
- **Shared caching** across subdomains reduces redundant WHOIS lookups

**Note**: Cache is stored in `/tmp/ssl-checker-cache` by default. Use volume mounts to persist cache across container runs.

## Notes

- **Domain Expiry**: Domain expiry information is retrieved via WHOIS lookup. Some domains may not provide this information, or it may be rate-limited by WHOIS servers.
- **Health Check**: The health check tries HTTPS first, then falls back to HTTP if HTTPS fails.
- **Response Time**: Measured from connection initiation to first byte received.
- **Timezone**: All dates are in UTC timezone.
- **Cache**: Cache is ephemeral by default (lost when container stops). Use volumes for persistence.

