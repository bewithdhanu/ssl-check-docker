# Deploying Domain Checker to Coolify

This guide will help you deploy the Domain Checker as a web service on Coolify.

## Prerequisites

- Coolify instance running
- Docker Hub account (or use GitHub Container Registry)
- Domain/subdomain for your service (optional)

## Step 1: Build and Push Docker Image

The image is already available on Docker Hub:
```bash
docker pull bewithdhanu/domain-checker:latest
```

Or build and push your own:
```bash
docker build -t your-username/domain-checker:latest .
docker push your-username/domain-checker:latest
```

## Step 2: Deploy in Coolify

### Option A: Deploy from Docker Hub

1. **Create New Resource** in Coolify
   - Go to your Coolify dashboard
   - Click "New Resource" → "Docker Image"

2. **Configure the Service**
   - **Name**: `domain-checker` (or your preferred name)
   - **Docker Image**: `bewithdhanu/domain-checker:latest`
   - **Port**: `5000` (internal port)
   - **Public Port**: `80` or `443` (if you want public access)

3. **Environment Variables** (Optional)
   - `PORT=5000` (default, usually not needed)
   - `HOST=0.0.0.0` (default, usually not needed)
   - `CACHE_DIR=/app/cache` (if you want custom cache location)

4. **Volumes** (Optional - for persistent cache)
   - Mount path: `/tmp/ssl-checker-cache`
   - Volume name: `domain-checker-cache`

5. **Health Check**
   - Path: `/health`
   - Interval: `30s`

6. **Deploy**
   - Click "Deploy" and wait for the service to start

### Option B: Deploy from GitHub (with auto-deploy)

1. **Connect GitHub Repository**
   - In Coolify, go to "New Resource" → "GitHub Repository"
   - Connect your `ssl-check-docker` repository

2. **Configure Build**
   - **Build Pack**: Docker
   - **Dockerfile Path**: `Dockerfile`
   - **Port**: `5000`

3. **Configure Environment**
   - Same as Option A

4. **Enable Auto-Deploy**
   - Enable "Auto Deploy" to automatically rebuild on git push

## Step 3: Configure Domain (Optional)

1. **Add Domain in Coolify**
   - Go to your service settings
   - Add your domain/subdomain (e.g., `domain-checker.yourdomain.com`)

2. **SSL Certificate**
   - Coolify will automatically provision SSL via Let's Encrypt

## Step 4: Test the API

Once deployed, test the API:

### Health Check
```bash
curl https://your-domain.com/health
```

### Check Single Domain (GET)
```bash
curl "https://your-domain.com/check?domains=example.com"
```

### Check Multiple Domains (GET)
```bash
curl "https://your-domain.com/check?domains=example.com,google.com"
```

### Check Domains (POST)
```bash
curl -X POST https://your-domain.com/check \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "google.com"]}'
```

## API Endpoints

### `GET /`
Returns API documentation and usage examples.

### `GET /health`
Health check endpoint. Returns `{"status": "healthy", "service": "domain-checker"}`

### `POST /check`
Check domain(s) via POST request.

**Request Body:**
```json
{
  "domains": ["example.com", "google.com"]
}
```

**Response:**
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
  }
]
```

### `GET /check?domains=example.com,google.com`
Check domain(s) via GET request with comma-separated domains.

## Environment Variables

- `PORT`: Port for the web server (default: `5000`)
- `HOST`: Host to bind to (default: `0.0.0.0`)
- `CACHE_DIR`: Custom cache directory path (default: `/tmp/ssl-checker-cache`)

## Persistent Cache

To enable persistent cache across container restarts:

1. In Coolify, add a volume:
   - **Mount Path**: `/tmp/ssl-checker-cache`
   - **Volume Name**: `domain-checker-cache`

This will persist the cache even when the container restarts.

## Monitoring

- **Health Check**: Use `/health` endpoint for monitoring
- **Logs**: View logs in Coolify dashboard
- **Metrics**: Monitor response times and error rates

## Troubleshooting

### Service won't start
- Check logs in Coolify dashboard
- Verify port `5000` is exposed
- Check environment variables

### Cache not persisting
- Ensure volume is mounted at `/tmp/ssl-checker-cache`
- Check volume permissions

### API returns errors
- Check domain format (no `http://` or `https://` needed)
- Verify domains are reachable
- Check rate limits on WHOIS servers

## Example Integration

### JavaScript/TypeScript
```javascript
const response = await fetch('https://your-domain.com/check', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ domains: ['example.com', 'google.com'] })
});
const results = await response.json();
console.log(results);
```

### Python
```python
import requests

response = requests.post(
    'https://your-domain.com/check',
    json={'domains': ['example.com', 'google.com']}
)
results = response.json()
print(results)
```

### cURL
```bash
curl -X POST https://your-domain.com/check \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com"]}'
```

