# CVE Scanner Docker Setup

This guide explains how to containerize and run the CVE Scanner application using Docker.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose v2.0+
- Valid Slack Bot Token and Channel ID
- (Optional) NVD API Key for higher rate limits

## Quick Start

1. **Clone/Copy all files to your directory:**
   ```bash
   # Ensure you have all these files:
   # - Dockerfile
   # - docker-compose.yml
   # - .env.template
   # - .dockerignore
   # - build-and-run.sh
   # - All Python files (*.py)
   # - vendors.json
   # - requirements.txt
   ```

2. **Set up environment variables:**
   ```bash
   cp .env.template .env
   # Edit .env with your actual credentials
   ```

3. **Make the build script executable and run:**
   ```bash
   chmod +x build-and-run.sh
   ./build-and-run.sh
   ```

## Manual Setup

### 1. Configure Environment Variables

Create a `.env` file with your credentials:

```bash
# Required
SLACK_BOT_TOKEN=xoxb-your-actual-bot-token
SLACK_CHANNEL_ID=C1234567890

# Optional (for higher API rate limits)
NVD_API_KEY=your-nvd-api-key
```

### 2. Build the Docker Image

```bash
docker build -t cve-scanner .
```

### 3. Run Options

#### One-time Scan
```bash
# Today's vulnerabilities
docker run --rm --env-file .env cve-scanner python runner.py --timeframe TODAY

# This week's vulnerabilities  
docker run --rm --env-file .env cve-scanner python runner.py --timeframe "THIS WEEK"

# This month's vulnerabilities
docker run --rm --env-file .env cve-scanner python runner.py --timeframe "THIS MONTH"
```

#### Test Slack Integration
```bash
docker run --rm --env-file .env cve-scanner \
  python slack_auth.py --token $SLACK_BOT_TOKEN --channel-id $SLACK_CHANNEL_ID --send-test
```

#### Scheduled Scanning with Docker Compose
```bash
# Start daily scanner
docker-compose up -d cve-scanner-daily

# Start both daily and weekly scanners
docker-compose --profile weekly up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Docker Compose Services

The `docker-compose.yml` defines several services:

- **cve-scanner**: Base service for manual runs
- **cve-scanner-daily**: Runs every 24 hours checking TODAY's vulnerabilities
- **cve-scanner-weekly**: Runs every 7 days checking THIS WEEK's vulnerabilities (optional)

## File Structure

```
cve-scanner/
├── Dockerfile              # Container definition
├── docker-compose.yml      # Multi-container orchestration
├── .env                    # Environment variables (create from template)
├── .env.template           # Template for environment variables
├── .dockerignore           # Files to exclude from Docker build
├── build-and-run.sh        # Automated build and run script
├── requirements.txt        # Python dependencies
├── vendors.json            # Vendor/product definitions
├── *.py                    # Python application files
├── reports/                # Volume mount for reports (created automatically)
└── README-Docker.md        # This file
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SLACK_BOT_TOKEN` | Yes | Slack bot token (starts with `xoxb-`) |
| `SLACK_CHANNEL_ID` | Yes | Slack channel ID (starts with `C`) |
| `NVD_API_KEY` | No | NVD API key for higher rate limits |

## Volumes

- `./reports:/app/reports` - Mount local `reports/` directory for persistent storage of scan results

## Networking

- All services use the `cve-scanner-network` network
- No ports are exposed as this is a batch processing application

## Troubleshooting

### 1. Permission Denied Errors
```bash
# Make sure the build script is executable
chmod +x build-and-run.sh
```

### 2. Environment Variables Not Set
```bash
# Check your .env file exists and has correct values
cat .env

# Validate environment variables
source .env
echo $SLACK_BOT_TOKEN
echo $SLACK_CHANNEL_ID
```

### 3. Slack Authentication Issues
```bash
# Test Slack connectivity
docker run --rm --env-file .env cve-scanner \
  python slack_auth.py --token $SLACK_BOT_TOKEN --list-channels
```

### 4. NVD Rate Limiting
If you see rate limiting errors:
- Get an NVD API key: https://nvd.nist.gov/developers/request-an-api-key
- Add it to your `.env` file
- Rebuild the container

### 5. View Container Logs
```bash
# For running containers
docker-compose logs -f

# For completed containers
docker logs cve-scanner
```

## Security Considerations

- The container runs as a non-root user (`cveuser`)
- Environment variables are loaded from `.env` file (not hardcoded)
- `.env` file is excluded from Docker build context via `.dockerignore`
- Only necessary files are copied into the container

## Customization

### Modify Scan Schedule
Edit `docker-compose.yml` to change the scanning frequency:

```yaml
# Change sleep duration (in seconds)
# 86400 = 24 hours
# 604800 = 7 days  
# 2592000 = 30 days
sleep 86400
```

### Add New Vendors/Products
Edit `vendors.json` and rebuild the container:

```bash
docker build -t cve-scanner .
```

### Custom Commands
Run any Python script in the container:

```bash
docker run --rm --env-file .env cve-scanner python cve_checker.py --help
```

## Production Deployment

For production deployments, consider:

1. **Use a container registry:**
   ```bash
   docker tag cve-scanner your-registry.com/cve-scanner:latest
   docker push your-registry.com/cve-scanner:latest
   ```

2. **Use Docker secrets instead of .env files**

3. **Set up proper logging and monitoring**

4. **Use restart policies:**
   ```yaml
   restart: unless-stopped
   ```

5. **Resource limits:**
   ```yaml
   deploy:
     resources:
       limits:
         memory: 512M
         cpus: '0.5'
   ```

## Support

For issues related to:
- **Docker setup**: Check this README and Docker logs
- **Application functionality**: Check the original Python application documentation
- **Slack integration**: Use the built-in `slack_auth.py` testing script