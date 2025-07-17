#!/bin/bash

# CVE Scanner Docker Build and Run Script
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🐳 CVE Scanner Docker Setup${NC}"
echo "================================"

# Check if .env file exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚠️  .env file not found. Creating from template...${NC}"
    if [ -f ".env.template" ]; then
        cp .env.template .env
        echo -e "${RED}❌ Please edit .env file with your actual API keys and tokens before running!${NC}"
        exit 1
    else
        echo -e "${RED}❌ .env.template not found. Please create a .env file manually.${NC}"
        exit 1
    fi
fi

# Validate .env file has required variables
echo -e "${BLUE}🔍 Validating environment configuration...${NC}"
source .env

if [ -z "$SLACK_BOT_TOKEN" ] || [ "$SLACK_BOT_TOKEN" = "xoxb-your-slack-bot-token-here" ]; then
    echo -e "${RED}❌ SLACK_BOT_TOKEN not configured in .env file${NC}"
    exit 1
fi

if [ -z "$SLACK_CHANNEL_ID" ] || [ "$SLACK_CHANNEL_ID" = "C1234567890" ]; then
    echo -e "${RED}❌ SLACK_CHANNEL_ID not configured in .env file${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Environment configuration validated${NC}"

# Create reports directory
mkdir -p reports

# Build Docker image
echo -e "${BLUE}🔨 Building Docker image...${NC}"
docker build -t cve-scanner .

echo -e "${GREEN}✅ Docker image built successfully${NC}"

# Function to run different scanner modes
run_scanner() {
    local timeframe=$1
    local extra_args=$2
    
    echo -e "${BLUE}🚀 Running CVE scanner with timeframe: ${timeframe}${NC}"
    docker run --rm \
        --env-file .env \
        -v "$(pwd)/reports:/app/reports" \
        cve-scanner \
        python runner.py --timeframe "$timeframe" $extra_args
}

# Function to run one-time scan
run_oneshot() {
    echo -e "${BLUE}📋 Available timeframe options:${NC}"
    echo "1) TODAY"
    echo "2) THIS WEEK" 
    echo "3) THIS MONTH"
    echo ""
    read -p "Select timeframe (1-3): " choice
    
    case $choice in
        1) run_scanner "TODAY" ;;
        2) run_scanner "THIS WEEK" ;;
        3) run_scanner "THIS MONTH" ;;
        *) echo -e "${RED}❌ Invalid choice${NC}"; exit 1 ;;
    esac
}

# Function to test Slack authentication
test_slack() {
    echo -e "${BLUE}🧪 Testing Slack authentication...${NC}"
    docker run --rm \
        --env-file .env \
        cve-scanner \
        python slack_auth.py --token "$SLACK_BOT_TOKEN" --channel-id "$SLACK_CHANNEL_ID" --send-test
}

# Function to delete last Slack message
delete_last_message() {
    echo -e "${BLUE}🗑️  Deleting last Slack message...${NC}"
    docker run --rm \
        --env-file .env \
        -v "$(pwd)/reports:/app/reports" \
        cve-scanner \
        python runner.py --delete-last-message
}

# Function to start scheduled services
start_scheduled() {
    echo -e "${BLUE}⏰ Starting scheduled CVE scanner services...${NC}"
    echo "This will start:"
    echo "  - Daily scanner (runs every 24 hours)"
    echo "  - Weekly scanner (runs every 7 days, optional)"
    echo ""
    read -p "Include weekly scanner? (y/N): " include_weekly
    
    if [[ $include_weekly =~ ^[Yy]$ ]]; then
        docker-compose --profile weekly up -d
    else
        docker-compose up -d cve-scanner-daily
    fi
    
    echo -e "${GREEN}✅ Scheduled services started${NC}"
    echo "Use 'docker-compose logs -f' to view logs"
    echo "Use 'docker-compose down' to stop services"
}

# Function to clean up Docker resources
cleanup() {
    echo -e "${BLUE}🧹 Cleaning up Docker resources...${NC}"
    docker-compose down
    docker rmi cve-scanner 2>/dev/null || true
    echo -e "${GREEN}✅ Cleanup completed${NC}"
}

# Main menu
echo -e "${BLUE}📋 What would you like to do?${NC}"
echo "1) Run one-time CVE scan"
echo "2) Test Slack authentication"
echo "3) Delete last Slack message"
echo "4) Start scheduled scanning services"
echo "5) View running containers"
echo "6) Stop scheduled services"
echo "7) Cleanup Docker resources"
echo "8) Exit"
echo ""

read -p "Select option (1-8): " option

case $option in
    1) run_oneshot ;;
    2) test_slack ;;
    3) delete_last_message ;;
    4) start_scheduled ;;
    5) docker-compose ps ;;
    6) docker-compose down ;;
    7) cleanup ;;
    8) echo -e "${GREEN}👋 Goodbye!${NC}"; exit 0 ;;
    *) echo -e "${RED}❌ Invalid option${NC}"; exit 1 ;;
esac