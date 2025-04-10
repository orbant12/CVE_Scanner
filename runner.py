#!/usr/bin/env python3
"""
CVE Slack Runner

This script automatically runs the CVE scanner and notifies Slack if vulnerabilities are found.
It uses the .env file for all configuration and is designed to be run from cron or a scheduler.

The .env file should contain:
- SLACK_BOT_TOKEN - the Slack bot token
- SLACK_CHANNEL_ID - the Slack channel ID
- NVD_API_KEY (optional) - the NVD API key

Usage:
    python cve_slack_runner.py [--timeframe TODAY|THIS WEEK|THIS MONTH]

Example:
    python cve_slack_runner.py --timeframe "THIS WEEK"
    python cve_slack_runner.py --timeframe "THIS MONTH"
"""

import os
import sys
import json
import tempfile
import datetime
import argparse
from pathlib import Path

# Import your CVE checker (update the import path as needed)
from cve_checker import CVEChecker

# Import the Slack notifier
from slack import SlackNotifier

def load_env_file():
    """Load environment variables from .env file"""
    env_file = Path(__file__).parent / '.env'
    if env_file.exists():
        print(f"Loading environment from {env_file}")
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split('=', 1)
                if len(parts) == 2:
                    key, value = parts[0].strip(), parts[1].strip()
                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    
                    # Set environment variable
                    os.environ[key] = value
    else:
        print(f"No .env file found at {env_file}")

def load_vendor_products():
    """Load vendor-product pairs from vendors.json"""
    vendor_file = Path(__file__).parent / 'vendors.json'
    if not vendor_file.exists():
        print(f"Error: vendors.json not found at {vendor_file}")
        return []
    
    try:
        with open(vendor_file, 'r') as f:
            data = json.load(f)
            
        vendor_products = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'vendor' in item and 'product' in item:
                    vendor_products.append((item['vendor'].strip(), item['product'].strip()))
        
        return vendor_products
    except Exception as e:
        print(f"Error loading vendors.json: {e}")
        return []

def main():
    """Main function to run the CVE scanner and notify Slack"""
    # Set up command line argument parser
    parser = argparse.ArgumentParser(
        description='Scan for CVEs and notify Slack if vulnerabilities are found',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cve_slack_runner.py --timeframe "TODAY"
  python cve_slack_runner.py --timeframe "THIS WEEK"
  python cve_slack_runner.py --timeframe "THIS MONTH"
"""
    )
    
    # Define timeframe argument
    parser.add_argument('--timeframe', type=str, choices=['TODAY', 'THIS WEEK', 'THIS MONTH'], 
                       default='TODAY', help='Timeframe to check for vulnerabilities')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Load environment variables from .env file
    load_env_file()
    
    # Check if required environment variables are set
    slack_token = os.environ.get('SLACK_BOT_TOKEN')
    slack_channel_id = os.environ.get('SLACK_CHANNEL_ID')
    
    if not slack_token or not slack_channel_id:
        print("Error: SLACK_BOT_TOKEN and SLACK_CHANNEL_ID must be set in .env file")
        print(f"  SLACK_BOT_TOKEN: {'Set' if slack_token else 'Missing'}")
        print(f"  SLACK_CHANNEL_ID: {'Set' if slack_channel_id else 'Missing'}")
        sys.exit(1)
    
    # Load vendor-product pairs
    vendor_products = load_vendor_products()
    if not vendor_products:
        print("Error: No vendor-product pairs found in vendors.json")
        sys.exit(1)
    
    # Get the timeframe
    timeframe = args.timeframe
    
    print(f"Scanning {len(vendor_products)} vendor-product pairs for vulnerabilities from {timeframe}...")
    
    # Create CVE checker instance
    checker = CVEChecker()
    
    # Search for vulnerabilities
    vulnerabilities = checker.search_vulnerabilities(
        vendor_products, 
        timeframe
    )
    
    # Display results in the terminal
    checker.display_results(vulnerabilities)
    
    # Only notify if there are vulnerabilities
    if vulnerabilities:
        # Create a temporary file to store the results
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            # Create a report structure with metadata and results
            report = {
                "metadata": {
                    "generated_at": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "total_vulnerabilities": len(vulnerabilities),
                    "cisa_matches": checker.stats.get('cisa_matches', 0),
                    "nvd_matches": checker.stats.get('nvd_matches', 0),
                    "severity_breakdown": {
                        "critical": checker.stats.get('critical_count', 0),
                        "high": checker.stats.get('high_count', 0),
                        "medium": checker.stats.get('medium_count', 0),
                        "low": checker.stats.get('low_count', 0),
                        "unknown": checker.stats.get('unknown_count', 0)
                    }
                },
                "vulnerabilities": vulnerabilities
            }
            
            # Write the report to the temp file
            json.dump(report, temp_file, indent=2)
            temp_file_name = temp_file.name
        
        try:
            # Create Slack notifier (uses .env for credentials)
            notifier = SlackNotifier()
            
            # Send notification
            success = notifier.notify_if_vulnerabilities(vulnerabilities, report["metadata"])
            
            if success:
                print(f"\nSuccessfully sent notification to Slack")
            else:
                print(f"\nFailed to send notification to Slack. Check your .env file.")
        except Exception as e:
            print(f"Error sending Slack notification: {e}")
        finally:
            # Remove the temporary file
            os.unlink(temp_file_name)
    else:
        print(f"\nNo vulnerabilities found. No Slack notification sent.")
    
    # Return success code
    return 0

if __name__ == "__main__":
    sys.exit(main())