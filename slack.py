#!/usr/bin/env python3
"""
Slack Notifier for CVE Checker

This script sends vulnerability findings to a Slack channel using a bot token.
It only sends notifications when vulnerabilities are actually found.

Usage:
    Import this in your cve_checker.py or call it directly:
    python slack_notifier.py --json results.json --token XOXB_BOT_TOKEN --channel CVE-reports
"""

import argparse
import datetime
import json
import os
import sys
import requests
from typing import Dict, List, Optional


class SlackNotifier:
    """Class to send vulnerability findings to Slack"""
    
    def __init__(self):
        """Initialize the Slack notifier with token and channel ID from .env"""
        # Only load from .env or environment variables, not from parameters
        self.token = os.environ.get('SLACK_BOT_TOKEN')
        self.channel_id = os.environ.get('SLACK_CHANNEL_ID')
        self.api_url = "https://slack.com/api/chat.postMessage"
        
        # Don't print warnings - we'll handle this in the notification method
    
    def load_vulnerabilities_from_file(self, json_file: str) -> List[Dict]:
        """Load vulnerability data from a JSON file"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                
                # Handle both direct list of vulnerabilities and the report structure
                if isinstance(data, dict) and 'vulnerabilities' in data:
                    return data['vulnerabilities'], data.get('metadata', {})
                elif isinstance(data, list):
                    return data, {}
                else:
                    print(f"⚠️ Error: Unexpected JSON format in {json_file}")
                    return [], {}
        except Exception as e:
            print(f"⚠️ Error loading JSON file: {e}")
            return [], {}
    
    def format_slack_message(self, vulnerabilities: List[Dict], metadata: Optional[Dict] = None) -> Dict:
        """Format vulnerabilities into a Slack message"""
        if not vulnerabilities:
            return None  # No message to send
        
        # Add a header with summary information
        blocks = []
        
        # Header block
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        header_text = f"🚨 *CVE ALERT: {len(vulnerabilities)} new vulnerabilities detected* 🚨"
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": header_text,
                "emoji": True
            }
        })
        
        # Add metadata if available
        if metadata:
            metadata_fields = []
            
            # Add timestamp
            generated_at = metadata.get('generated_at', current_time)
            metadata_fields.append({
                "type": "mrkdwn",
                "text": f"*Generated:* {generated_at}"
            })
            
            # Add sources
            cisa_matches = metadata.get('cisa_matches', 0)
            nvd_matches = metadata.get('nvd_matches', 0)
            if(cisa_matches > 0) and (nvd_matches > 0):
                metadata_fields.append({
                    "type": "mrkdwn",
                    "text": f"*Sources:* CISA KEV ({cisa_matches}), NVD ({nvd_matches})"
                })
            elif (cisa_matches > 0) and (nvd_matches == 0):
                metadata_fields.append({
                    "type": "mrkdwn",
                    "text": f"*Sources:* CISA KEV"
                })
            elif (cisa_matches == 0) and (nvd_matches > 0):
                metadata_fields.append({
                    "type": "mrkdwn",
                    "text": f"*Sources:* NVD ({nvd_matches})"
                })
            else:
                metadata_fields.append({
                    "type": "mrkdwn",
                    "text": f"*Sources:* Unknown"
                })
            
            # Add severity breakdown if available
            if 'severity_breakdown' in metadata:
                sev = metadata['severity_breakdown']
                breakdown = f"*Severity:* "
                if sev.get('critical', 0) > 0:
                    breakdown += f"🔴 Critical: {sev['critical']} "
                if sev.get('high', 0) > 0:
                    breakdown += f"🟠 High: {sev['high']} "
                if sev.get('medium', 0) > 0:
                    breakdown += f"🟡 Medium: {sev['medium']} "
                if sev.get('low', 0) > 0:
                    breakdown += f"🟢 Low: {sev['low']} "
                
                metadata_fields.append({
                    "type": "mrkdwn",
                    "text": breakdown
                })
            
            # Add fields section
            blocks.append({
                "type": "section",
                "fields": metadata_fields
            })
        
        # Add divider
        blocks.append({"type": "divider"})
        
        # Group vulnerabilities by severity for better organization
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'UNKNOWN': '⚪'
        }
        
        # Sort vulnerabilities by severity and then by CVE ID
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: (
                severity_order.index(x.get('severity', 'UNKNOWN')),
                x.get('cve_id', '')
            )
        )
        
        # Add only the most important vulnerabilities to avoid message size limits
        # Focus on Critical and High severity - Slack has message size limits
        critical_high_vulns = [v for v in sorted_vulns if v.get('severity') in ['CRITICAL', 'HIGH']]
        remaining_vulns = [v for v in sorted_vulns if v.get('severity') not in ['CRITICAL', 'HIGH']]
        
        # Limit to top 15 vulns max to avoid message size limits
        vulns_to_show = critical_high_vulns[:10]
        if len(vulns_to_show) < 10:
            vulns_to_show += remaining_vulns[:10 - len(vulns_to_show)]
        
        # Add each vulnerability as a section
        for vuln in vulns_to_show:
            cve_id = vuln.get('cve_id', 'N/A')
            severity = vuln.get('severity', 'UNKNOWN')
            vendor = vuln.get('vendor', 'Unknown')
            product = vuln.get('product', 'Unknown')
            description = vuln.get('description', 'No description available')
            
            # Truncate description if too long
            if len(description) > 300:
                description = description[:297] + "..."
            
            # Get CVSS score if available
            cvss_info = ""
            if vuln.get('cvss_score', 'N/A') != 'N/A':
                cvss_info = f" (CVSS: {vuln.get('cvss_score')})"
            
            # Construct the text with emojis for severity
            emoji = severity_emoji.get(severity, '⚪')
            title = f"*{emoji} {cve_id}* - {severity}{cvss_info}"
            
            # Add ransomware indicator if applicable
            if vuln.get('ransomware_use', False):
                title += " ⚠️ *RANSOMWARE*"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{title}\n*Affects:* {vendor} {product}\n{description}"
                }
            })
        
        # If we had to truncate vulnerabilities, add a note
        if len(sorted_vulns) > len(vulns_to_show):
            remaining_count = len(sorted_vulns) - len(vulns_to_show)
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*+{remaining_count} more vulnerabilities not shown.* Check the full report for details."
                    }
                ]
            })
        
        # Add call to action
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Run `python cve_checker.py` with appropriate parameters for full details."
                }
            ]
        })
        
        return {
            "blocks": blocks
        }
    
    def send_notification(self, message_payload: Dict) -> bool:
        """Send the notification to Slack using the bot token"""
        if not self.token or not self.channel_id or not message_payload:
            print("⚠️ Cannot send notification: Missing token, channel ID, or message content.")
            if not self.token:
                print("   - SLACK_BOT_TOKEN is not set in .env file or environment")
            if not self.channel_id:
                print("   - SLACK_CHANNEL_ID is not set in .env file or environment")
            return False
        
        try:
            # Add the channel to the payload
            payload = {
                "channel": self.channel_id,
                "blocks": message_payload.get("blocks", []),
                "text": "CVE Alert: New vulnerabilities detected" # Fallback text
            }
            
            # Send the message using the Slack API
            response = requests.post(
                self.api_url,
                json=payload,
                headers={
                    'Content-Type': 'application/json; charset=utf-8',
                    'Authorization': f'Bearer {self.token}'
                }
            )
            
            response_data = response.json()
            
            if response.status_code == 200 and response_data.get('ok'):
                print(f"✅ Successfully sent notification to Slack channel ID '{self.channel_id}'")
                return True
            else:
                error = response_data.get('error', 'Unknown error')
                print(f"⚠️ Failed to send notification to Slack: {error}")
                return False
        except Exception as e:
            print(f"⚠️ Error sending notification to Slack: {e}")
            return False
    
    def notify_if_vulnerabilities(self, vulnerabilities: List[Dict], metadata: Optional[Dict] = None) -> bool:
        """Check if there are vulnerabilities and notify if needed"""
        if not vulnerabilities:
            print("ℹ️ No vulnerabilities found. No notification sent.")
            return False
        
        message = self.format_slack_message(vulnerabilities, metadata)
        success = self.send_notification(message)
        
        if not success:
            print("⚠️ Failed to send notification to Slack. Please check your .env file for SLACK_BOT_TOKEN and SLACK_CHANNEL_ID.")
        
        return success


def main():
    """Main function to run the notifier directly with data from .env file"""
    parser = argparse.ArgumentParser(
        description='Send vulnerability findings to Slack channel',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python slack_notifier.py --json results.json
  (Credentials are only loaded from .env file or environment variables)
"""
    )
    
    # Required arguments
    parser.add_argument('--json', type=str, required=True,
                        help='JSON file with vulnerability data')
    
    args = parser.parse_args()
    
    # Create notifier (will only use .env or environment variables)
    notifier = SlackNotifier()
    
    # Load vulnerabilities and notify if needed
    vulns, metadata = notifier.load_vulnerabilities_from_file(args.json)
    result = notifier.notify_if_vulnerabilities(vulns, metadata)
    
    # Exit with appropriate code for automation purposes
    sys.exit(0 if result else 1)


if __name__ == "__main__":
    main()