#!/usr/bin/env python3
"""
Slack Authentication Example

This script demonstrates how to authenticate with Slack using a bot token
and send messages to a channel.

Usage:
    python slack_auth_example.py --token xoxb-your-token --channel CVE-reports
"""

import argparse
import os
import requests
import json


def verify_bot_token(token):
    """Verify if the bot token is valid"""
    try:
        response = requests.post(
            "https://slack.com/api/auth.test",
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json; charset=utf-8'
            }
        )
        
        data = response.json()
        
        if data.get('ok'):
            print("✅ Bot token is valid")
            print(f"   Bot Name: {data.get('user')}")
            print(f"   Team: {data.get('team')}")
            print(f"   User ID: {data.get('user_id')}")
            print(f"   Team ID: {data.get('team_id')}")
            return True
        else:
            print(f"❌ Bot token is invalid: {data.get('error')}")
            return False
    except Exception as e:
        print(f"❌ Error verifying bot token: {e}")
        return False


def list_channels(token):
    """List channels the bot has access to"""
    try:
        response = requests.get(
            "https://slack.com/api/conversations.list",
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json; charset=utf-8'
            },
            params={
                'types': 'public_channel,private_channel'
            }
        )
        
        data = response.json()
        
        if data.get('ok'):
            channels = data.get('channels', [])
            print(f"\n📋 Bot has access to {len(channels)} channels:")
            
            for channel in channels:
                channel_type = "🔒 Private" if channel.get('is_private') else "🌐 Public"
                print(f"   {channel_type}: #{channel.get('name')} (ID: {channel.get('id')})")
            
            return True
        else:
            print(f"❌ Error listing channels: {data.get('error')}")
            return False
    except Exception as e:
        print(f"❌ Error listing channels: {e}")
        return False


def check_channel_access(token, channel_id):
    """Check if the bot has access to a specific channel by ID"""
    try:
        # Check if the bot can access this specific channel
        response = requests.get(
            "https://slack.com/api/conversations.info",
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json; charset=utf-8'
            },
            params={
                'channel': channel_id
            }
        )
        
        data = response.json()
        
        if data.get('ok'):
            channel = data.get('channel', {})
            channel_type = "🔒 Private" if channel.get('is_private') else "🌐 Public"
            print(f"\n✅ Bot has access to {channel_type} channel: #{channel.get('name')} (ID: {channel.get('id')})")
            return True
        else:
            error = data.get('error')
            if error == 'channel_not_found':
                print(f"❌ Bot does not have access to channel ID '{channel_id}'")
            else:
                print(f"❌ Error checking channel access: {error}")
            return False
    except Exception as e:
        print(f"❌ Error checking channel access: {e}")
        return False


def send_test_message(token, channel_id):
    """Send a test message to the specified channel by ID"""
    try:
        response = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json; charset=utf-8'
            },
            json={
                'channel': channel_id,
                'text': '🧪 This is a test message from the CVE Scanner bot',
                'blocks': [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🧪 CVE Scanner Bot Test",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "This is a test message to verify that the CVE Scanner bot is properly configured and has access to this channel."
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "When vulnerabilities are found, alerts will be posted to this channel."
                        }
                    }
                ]
            }
        )
        
        data = response.json()
        
        if data.get('ok'):
            print(f"✅ Successfully sent test message to channel ID: {channel_id}")
            return True
        else:
            print(f"❌ Failed to send test message: {data.get('error')}")
            return False
    except Exception as e:
        print(f"❌ Error sending test message: {e}")
        return False


def save_credentials_to_env_file(token, channel_id):
    """Save credentials to .env file for future use"""
    try:
        env_file = '.env'
        
        # Check if file exists and if it already has these variables
        existing_vars = {}
        if os.path.exists(env_file):
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        existing_vars[key.strip()] = value.strip()
        
        # Update with new values
        existing_vars['SLACK_BOT_TOKEN'] = token
        existing_vars['SLACK_CHANNEL_ID'] = channel_id
        
        # Write back to file
        with open(env_file, 'w') as f:
            for key, value in existing_vars.items():
                f.write(f"{key}={value}\n")
        
        print(f"✅ Saved credentials to {env_file}")
        print("   The CVE scanner and Slack notifier will now automatically use these credentials")
        return True
    except Exception as e:
        print(f"❌ Error saving credentials: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Test Slack bot authentication and channel access',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python slack_auth_example.py --token xoxb-your-token --channel-id C04XXXXXX
  python slack_auth_example.py --token xoxb-your-token --list-channels
"""
    )
    
    # Required arguments
    parser.add_argument('--token', type=str, required=True,
                        help='Slack bot token (starting with xoxb-)')
    
    # Optional channel argument
    parser.add_argument('--channel-id', type=str,
                        help='Slack channel ID to test sending a message to')
    
    # Optional flags
    parser.add_argument('--list-channels', action='store_true',
                        help='List all channels the bot has access to')
    parser.add_argument('--save-credentials', action='store_true',
                        help='Save the token and channel ID to .env file')
    parser.add_argument('--send-test', action='store_true',
                        help='Send a test message to the specified channel')
    
    args = parser.parse_args()
    
    print("\n🤖 SLACK BOT AUTHENTICATION TEST\n")
    
    # Verify the token
    if not verify_bot_token(args.token):
        print("❌ Authentication failed. Please check your bot token.")
        return
    
    # List channels if requested
    if args.list_channels:
        list_channels(args.token)
        return
    
    # Check channel access if provided
    if args.channel_id:
        if check_channel_access(args.token, args.channel_id):
            # Send test message if requested
            if args.send_test:
                send_test_message(args.token, args.channel_id)
                
            # Save credentials if requested
            if args.save_credentials:
                save_credentials_to_env_file(args.token, args.channel_id)
        else:
            print(f"❌ Cannot proceed with channel ID '{args.channel_id}'. Please check channel ID and bot permissions.")
    else:
        print("\n⚠️ No channel ID specified. Use --channel-id to specify a channel to test.")
        if args.save_credentials:
            print("❌ Cannot save credentials without a channel ID. Please specify --channel-id.")


if __name__ == "__main__":
    main()