#!/usr/bin/env python3
"""
Slack Message Cleaner

This script deletes messages from a specific bot in a Slack channel.
It can be used to clean up messages from your CVE Scanner Bot or any other bot.

Requirements:
    - Python 3.6+
    - requests library (pip install requests)
    - A Slack user token with chat:write and channels:history permissions

Usage:
    python slack_message_cleaner.py --token xoxp-your-user-token --channel-id C04XXXXX --bot-user-id B05XXXXX
    python slack_message_cleaner.py --hours 48  # Delete messages from past 48 hours

You can also store your credentials in a .env file:
    SLACK_USER_TOKEN=xoxp-your-user-token
    SLACK_CHANNEL_ID=C04XXXXX
    SLACK_BOT_USER_ID=B05XXXXX
"""

import os
import sys
import time
import argparse
import datetime
import requests
from pathlib import Path


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


def verify_token(token):
    """Verify if the user token is valid and has necessary permissions"""
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
            print(f"✅ Token valid for user: {data.get('user')}")
            print(f"   User ID: {data.get('user_id')}")
            print(f"   Team: {data.get('team')}")
            return True
        else:
            print(f"❌ Invalid token: {data.get('error')}")
            return False
    except Exception as e:
        print(f"❌ Error verifying token: {e}")
        return False


def get_bot_info(token, bot_user_id):
    """Get information about the bot"""
    try:
        response = requests.get(
            f"https://slack.com/api/users.info",
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json; charset=utf-8'
            },
            params={
                'user': bot_user_id
            }
        )
        
        data = response.json()
        
        if data.get('ok'):
            user = data.get('user', {})
            if user.get('is_bot'):
                print(f"✅ Bot user found: {user.get('name')}")
                return user.get('name')
            else:
                print(f"⚠️ User ID {bot_user_id} is not a bot")
                return None
        else:
            print(f"❌ Error getting bot info: {data.get('error')}")
            return None
    except Exception as e:
        print(f"❌ Error retrieving bot info: {e}")
        return None


def get_channel_info(token, channel_id):
    """Get information about the channel"""
    try:
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
            channel_type = "private" if channel.get('is_private') else "public"
            print(f"✅ Channel found: #{channel.get('name')} ({channel_type})")
            return channel.get('name')
        else:
            print(f"❌ Error getting channel info: {data.get('error')}")
            return None
    except Exception as e:
        print(f"❌ Error retrieving channel info: {e}")
        return None


def delete_bot_messages(token, channel_id, bot_user_id, hours=24, dry_run=False, limit=1000):
    """
    Delete messages from a specific bot in a channel
    
    Args:
        token: Slack user token (not bot token)
        channel_id: The channel ID to clean
        bot_user_id: The bot's user ID
        hours: Delete messages from the last N hours (0 for all messages)
        dry_run: If True, don't actually delete messages
        limit: Maximum number of messages to process
    
    Returns:
        Tuple of (success, deleted_count, error_count)
    """
    # Calculate the oldest timestamp to delete
    if hours > 0:
        oldest_time = datetime.datetime.now() - datetime.timedelta(hours=hours)
        oldest_ts = oldest_time.timestamp()
        time_desc = f"from the last {hours} hours"
    else:
        oldest_ts = 0
        time_desc = "regardless of age"
    
    # Get bot name for better messaging
    bot_name = get_bot_info(token, bot_user_id) or bot_user_id
    channel_name = get_channel_info(token, channel_id) or channel_id
    
    print(f"\n🔍 Searching for messages from {bot_name} in #{channel_name} {time_desc}...")
    
    # Get message history
    try:
        response = requests.get(
            "https://slack.com/api/conversations.history",
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json; charset=utf-8'
            },
            params={
                'channel': channel_id,
                'oldest': oldest_ts,
                'limit': limit
            }
        )
        
        if not response.json().get('ok'):
            print(f"❌ Error fetching messages: {response.json().get('error')}")
            return False, 0, 0
        
        messages = response.json().get('messages', [])
        print(f"📝 Retrieved {len(messages)} total messages from the channel")
        
        # Find bot messages
        bot_messages = [msg for msg in messages if msg.get('user') == bot_user_id or 
                        (msg.get('bot_id') and msg.get('username') == bot_name)]
        
        if not bot_messages:
            print(f"✅ No messages from {bot_name} found in this time period")
            return True, 0, 0
        
        print(f"🤖 Found {len(bot_messages)} messages from {bot_name}")
        
        if dry_run:
            print(f"🔍 DRY RUN: Would delete {len(bot_messages)} messages (no actual deletion)")
            return True, len(bot_messages), 0
        
        # Delete each message
        deleted = 0
        errors = 0
        
        for i, msg in enumerate(bot_messages, 1):
            ts = msg.get('ts')
            date_str = datetime.datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')
            
            try:
                print(f"🗑️  Deleting message {i}/{len(bot_messages)} from {date_str}... ", end='', flush=True)
                
                response = requests.post(
                    "https://slack.com/api/chat.delete",
                    headers={
                        'Authorization': f'Bearer {token}',
                        'Content-Type': 'application/json; charset=utf-8'
                    },
                    json={
                        'channel': channel_id,
                        'ts': ts
                    }
                )
                
                if response.json().get('ok'):
                    print("✅")
                    deleted += 1
                else:
                    print(f"❌ {response.json().get('error')}")
                    errors += 1
                
                # Add a small delay to avoid rate limiting
                time.sleep(0.5)
                
            except Exception as e:
                print(f"❌ Error: {e}")
                errors += 1
        
        print(f"\n✅ Summary: Deleted {deleted} messages, Failed: {errors}")
        return True, deleted, errors
        
    except Exception as e:
        print(f"❌ Error performing cleanup: {e}")
        return False, 0, 0


def main():
    """Main function to run the Slack message cleaner"""
    parser = argparse.ArgumentParser(
        description='Delete bot messages from a Slack channel',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python slack_message_cleaner.py --token xoxp-your-user-token --channel-id C04XXXXX --bot-user-id B05XXXXX
  python slack_message_cleaner.py --hours 48  # Delete messages from past 48 hours
  python slack_message_cleaner.py --dry-run   # Preview what would be deleted without actually deleting
  python slack_message_cleaner.py --hours 0   # Delete all messages regardless of age
"""
    )
    
    parser.add_argument('--token', type=str, 
                        help='Slack user token (not bot token)')
    parser.add_argument('--channel-id', type=str, 
                        help='Channel ID to clean')
    parser.add_argument('--bot-user-id', type=str, 
                        help='Bot User ID whose messages to delete')
    parser.add_argument('--hours', type=int, default=24, 
                        help='Delete messages from the last N hours (0 for all messages)')
    parser.add_argument('--dry-run', action='store_true', 
                        help='Do not actually delete messages, just show what would be deleted')
    parser.add_argument('--limit', type=int, default=1000, 
                        help='Maximum number of messages to process')
    
    args = parser.parse_args()
    
    # Load environment variables from .env file
    load_env_file()
    
    # Get credentials from arguments or environment
    token = args.token or os.environ.get('SLACK_USER_TOKEN')
    channel_id = args.channel_id or os.environ.get('SLACK_CHANNEL_ID')
    bot_user_id = args.bot_user_id or os.environ.get('SLACK_BOT_USER_ID')
    
    # Validate required parameters
    missing = []
    if not token:
        missing.append("--token (or SLACK_USER_TOKEN in .env)")
    if not channel_id:
        missing.append("--channel-id (or SLACK_CHANNEL_ID in .env)")
    if not bot_user_id:
        missing.append("--bot-user-id (or SLACK_BOT_USER_ID in .env)")
    
    if missing:
        print("❌ Error: Missing required parameters:")
        for param in missing:
            print(f"  - {param}")
        print("\nUse --help for more information")
        return 1
    
    # Display a header
    print("\n🧹 SLACK MESSAGE CLEANER 🧹")
    print("=" * 50)
    
    # Verify the token
    if not verify_token(token):
        print("❌ Authentication failed. Please check your user token.")
        print("   Note: This requires a USER token (xoxp-), not a BOT token (xoxb-)")
        return 1
    
    # Delete messages
    success, deleted, errors = delete_bot_messages(
        token, channel_id, bot_user_id, 
        hours=args.hours, dry_run=args.dry_run, limit=args.limit
    )
    
    if success and deleted > 0:
        print("\n✅ Cleanup completed successfully!")
    elif success and deleted == 0:
        print("\n✅ No messages to clean up!")
    else:
        print("\n❌ Cleanup failed or was incomplete")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())