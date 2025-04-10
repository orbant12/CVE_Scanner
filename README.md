# CVE Scanner and Slack Notifier

This project provides tools to scan for CVEs (Common Vulnerabilities and Exposures) in the CISA KEV and NVD databases and notify a Slack channel when vulnerabilities are found.

## Components

- **cve_checker.py**: The main script that scans for vulnerabilities based on specified vendors and products.
- **slack_notifier.py**: A separate script that takes the findings and sends notifications to Slack.
- **integration_example.py**: An example script that shows how to use both tools together.

## Setup

### Requirements

- Python 3.6+
- Required packages: `requests`

Install dependencies:

```bash
pip install requests
```

### Slack Webhook URL

To receive notifications in Slack, you need to create a webhook URL:

1. Go to your Slack workspace
2. Create a new app (or use an existing one)
3. Enable "Incoming Webhooks"
4. Create a new webhook URL for your workspace
5. Choose the "CVE-reports" channel as the destination

You can provide the webhook URL in two ways:
- As a command-line argument with `--slack-webhook`
- As an environment variable named `SLACK_WEBHOOK_URL`

### NVD API Key (Optional)

For better rate limits with the NVD API, you can obtain an API key from the NVD website and add it to:
- A `.env` file in the same directory as the scripts
- An environment variable named `NVD_API_KEY`

## Usage

### Using the Integrated Solution

The simplest way to use the tools together:

```bash
python integration_example.py --timeframe "THIS WEEK" --vendor-product "Microsoft:Windows" --slack-webhook https://hooks.slack.com/services/XXX/YYY/ZZZ
```

This will:
1. Scan for vulnerabilities related to Microsoft Windows from the past week
2. Display the results in the terminal
3. Send a notification to Slack if any vulnerabilities are found

### Using the Components Separately

You can also use the components separately:

1. First, scan for vulnerabilities and export the results:

```bash
python cve_checker.py --timeframe "THIS WEEK" --vendor-product "Microsoft:Windows" --json results.json
```

2. Then send the results to Slack:

```bash
python slack_notifier.py --json results.json --webhook-url https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Scanning Multiple Vendors/Products

You can scan for multiple vendors and products by:

1. Creating a JSON file (`vendors.json`):

```json
[
  {
    "vendor": "Microsoft",
    "product": "Windows 10"
  },
  {
    "vendor": "Apache",
    "product": "Log4j"
  }
]
```

2. Passing the file to the script:

```bash
python integration_example.py --timeframe "THIS MONTH" --vendor-product-file vendors.json
```

### Automation

For automated scanning, set up a cron job or scheduled task to run the integration script regularly.

Example cron job (daily at 9 AM):

```
0 9 * * * cd /path/to/scripts && python integration_example.py --timeframe "TODAY" --vendor-product-file vendors.json
```

## Slack Notification Features

The Slack notifications include:

- A summary of the findings
- Severity breakdown
- Details about Critical and High vulnerabilities
- Indicators for vulnerabilities used in ransomware campaigns
- CVSS scores when available

## Customization

You can modify the scripts to:
- Change the formatting of Slack messages
- Add additional data sources
- Integrate with other notification systems
- Customize the scanning timeframes