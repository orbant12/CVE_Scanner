#!/bin/bash

# Set environment
export PATH=/usr/bin:/bin:/usr/local/bin
export PYTHONIOENCODING=utf-8
export HOME=/home/itsupport

# Change to script directory
cd /home/itsupport/CVE_Scanner

# Log start
echo "===========================================" >> /var/log/cve_scanner_test.log
echo "Cron job started at $(date)" >> /var/log/cve_scanner_test.log
echo "Current directory: $(pwd)" >> /var/log/cve_scanner_test.log
echo "Python path: $(which python3)" >> /var/log/cve_scanner_test.log
echo "===========================================" >> /var/log/cve_scanner_test.log

# Run the script
python3 runner.py --timeframe "TODAY" >> /var/log/cve_scanner_test.log 2>&1

# Log completion
echo "Cron job completed at $(date)" >> /var/log/cve_scanner_test.log
echo "" >> /home/itsupport/Logs/cve_scanner_test.log
