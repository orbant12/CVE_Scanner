#!/usr/bin/env python3
"""
CISA KEV and NVD Database CVE Checker

This script queries the CISA KEV and NVD databases for CVEs related to specific vendors and products.
It allows filtering by different timeframes: TODAY, THIS WEEK, or THIS MONTH.

Usage:
    python cve_checker.py --timeframe TODAY --vendor-product-file vendors.json
    python cve_checker.py --timeframe "THIS WEEK" --vendor-product "Microsoft:Windows"
    python cve_checker.py --timeframe "THIS MONTH" --vendors-json '[{"vendor":"Microsoft","product":"Windows 10"}]'

JSON format for vendor-product-file should be:
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

The script will automatically look for a .env file in the same directory for API keys.
"""

import argparse
import csv
import datetime
import json
import os
import sys
import time
import textwrap as tw
from typing import Dict, List, Tuple, Set
import urllib.request
import urllib.parse
import tempfile
from slack import SlackNotifier

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    @staticmethod
    def disable():
        """Disable colors for non-compatible terminals"""
        Colors.HEADER = ''
        Colors.BLUE = ''
        Colors.CYAN = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''

# Check if Windows or a non-ANSI terminal
if os.name == 'nt' or not sys.stdout.isatty():
    Colors.disable()

class CVEChecker:
    """Class to check for CVEs in vulnerability databases based on vendors and products."""
    
    # Database URLs
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self):
        self.cisa_data = None
        self.nvd_api_key = self.load_api_key()
        self.request_delay = 6  # Delay between API requests in seconds (for rate limiting)
        
        # Track statistics for summary report
        self.stats = {
            'cisa_checked': 0,
            'nvd_checked': 0,
            'cisa_matches': 0,
            'nvd_matches': 0,
            'total_vulnerabilities': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'unknown_count': 0,
            'vendor_stats': {}
        }
    
    def load_api_key(self):
        """Load NVD API key from .env file or environment variable."""
        api_key = None
        
        # Try to load from .env file in the same directory
        env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
        if os.path.exists(env_file):
            try:
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
                            
                            if key == 'NVD_API_KEY':
                                api_key = value
                                print(f"{Colors.GREEN}✓ NVD API key loaded from .env file{Colors.ENDC}")
                                break
            except Exception as e:
                print(f"{Colors.YELLOW}⚠️ Error reading .env file: {e}{Colors.ENDC}", file=sys.stderr)
        
        # Try environment variable as fallback
        if not api_key and 'NVD_API_KEY' in os.environ:
            api_key = os.environ['NVD_API_KEY']
            print(f"{Colors.GREEN}✓ NVD API key loaded from environment variable{Colors.ENDC}")
        
        return api_key
    
    def fetch_cisa_data(self) -> None:
        """Fetch the latest KEV data from CISA."""
        try:
            print(f"\n{Colors.CYAN}Fetching CISA KEV database...{Colors.ENDC}")
            with urllib.request.urlopen(self.CISA_KEV_URL) as response:
                data = json.loads(response.read().decode('utf-8'))
                self.cisa_data = data.get('vulnerabilities', [])
                self.stats['cisa_checked'] = len(self.cisa_data)
                print(f"{Colors.GREEN}✓ Successfully fetched {len(self.cisa_data)} vulnerabilities from CISA KEV database.{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}✗ Error fetching CISA KEV data: {e}{Colors.ENDC}", file=sys.stderr)
            self.cisa_data = []
    
    def fetch_nvd_data(self, vendor: str, product: str, start_date: datetime.datetime, 
                      end_date: datetime.datetime) -> List[Dict]:
        """
        Fetch CVE data from NVD for a specific vendor and product.
        
        The NVD API has rate limiting (5 requests per 30 seconds for unauthenticated users),
        so we add delays between requests.
        """
        try:
            # Format search query - using keywords for more reliable results
            search_keyword = f"{vendor} {product}"
            
            # Format search parameters for NVD API
            params = {
                'keywordSearch': search_keyword,
                'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
                'resultsPerPage': 2000  # Maximum allowed
            }
            
            # Add API key if available
            if self.nvd_api_key:
                #params['apiKey'] = self.nvd_api_key
                print("")
            
            url = f"{self.NVD_API_URL}?{urllib.parse.urlencode(params)}"
            
            # Create a custom request with appropriate headers
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'CVEChecker/1.0')
            
            print(f"\n{Colors.CYAN}Querying NVD API for {vendor} {product}...{Colors.ENDC}")
            
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode('utf-8'))
                vulns = data.get('vulnerabilities', [])
                self.stats['nvd_checked'] += len(vulns)
                
                vendor_key = f"{vendor}:{product}"
                if vendor_key not in self.stats['vendor_stats']:
                    self.stats['vendor_stats'][vendor_key] = {'cisa': 0, 'nvd': 0, 'total': 0}
                
                self.stats['vendor_stats'][vendor_key]['nvd'] += len(vulns)
                self.stats['vendor_stats'][vendor_key]['total'] += len(vulns)
                
                if vulns:
                    print(f"{Colors.GREEN}✓ Found {len(vulns)} vulnerabilities in NVD for {vendor}:{product}{Colors.ENDC}")
                else:
                    print(f"{Colors.YELLOW}⚠️ No vulnerabilities found in NVD for {vendor}:{product}{Colors.ENDC}")
                
                # Rate limiting - sleep between requests
                time.sleep(self.request_delay)
                
                return vulns
        except Exception as e:
            print(f"{Colors.RED}✗ Error fetching NVD data for {vendor}:{product}: {e}{Colors.ENDC}", file=sys.stderr)
            return []
    
    def parse_vendor_product_file(self, filepath: str) -> List[Tuple[str, str]]:
        """
        Parse a file containing vendor and product pairs.
        
        The file can be either:
        1. A JSON file with a list of objects in format: 
           [{"vendor": "Vendor", "product": "Product"}, ...]
        2. A text file where each line is in format: "vendor:product"
        """
        vendor_products = []
        
        try:
            with open(filepath, 'r') as f:
                # Try to parse as JSON first
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict) and 'vendor' in item and 'product' in item:
                                vendor_products.append((item['vendor'].strip(), item['product'].strip()))
                            else:
                                print(f"{Colors.YELLOW}⚠️ Warning: Ignoring invalid JSON item format: {item}{Colors.ENDC}", file=sys.stderr)
                        return vendor_products
                    else:
                        print(f"{Colors.YELLOW}⚠️ Warning: JSON file does not contain a list{Colors.ENDC}", file=sys.stderr)
                except json.JSONDecodeError:
                    # If JSON parsing fails, try as a text file
                    f.seek(0)  # Reset file pointer to beginning
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        
                        parts = line.split(':', 2)
                        if len(parts) >= 2:
                            vendor, product = parts[0].strip(), parts[1].strip()
                            vendor_products.append((vendor, product))
                        else:
                            print(f"{Colors.YELLOW}⚠️ Warning: Ignoring invalid line format: {line}{Colors.ENDC}", file=sys.stderr)
        except Exception as e:
            print(f"{Colors.RED}✗ Error reading vendor-product file {filepath}: {e}{Colors.ENDC}", file=sys.stderr)
            sys.exit(1)
        
        return vendor_products
    
    def get_date_range(self, timeframe: str) -> Tuple[datetime.datetime, datetime.datetime]:
        """
        Get date range based on the specified timeframe.
        
        Args:
            timeframe: One of "TODAY", "THIS WEEK", or "THIS MONTH"
            
        Returns:
            Tuple of (start_date, end_date)
        """
        today = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = today + datetime.timedelta(days=1) - datetime.timedelta(seconds=1)
        
        if timeframe.upper() == "TODAY":
            start_date = today
            range_desc = "today"
        elif timeframe.upper() == "THIS WEEK":
            # Start from Monday of current week
            start_date = today - datetime.timedelta(days=today.weekday())
            range_desc = "this week"
        elif timeframe.upper() == "THIS MONTH":
            # Start from first day of current month
            start_date = today.replace(day=1)
            range_desc = "this month"
        else:
            print(f"{Colors.YELLOW}⚠️ Invalid timeframe: {timeframe}. Using TODAY as default.{Colors.ENDC}", file=sys.stderr)
            start_date = today
            range_desc = "today"
        
        return start_date, end_date, range_desc
    
    def search_vulnerabilities(self, vendor_products: List[Tuple[str, str]], timeframe: str) -> List[Dict]:
        """
        Search for vulnerabilities across CISA KEV and NVD databases.
        
        Args:
            vendor_products: List of (vendor, product) tuples
            timeframe: One of "TODAY", "THIS WEEK", or "THIS MONTH"
            
        Returns:
            List of matching vulnerability dictionaries from all sources
        """
        start_date, end_date, range_desc = self.get_date_range(timeframe)
        
        print(f"\n{Colors.HEADER}{Colors.BOLD}🔍 SEARCHING FOR VULNERABILITIES{Colors.ENDC}")
        print(f"{Colors.BOLD}Time Range:{Colors.ENDC} {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')} ({range_desc})")
        print(f"{Colors.BOLD}Vendors/Products:{Colors.ENDC} {len(vendor_products)} pairs")
        print(f"{Colors.BOLD}Databases:{Colors.ENDC} CISA KEV, NVD")
        print("=" * 80)
        
        all_vulns = []
        cve_set = set()  # Track unique CVEs to avoid duplicates
        
        # Fetch CISA data once
        if not self.cisa_data:
            self.fetch_cisa_data()
        
        # Process CISA KEV data vendor by vendor
        print(f"\n{Colors.HEADER}{Colors.BOLD}CISA KEV DATABASE RESULTS{Colors.ENDC}")
        cisa_matches = 0
        
        for vendor, product in vendor_products:
            print(f"\n{Colors.BOLD}Searching CISA KEV for {vendor}:{product}{Colors.ENDC}")
            vendor_matches = 0
            
            # Look for matching vulnerabilities in CISA KEV database
            for vuln in self.cisa_data:
                # Check if the vulnerability was added within the specified timeframe
                added_date = datetime.datetime.strptime(vuln.get('dateAdded', ''), '%Y-%m-%d')
                if not (start_date <= added_date <= end_date):
                    continue
                
                # Check if the vulnerability matches current vendor-product pair
                # Case-insensitive comparison
                vuln_vendor = vuln.get('vendor', '').lower()
                vuln_product = vuln.get('product', '').lower()
                
                if vuln_vendor == vendor.lower() and vuln_product == product.lower():
                    cve_id = vuln.get('cveID')
                    if cve_id and cve_id not in cve_set:
                        cve_set.add(cve_id)
                        normalized_vuln = self.normalize_cisa_vulnerability(vuln)
                        all_vulns.append(normalized_vuln)
                        cisa_matches += 1
                        vendor_matches += 1
                        
                        # Update vendor stats
                        vendor_key = f"{vendor}:{product}"
                        if vendor_key not in self.stats['vendor_stats']:
                            self.stats['vendor_stats'][vendor_key] = {'cisa': 0, 'nvd': 0, 'total': 0}
                        
                        self.stats['vendor_stats'][vendor_key]['cisa'] += 1
                        self.stats['vendor_stats'][vendor_key]['total'] += 1
            
            # Display results for this vendor-product pair
            if vendor_matches > 0:
                print(f"{Colors.GREEN}✓ Found {vendor_matches} vulnerabilities in CISA KEV for {vendor}:{product}{Colors.ENDC}")
            else:
                print(f"{Colors.YELLOW}⚠️ No vulnerabilities found in CISA KEV for {vendor}:{product}{Colors.ENDC}")
        
        self.stats['cisa_matches'] = cisa_matches
        
        if cisa_matches > 0:
            print(f"\n{Colors.GREEN}✓ Total: Found {cisa_matches} vulnerabilities in CISA KEV database{Colors.ENDC}")
        else:
            print(f"\n{Colors.YELLOW}⚠️ Total: No vulnerabilities found in CISA KEV database for the specified criteria{Colors.ENDC}")
        
        # Search NVD for each vendor-product pair
        print(f"\n{Colors.HEADER}{Colors.BOLD}NVD DATABASE RESULTS{Colors.ENDC}")
        
        nvd_matches = 0
        for vendor, product in vendor_products:
            print(f"\n{Colors.BOLD}Searching NVD for {vendor}:{product}{Colors.ENDC}")
            
            nvd_vulns = self.fetch_nvd_data(vendor, product, start_date, end_date)
            for vuln_item in nvd_vulns:
                vuln = vuln_item.get('cve', {})
                cve_id = vuln.get('id')
                if cve_id and cve_id not in cve_set:
                    cve_set.add(cve_id)
                    normalized_vuln = self.normalize_nvd_vulnerability(vuln_item, vendor, product)
                    all_vulns.append(normalized_vuln)
                    nvd_matches += 1
                    
                    # Update severity statistics
                    severity = normalized_vuln.get('severity', 'UNKNOWN').upper()
                    if severity == 'CRITICAL':
                        self.stats['critical_count'] += 1
                    elif severity == 'HIGH':
                        self.stats['high_count'] += 1
                    elif severity == 'MEDIUM':
                        self.stats['medium_count'] += 1
                    elif severity == 'LOW':
                        self.stats['low_count'] += 1
                    else:
                        self.stats['unknown_count'] += 1
        
        self.stats['nvd_matches'] = nvd_matches
        self.stats['total_vulnerabilities'] = len(all_vulns)
        
        return all_vulns
    
    def normalize_cisa_vulnerability(self, vuln: Dict) -> Dict:
        """Normalize CISA KEV vulnerability data."""
        # Add to severity statistics
        self.stats['high_count'] += 1  # CISA KEV vulnerabilities are considered high severity
        
        return {
            'cve_id': vuln.get('cveID'),
            'vendor': vuln.get('vendor'),
            'product': vuln.get('product'),
            'vulnerability_name': vuln.get('vulnerabilityName'),
            'date_added': vuln.get('dateAdded'),
            'due_date': vuln.get('dueDate', 'N/A'),
            'description': vuln.get('shortDescription'),
            'action': vuln.get('requiredAction', 'N/A'),
            'notes': vuln.get('notes', 'N/A'),
            'ransomware_use': vuln.get('knownRansomwareCampaignUse', False),
            'severity': 'HIGH',  # CISA KEV vulnerabilities are all considered high severity
            'source': 'CISA KEV',
            'references': [],
            'cvss_score': 'N/A',  # CISA doesn't provide CVSS scores
            'cvss_vector': 'N/A'  # CISA doesn't provide CVSS vectors
        }
    
    def normalize_nvd_vulnerability(self, vuln_item: Dict, vendor: str, product: str) -> Dict:
        """Normalize NVD vulnerability data."""
        vuln = vuln_item.get('cve', {})
        metrics = vuln.get('metrics', {})
        
        # Extract CVSS data and vector
        cvss_data = {}
        cvss_vector = 'N/A'
        severity = 'UNKNOWN'
        cvss_score = 'N/A'
        
        # Try each CVSS version in order of preference
        for metric_type in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if metric_type in metrics and metrics[metric_type]:
                metric_data = metrics[metric_type][0]
                cvss_data = metric_data.get('cvssData', {})
                if cvss_data:
                    cvss_vector = cvss_data.get('vectorString', 'N/A')
                    cvss_score = str(cvss_data.get('baseScore', 'N/A'))
                    
                    # Also check if there's an override severity
                    if 'baseSeverity' in cvss_data:
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                    break
        
        # If no baseSeverity, derive from score
        if severity == 'UNKNOWN' and cvss_score != 'N/A':
            score = float(cvss_score)
            if score >= 9.0:
                severity = 'CRITICAL'
            elif score >= 7.0:
                severity = 'HIGH'
            elif score >= 4.0:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
        
        # Get the published date
        published_date = vuln.get('published', '')
        if published_date:
            published_date = published_date.split('T')[0]  # Keep just the date part
        
        # Extract references
        references = []
        for ref in vuln.get('references', []):
            references.append(ref.get('url', ''))
        
        # Get a better vulnerability name from description if possible
        description = '\n'.join([desc.get('value', '') for desc in vuln.get('descriptions', []) if desc.get('lang') == 'en'])
        vulnerability_name = ''
        
        # Try to get a better title from the first line of the description
        if description:
            first_line = description.split('\n')[0].strip()
            # If the first line is reasonably short, use it as the title
            if len(first_line) < 100:
                vulnerability_name = first_line
        
        return {
            'cve_id': vuln.get('id'),
            'vendor': vendor,
            'product': product,
            'vulnerability_name': vulnerability_name,
            'date_added': published_date,
            'due_date': 'N/A',
            'description': description,
            'action': 'Apply vendor patches when available',
            'notes': '',
            'ransomware_use': False,  # NVD doesn't specify this
            'severity': severity,
            'source': 'NVD',
            'references': references,
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector
        }
    
    def display_results(self, vulnerabilities: List[Dict]) -> None:
        """Display the matching vulnerabilities in a formatted output."""
        if not vulnerabilities:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️ NO VULNERABILITIES FOUND{Colors.ENDC}")
            print(f"No matching vulnerabilities found in the specified timeframe.")
            self.display_summary_report()
            return
        
        print(f"\n{Colors.HEADER}{Colors.BOLD}🔍 VULNERABILITY RESULTS{Colors.ENDC}")
        print(f"Found {len(vulnerabilities)} matching vulnerabilities:")
        print("=" * 100)
        
        # Sort vulnerabilities by severity and then by date
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
        vulnerabilities.sort(key=lambda x: (
            severity_order.get(x.get('severity', 'UNKNOWN'), 4),
            x.get('date_added', '2099-01-01'),
            x.get('cve_id', '')
        ))
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id', 'N/A')
            source = vuln.get('source', 'Unknown')
            
            # Set color based on severity
            severity = vuln.get('severity', 'UNKNOWN')
            if severity == 'CRITICAL':
                severity_color = Colors.RED
            elif severity == 'HIGH':
                severity_color = Colors.YELLOW
            elif severity == 'MEDIUM':
                severity_color = Colors.CYAN
            elif severity == 'LOW':
                severity_color = Colors.GREEN
            else:
                severity_color = Colors.ENDC
            
            # Display header with CVE ID and source
            print(f"{Colors.BOLD}{Colors.UNDERLINE}{cve_id} ({source}){Colors.ENDC}")
            
            # Display base info with proper formatting
            print(f"{Colors.BOLD}Vendor:{Colors.ENDC} {vuln.get('vendor', 'Unknown')}")
            print(f"{Colors.BOLD}Product:{Colors.ENDC} {vuln.get('product', 'Unknown')}")
            print(f"{Colors.BOLD}Severity:{Colors.ENDC} {severity_color}{severity}{Colors.ENDC}")
            
            # Show CVSS info if available
            cvss_score = vuln.get('cvss_score', 'N/A')
            cvss_vector = vuln.get('cvss_vector', 'N/A')
            if cvss_score != 'N/A':
                print(f"{Colors.BOLD}CVSS Score:{Colors.ENDC} {cvss_score}")
            if cvss_vector != 'N/A':
                print(f"{Colors.BOLD}CVSS Vector:{Colors.ENDC} {cvss_vector}")
            
            # Show name if available
            vuln_name = vuln.get('vulnerability_name', '')
            if vuln_name:
                print(f"{Colors.BOLD}Name:{Colors.ENDC} {vuln_name}")
            
            # Date information
            print(f"{Colors.BOLD}Date Added:{Colors.ENDC} {vuln.get('date_added', 'Unknown')}")
            
            # Display description with wrapping
            description = vuln.get('description', '')
            if description:
                print(f"{Colors.BOLD}Description:{Colors.ENDC}")
                # Wrap text for terminal display
                wrapper = tw.TextWrapper(width=95, initial_indent="  ", subsequent_indent="  ")
                wrapped_description = wrapper.fill(description)
                print(wrapped_description)
            
            # Display required action if available
            action = vuln.get('action', '')
            if action:
                print(f"{Colors.BOLD}Required Action:{Colors.ENDC}")
                wrapper = tw.TextWrapper(width=95, initial_indent="  ", subsequent_indent="  ")
                wrapped_action = wrapper.fill(action)
                print(wrapped_action)
            
            # Display notes if available
            notes = vuln.get('notes', '')
            if notes and notes != 'N/A':
                print(f"{Colors.BOLD}Notes:{Colors.ENDC}")
                wrapper = tw.TextWrapper(width=95, initial_indent="  ", subsequent_indent="  ")
                wrapped_notes = wrapper.fill(notes)
                print(wrapped_notes)
            
            # Alert if used in ransomware campaigns
            if vuln.get('ransomware_use', False):
                print(f"{Colors.RED}{Colors.BOLD}⚠️ USED IN KNOWN RANSOMWARE CAMPAIGNS ⚠️{Colors.ENDC}")
            
            # Print references if available
            references = vuln.get('references', [])
            if references:
                print(f"{Colors.BOLD}References:{Colors.ENDC}")
                for i, ref in enumerate(references[:5]):  # Limit to 5 references
                    print(f"  {i+1}. {ref}")
                if len(references) > 5:
                    print(f"  (and {len(references) - 5} more...)")
            
            print("-" * 100)
        
        # Display summary after results
        self.display_summary_report()
    
    def display_summary_report(self):
        """Display a summary report of search results and statistics."""
        print(f"\n{Colors.HEADER}{Colors.BOLD}📊 SUMMARY REPORT{Colors.ENDC}")
        print("=" * 80)
        
        # Database stats
        print(f"{Colors.BOLD}Database Summary:{Colors.ENDC}")
        print(f"  CISA KEV: {self.stats['cisa_matches']} vulnerabilities found (from {self.stats['cisa_checked']} checked)")
        print(f"  NVD: {self.stats['nvd_matches']} vulnerabilities found (from {self.stats['nvd_checked']} checked)")
        print(f"  Total unique vulnerabilities: {self.stats['total_vulnerabilities']}")
        
        # Severity breakdown
        print(f"\n{Colors.BOLD}Severity Breakdown:{Colors.ENDC}")
        print(f"  {Colors.RED}CRITICAL:{Colors.ENDC} {self.stats['critical_count']}")
        print(f"  {Colors.YELLOW}HIGH:{Colors.ENDC} {self.stats['high_count']}")
        print(f"  {Colors.CYAN}MEDIUM:{Colors.ENDC} {self.stats['medium_count']}")
        print(f"  {Colors.GREEN}LOW:{Colors.ENDC} {self.stats['low_count']}")
        print(f"  UNKNOWN: {self.stats['unknown_count']}")
        
        # Vendor/product breakdown
        if self.stats['vendor_stats']:
            print(f"\n{Colors.BOLD}Vendor/Product Breakdown:{Colors.ENDC}")
            for vendor_product, counts in self.stats['vendor_stats'].items():
                if counts['total'] > 0:
                    print(f"  {vendor_product}: {counts['total']} vulnerabilities (CISA: {counts['cisa']}, NVD: {counts['nvd']})")
        
        print(f"\n{Colors.CYAN}Search completed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
        print("=" * 80)
    
    def export_csv(self, vulnerabilities: List[Dict], output_file: str) -> None:
        """Export results to a CSV file."""
        if not vulnerabilities:
            print(f"\n{Colors.YELLOW}⚠️ No vulnerabilities to export to {output_file}{Colors.ENDC}")
            return
        
        try:
            with open(output_file, 'w', newline='') as csvfile:
                fieldnames = [
                    'cve_id', 'source', 'vendor', 'product', 'vulnerability_name', 
                    'severity', 'cvss_score', 'cvss_vector', 'date_added', 'due_date', 
                    'description', 'action', 'notes', 'ransomware_use', 'references'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                
                writer.writeheader()
                for vuln in vulnerabilities:
                    # Convert references list to string for CSV
                    vuln_copy = vuln.copy()
                    if 'references' in vuln_copy and isinstance(vuln_copy['references'], list):
                        vuln_copy['references'] = '; '.join(vuln_copy['references'])
                    
                    writer.writerow({k: vuln_copy.get(k, '') for k in fieldnames})
                
            print(f"\n{Colors.GREEN}✓ Results exported to {output_file}{Colors.ENDC}")
            print(f"  {len(vulnerabilities)} vulnerabilities saved to CSV file.")
        except Exception as e:
            print(f"\n{Colors.RED}✗ Error exporting to CSV: {e}{Colors.ENDC}", file=sys.stderr)
    
    def export_json(self, vulnerabilities: List[Dict], output_file: str) -> None:
        """Export results to a JSON file."""
        if not vulnerabilities:
            print(f"\n{Colors.YELLOW}⚠️ No vulnerabilities to export to {output_file}{Colors.ENDC}")
            return
        
        try:
            # Create a report structure with metadata and results
            report = {
                "metadata": {
                    "generated_at": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "total_vulnerabilities": len(vulnerabilities),
                    "cisa_matches": self.stats['cisa_matches'],
                    "nvd_matches": self.stats['nvd_matches'],
                    "severity_breakdown": {
                        "critical": self.stats['critical_count'],
                        "high": self.stats['high_count'],
                        "medium": self.stats['medium_count'],
                        "low": self.stats['low_count'],
                        "unknown": self.stats['unknown_count']
                    }
                },
                "vulnerabilities": vulnerabilities
            }
            
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"\n{Colors.GREEN}✓ Results exported to {output_file}{Colors.ENDC}")
            print(f"  {len(vulnerabilities)} vulnerabilities saved to JSON file.")
        except Exception as e:
            print(f"\n{Colors.RED}✗ Error exporting to JSON: {e}{Colors.ENDC}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Check for CVEs and notify Slack if vulnerabilities are found',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python integration_example.py --timeframe "THIS WEEK" --vendor-product "Microsoft:Windows" --slack-webhook https://hooks.slack.com/services/XXX/YYY/ZZZ
  python integration_example.py --timeframe "THIS MONTH" --vendor-product-file vendors.json
"""
    )
    
    # Define timeframe argument
    parser.add_argument('--timeframe', type=str, choices=['TODAY', 'THIS WEEK', 'THIS MONTH'], 
                       default='THIS MONTH', help='Timeframe to check for vulnerabilities')
    
    # Define mutually exclusive group for vendor-product input
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--vendor-product-file', type=str, 
                           help='Path to JSON file with vendor/product pairs')
    input_group.add_argument('--vendor-product', type=str, 
                           help='Single vendor:product pair (e.g., "Microsoft:Windows")')
    input_group.add_argument('--vendors-json', type=str,
                           help='JSON string with vendor/product pairs')
    
    # Add no-notify option to disable Slack notification
    parser.add_argument('--no-notify', action='store_true',
                      help='Disable Slack notifications')
    
    # Add output formatting option
    parser.add_argument('--no-color', action='store_true', 
                      help='Disable colored output')
    
    args = parser.parse_args()
    
    # Create CVE checker instance
    checker = CVEChecker()
    
    # Parse vendor-product inputs (simplified - using the checker's methods)
    if args.vendor_product_file:
        vendor_products = checker.parse_vendor_product_file(args.vendor_product_file)
    elif args.vendors_json:
        try:
            data = json.loads(args.vendors_json)
            vendor_products = []
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and 'vendor' in item and 'product' in item:
                        vendor_products.append((item['vendor'].strip(), item['product'].strip()))
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON string: {e}")
            return
    else:
        parts = args.vendor_product.split(':', 1)
        if len(parts) != 2:
            print(f"Error: Invalid vendor-product format. Use 'vendor:product'")
            return
        vendor_products = [(parts[0].strip(), parts[1].strip())]
    
    # Search for vulnerabilities
    vulnerabilities = checker.search_vulnerabilities(
        vendor_products, 
        args.timeframe
    )
    
    # Display results in the terminal
    checker.display_results(vulnerabilities)
    
    # Only notify if there are vulnerabilities and notifications are enabled
    if vulnerabilities and not args.no_notify:
        # Create a temporary file to store the results
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            # Create a report structure with metadata and results
            report = {
                "metadata": {
                    "generated_at": checker.stats.get('generated_at', 'N/A'),
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
    elif not vulnerabilities:
        print(f"\nNo vulnerabilities found. No Slack notification sent.")
    elif args.no_notify:
        print(f"\nSlack notifications disabled. No notification sent.")


if __name__ == "__main__":
    main()