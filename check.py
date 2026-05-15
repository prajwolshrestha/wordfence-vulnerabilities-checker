#!/usr/bin/env python3
"""
Wordfence Vulnerability Checker
Checks your WordPress plugins against the Wordfence Intelligence v3 API
and reports any vulnerabilities published in the last 7 days.

Usage:
    python check_vulnerabilities.py

Requirements:
    pip install requests

Setup:
    1. Get a free API key at https://www.wordfence.com/account/integrations
    2. Set it in the API_KEY variable below (or via env: WORDFENCE_API_KEY)
"""

import os
import json
import requests
from datetime import datetime, timedelta, timezone
import sys

# ---------------------------------------------------------------
# CONFIGURATION — edit these
# ---------------------------------------------------------------

# API_KEY = os.environ.get("WORDFENCE_API_KEY", "YOUR_API_KEY_HERE")
API_KEY = "YOUR_API_KEY_HERE"

# Days to look back (7 = last week)
DAYS_BACK = 7

# Plugin list file
PLUGINS_FILE = "plugins.txt"

# ---------------------------------------------------------------
# SCRIPT — no need to edit below
# ---------------------------------------------------------------

API_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"


def load_plugins_from_file(filename):
    """
    Load plugin slugs from a text file (one slug per line).
    Ignores empty lines and lines starting with #.
    """
    if not os.path.exists(filename):
        print(f"❌ Error: Plugin list file '{filename}' not found.")
        print(f"Please create a file named '{filename}' with one plugin slug per line.")
        print("\nExample content:")
        print("  contact-form-7")
        print("  elementor")
        print("  wordfence")
        exit(1)
    
    plugins = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    plugins.append(line)
        
        if not plugins:
            print(f"❌ Error: No plugins found in '{filename}'.")
            print("Please add at least one plugin slug to the file.")
            exit(1)
        
        return plugins
    
    except Exception as e:
        print(f"❌ Error reading plugin list file: {e}")
        exit(1)


def get_date_range():
    """
    Interactively ask user for date range preference.
    Returns tuple: (cutoff_date, days_description)
    """
    print("\n" + "=" * 60)
    print("WORDFENCE VULNERABILITY CHECKER")
    print("=" * 60)
    print("\nSelect time period to check:")
    print("  1. Last 7 days (default)")
    print("  2. Custom date range")
    print()
    
    choice = input("Enter your choice (1 or 2) [1]: ").strip()
    
    if choice == "" or choice == "1":
        # Default: last 7 days
        cutoff = datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)
        days_desc = f"Last {DAYS_BACK} days (since {cutoff.strftime('%Y-%m-%d')})"
        return cutoff, days_desc
    
    elif choice == "2":
        # Custom date range
        while True:
            print("\nEnter date range in YYYY-MM-DD format:")
            from_date_str = input("  From date (YYYY-MM-DD): ").strip()
            to_date_str = input("  To date   (YYYY-MM-DD): ").strip()
            
            try:
                # Parse dates
                from_date = datetime.strptime(from_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                to_date = datetime.strptime(to_date_str, "%Y-%m-%d").replace(
                    hour=23, minute=59, second=59, tzinfo=timezone.utc
                )
                
                # Validate date range
                if from_date > to_date:
                    print("❌ Error: 'From date' must be before or equal to 'To date'. Please try again.\n")
                    continue
                
                if to_date > datetime.now(timezone.utc):
                    print("❌ Error: 'To date' cannot be in the future. Please try again.\n")
                    continue
                
                # Check if date range exceeds 35 days
                date_diff = (to_date - from_date).days
                if date_diff > 35:
                    print(f"❌ Error: Date range cannot exceed 35 days. Your range is {date_diff} days. Please try again.\n")
                    continue
                
                days_desc = f"Custom range: {from_date_str} to {to_date_str}"
                return from_date, days_desc, to_date
                
            except ValueError:
                print("❌ Error: Invalid date format. Please use YYYY-MM-DD format.\n")
                continue
    
    else:
        print("Invalid choice. Using default (last 7 days).")
        cutoff = datetime.now(timezone.utc) - timedelta(days=DAYS_BACK)
        days_desc = f"Last {DAYS_BACK} days (since {cutoff.strftime('%Y-%m-%d')})"
        return cutoff, days_desc


def fetch_vulnerabilities():
    print("Fetching vulnerability feed from Wordfence...")
    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get(API_URL, headers=headers, timeout=60)

    if response.status_code == 401:
        print("ERROR: Invalid API key. Get one free at https://www.wordfence.com/account/integrations")
        return None
    elif response.status_code == 429:
        print("ERROR: Rate limited. Try again later.")
        return None
    elif response.status_code != 200:
        print(f"ERROR: Unexpected response: {response.status_code}")
        return None

    return response.json()


def check_plugins(vulns, date_range_info, my_plugins):
    """
    Check plugins against vulnerabilities within the specified date range.
    
    Args:
        vulns: Vulnerability data from API
        date_range_info: Tuple of (cutoff_date, days_desc) or (from_date, days_desc, to_date)
        my_plugins: List of plugin slugs to check
    """
    if len(date_range_info) == 2:
        # Last 7 days mode
        cutoff, days_desc = date_range_info
        to_date = None
    else:
        # Custom range mode
        cutoff, days_desc, to_date = date_range_info
    
    my_plugins_set = set(my_plugins)
    matches = []

    for vuln_id, vuln in vulns.items():
        published_str = vuln.get("published")
        if not published_str:
            continue

        published = datetime.fromisoformat(published_str).replace(tzinfo=timezone.utc)
        
        # Check if published date is within range
        if published < cutoff:
            continue
        
        if to_date and published > to_date:
            continue

        # Check if any affected software matches our plugin list
        for software in vuln.get("software", []):
            if software.get("type") != "plugin":
                continue
            if software.get("slug") in my_plugins_set:
                matches.append({
                    "plugin_name": software.get("name"),
                    "plugin_slug": software.get("slug"),
                    "title": vuln.get("title"),
                    "published": published_str,
                    "cvss_score": vuln.get("cvss", {}).get("score") if vuln.get("cvss") else "N/A",
                    "cvss_rating": vuln.get("cvss", {}).get("rating") if vuln.get("cvss") else "N/A",
                    "patched": software.get("patched"),
                    "patched_versions": software.get("patched_versions", []),
                    "remediation": software.get("remediation", ""),
                    "details_url": next(
                        (r for r in vuln.get("references", []) if "wordfence.com/threat-intel" in r),
                        f"https://www.wordfence.com/threat-intel/vulnerabilities/id/{vuln_id}"
                    ),
                    "cve": vuln.get("cve") or "N/A",
                })

    return matches, days_desc


def print_report(matches, days_desc):
    print("\n" + "=" * 60)
    print(f"WORDFENCE VULNERABILITY REPORT")
    print(f"Period: {days_desc}")
    print("=" * 60)

    if not matches:
        print("\n✅ No vulnerabilities found for your plugins. All clear!\n")
        return

    print(f"\n⚠️  {len(matches)} vulnerability/vulnerabilities found!\n")

    for i, m in enumerate(sorted(matches, key=lambda x: x["published"], reverse=True), 1):
        print(f"[{i}] {m['plugin_name']}")
        print(f"    Title     : {m['title']}")
        print(f"    Published : {m['published']}")
        print(f"    CVE       : {m['cve']}")
        print(f"    CVSS      : {m['cvss_score']} ({m['cvss_rating']})")
        print(f"    Patched   : {'Yes — update to ' + ', '.join(m['patched_versions']) if m['patched'] else 'NO PATCH YET'}")
        print(f"    Action    : {m['remediation']}")
        print(f"    Details   : {m['details_url']}")
        print()


if __name__ == "__main__":
    if API_KEY == "YOUR_API_KEY_HERE":
        print("ERROR: Please set your API key in the script or via the WORDFENCE_API_KEY environment variable.")
        print("Get a free key at: https://www.wordfence.com/account/integrations")
        exit(1)

    # Load plugins from file
    my_plugins = load_plugins_from_file(PLUGINS_FILE)
    print(f"✓ Loaded {len(my_plugins)} plugin(s) from {PLUGINS_FILE}\n")

    # Get date range preference from user
    date_range_info = get_date_range()
    
    # Fetch vulnerabilities
    vulns = fetch_vulnerabilities()
    if vulns:
        matches, days_desc = check_plugins(vulns, date_range_info, my_plugins)
        print_report(matches, days_desc)
