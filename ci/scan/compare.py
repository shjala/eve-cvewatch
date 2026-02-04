#!/usr/bin/env python3
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Compare two scan result JSON files and report new vulnerabilities.

import json
import sys
import os

def load_scan_results(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        sys.exit(1)

def get_vuln_set(results):
    """
    Parses scan results and returns a dictionary mapping:
    (package_name, vulnerability_id) -> { details }
    """
    vuln_map = {}
    if not results:
        return vuln_map

    for item in results:
        pkg = item.get("package", {})
        pkg_name = pkg.get("name", "Unknown")
        pkg_ver = pkg.get("versionInfo", "Unknown")
        
        vulns = item.get("vulnerabilities", [])
        for vuln in vulns:
            vuln_id = vuln.get("id")
            if not vuln_id:
                continue
            
            # Using (package_name, vuln_id) as identity
            key = (pkg_name, vuln_id)
            vuln_map[key] = {
                "pkg_name": pkg_name,
                "version": pkg_ver,
                "vuln": vuln
            }
    return vuln_map

def extract_fix_version(vuln):
    fixed_versions = set()
    affected = vuln.get("affected", [])
    for aff in affected:
        ranges = aff.get("ranges", [])
        for r in ranges:
            events = r.get("events", [])
            for evt in events:
                if "fixed" in evt:
                    fixed_versions.add(evt["fixed"])
    return ", ".join(sorted(fixed_versions)) if fixed_versions else "Unknown"

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 compare.py <scr_scan.json> <dst_scan.json>")
        sys.exit(1)

    scr_file = sys.argv[1]
    dst_file = sys.argv[2]

    # Validate inputs
    if not os.path.exists(scr_file):
        print(f"Error: source scan file not found: {scr_file}")
        sys.exit(1)
    if not os.path.exists(dst_file):
        print(f"Error: destination scan file not found: {dst_file}")
        sys.exit(1)

    print(f"Comparing destination scan: {dst_file}")
    print(f"     Against source scan: {scr_file}")
    master_data = load_scan_results(scr_file)
    pr_data = load_scan_results(dst_file)

    master_map = get_vuln_set(master_data)
    pr_map = get_vuln_set(pr_data)

    new_vulns = []

    for key, info in pr_map.items():
        if key not in master_map:
            new_vulns.append(info)

    if not new_vulns:
        print("\nNo vulnerabilities introduced.")
        sys.exit(0)

    print(f"\nFound {len(new_vulns)} vulnerabilities:\n")

    for i, info in enumerate(new_vulns, 1):
        vuln = info['vuln']
        print(f" {i}. Package: {info['pkg_name']}")
        print(f"    Version: {info['version']}")
        print(f"    Vuln ID: {vuln.get('id')}")
        print(f"    Severity: {vuln.get('summary', 'No summary available')}")
        print(f"    Fixed In: {extract_fix_version(vuln)}")
        
        # Link to details
        if 'references' in vuln:
            for ref in vuln['references']:
                if ref.get('type') == 'ADVISORY' or ref.get('type') == 'WEB':
                     print(f"    Link: {ref.get('url')}")
                     break
        
        print("-" * 60)

    sys.exit(1)

if __name__ == "__main__":
    main()
