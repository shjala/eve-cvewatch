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

def load_ignore_list(filepath):
    """
    Reads an ignore file and returns a set of vulnerability IDs.
    Format: one ID per line (CVE-..., GHSA-..., etc.), '#' starts a
    comment, blank lines are skipped. Matching is case-insensitive.
    """
    ignored = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                entry = line.split('#', 1)[0].strip()
                if entry:
                    ignored.add(entry.upper())
    except Exception as e:
        print(f"Error loading ignore file {filepath}: {e}")
        sys.exit(1)
    return ignored

def is_ignored(vuln, ignore_ids):
    """True if the vuln ID or any of its aliases is in the ignore set."""
    if not ignore_ids:
        return False
    ids = [vuln.get("id")]
    ids += vuln.get("aliases") or []
    ids += vuln.get("upstream") or []
    return any(i and i.upper() in ignore_ids for i in ids)

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
    if len(sys.argv) not in (3, 4):
        print("Usage: python3 compare.py <scr_scan.json> <dst_scan.json> [ignore_file]")
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

    ignore_ids = set()
    if len(sys.argv) == 4:
        ignore_ids = load_ignore_list(sys.argv[3])
        print(f"Ignore file found: {sys.argv[3]}")
        print(f"Loaded {len(ignore_ids)} ignored vulnerability IDs:")
        for ignored_id in sorted(ignore_ids):
            print(f"  {ignored_id}")

    print(f"Comparing destination scan: {dst_file}")
    print(f"     Against source scan: {scr_file}")
    master_data = load_scan_results(scr_file)
    pr_data = load_scan_results(dst_file)

    master_map = get_vuln_set(master_data)
    pr_map = get_vuln_set(pr_data)

    new_vulns = []
    ignored_vulns = []

    for key, info in pr_map.items():
        if key in master_map:
            continue
        if is_ignored(info["vuln"], ignore_ids):
            ignored_vulns.append(info)
            continue
        new_vulns.append(info)

    if ignored_vulns:
        print(f"\nIgnored {len(ignored_vulns)} vulnerabilities listed in the ignore file:")
        for info in ignored_vulns:
            print(f"  {info['vuln'].get('id')} (package: {info['pkg_name']})")

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
        
        details = vuln.get('details', '')
        if details:
            # simple wrap or limit
            if len(details) > 200:
                details = details[:197] + "..."
            print(f"    Details: {details.replace(chr(10), ' ')}")

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
