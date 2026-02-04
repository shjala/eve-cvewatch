# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Scan SPDX SBOM files for known vulnerabilities using the OSV database.
# Queries the OSV API for each package and caches results for efficient
# parallel execution across multiple runs.

import requests
import json
import re
import time
import random
import sys
import os
from datetime import datetime
from diskcache import Cache
import csv
import zipfile
import io
from packaging import version as packaging_version

PATH_PATTERN = re.compile(r'[\w./-]+(?:/\w+)+')

def extract_package_info(package):
    # base on https://ossf.github.io/osv-schema/#affectedpackage-field
    name = package.get("name", "Unknown")
    version = package.get("versionInfo", None)
    source_info = package.get("sourceInfo", None)
    package_file_name = package.get("packageFileName", None)
    description = package.get("description", None)
    external_refs = package.get("externalRefs", [])
    
    # extract PURL from externalRefs and remove version
    purl = None
    purl_raw = None
    for ref in external_refs:
        if ref.get("referenceType") == "purl":
            purl_raw = ref.get("referenceLocator", "")
            # strip version from PURL (remove @version part)
            if "@" in purl_raw:
                purl = purl_raw.split("@")[0]
            else:
                purl = purl_raw
            break
    
    ecosystem = None
    if purl:
        if purl.startswith("pkg:apk/"):
            ecosystem = "Alpine"
        elif purl.startswith("pkg:golang/"):
            ecosystem = "Go"
        elif purl.startswith("pkg:npm/"):
            ecosystem = "npm"
        elif purl.startswith("pkg:pypi/"):
            ecosystem = "PyPI"
        elif purl.startswith("pkg:maven/"):
            ecosystem = "Maven"
        elif purl.startswith("pkg:gem/"):
            ecosystem = "RubyGems"
        elif purl.startswith("pkg:cargo/"):
            ecosystem = "crates.io"
        elif purl.startswith("pkg:nuget/"):
            ecosystem = "NuGet"
        elif purl.startswith("pkg:hex/"):
            ecosystem = "Hex"
        elif purl.startswith("pkg:pub/"):
            ecosystem = "Pub"
        elif "kernel" in purl.lower():
            ecosystem = "Linux"

    # if still no luck, try sourceInfo
    # XXX: maybe SPDXID is better source?
    if not ecosystem and source_info:
        if "apk db" in source_info.lower():
            ecosystem = "Alpine"
        elif "go module" in source_info.lower():
            ecosystem = "Go"
    
    # for Go packages, extract module path as name
    if ecosystem == "Go" and purl and purl.startswith("pkg:golang/"):
        go_path = purl.replace("pkg:golang/", "")
        if "#" in go_path:
            # handle subpackages
            module_path, subpkg = go_path.split("#", 1)
            name = f"{module_path}/{subpkg}"
        else:
            name = go_path
    
    # for Linux kernel, name should be "Kernel"
    if ecosystem == "Linux":
        name = "Kernel"
    
    return {
        "name": name,
        "version": version,
        "purl": purl,
        "ecosystem": ecosystem,
        "sourceInfo": source_info,
        "packageFileName": package_file_name,
        "description": description
    }

def parse_spdx(file_path):
    packages = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            spdx_data = json.load(file)
        
        if "packages" not in spdx_data or not spdx_data["packages"]:
            print("No packages found in SPDX file.")
            return None
        
        for package in spdx_data["packages"]:
            package_info = {
                # required fields
                "name": package.get("name", "Unknown"),
                "SPDXID": package.get("SPDXID", "Unknown"),
                "downloadLocation": package.get("downloadLocation", "NOASSERTION"),
                
                # commonly used fields
                "versionInfo": package.get("versionInfo", None),
                "packageFileName": package.get("packageFileName", None),
                "supplier": package.get("supplier", "NOASSERTION"),
                "originator": package.get("originator", "NOASSERTION"),
                "filesAnalyzed": package.get("filesAnalyzed", True),
                "packageVerificationCode": package.get("packageVerificationCode", None),
                "checksums": package.get("checksums", []),
                "homepage": package.get("homepage", None),
                "sourceInfo": package.get("sourceInfo", None),
                
                # license information
                "licenseConcluded": package.get("licenseConcluded", "NOASSERTION"),
                "licenseDeclared": package.get("licenseDeclared", "NOASSERTION"),
                "licenseInfoFromFiles": package.get("licenseInfoFromFiles", []),
                "licenseComments": package.get("licenseComments", None),
                "copyrightText": package.get("copyrightText", "NOASSERTION"),
                
                # descriptive fields
                "summary": package.get("summary", None),
                "description": package.get("description", None),
                "comment": package.get("comment", None),
                
                # external references (for CPE, PURL, etc.)
                "externalRefs": package.get("externalRefs", []),
                
                # package purpose and metadata
                "primaryPackagePurpose": package.get("primaryPackagePurpose", None),
                "releaseDate": package.get("releaseDate", None),
                "builtDate": package.get("builtDate", None),
                "validUntilDate": package.get("validUntilDate", None),
            }
            
            packages.append(package_info)
            
    except FileNotFoundError:
        print(f"Error: SPDX file not found: {file_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in SPDX file: {e}")
        return None
    except Exception as e:
        print(f"Error reading SPDX file: {e}")
        return None
    
    return packages

def load_alpine_db(db_path):
    alpine_db = {}
    alpine_db_by_cpe = {}
    try:
        with open(db_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            for pkg in data:
                secfixes = pkg.get("secfixes", [])
                
                # Index by package name
                if "pkgname" in pkg:
                    alpine_db[pkg["pkgname"]] = secfixes
                
                # Index by CPE values (without version for broader matching)
                if "cpe_alpine" in pkg and pkg["cpe_alpine"]:
                    alpine_db_by_cpe[pkg["cpe_alpine"]] = secfixes
                if "cpe_vendor" in pkg and pkg["cpe_vendor"]:
                    alpine_db_by_cpe[pkg["cpe_vendor"]] = secfixes
                    
        print(f"Loaded {len(alpine_db)} packages from Alpine DB: {db_path}")
        print(f"Loaded {len(alpine_db_by_cpe)} CPE entries from Alpine DB")
    except FileNotFoundError:
        print(f"Warning: Alpine DB file not found: {db_path}")
        alpine_db_by_cpe = {}
    except Exception as e:
        print(f"Error loading Alpine DB: {e}")
        alpine_db_by_cpe = {}
    
    return alpine_db, alpine_db_by_cpe

def get_secfixes_for_package(pkg_info, alpine_db, alpine_db_by_cpe):
    pkg_name = pkg_info.get('name', '')
    
    # Try by package name first
    secfixes = alpine_db.get(pkg_name, [])
    if secfixes:
        return secfixes
    
    # Try by CPE from external refs if name lookup returned nothing
    external_refs = pkg_info.get('externalRefs', [])
    for ref in external_refs:
        if ref.get('referenceType') == 'cpe23Type':
            cpe = ref.get('referenceLocator', '')
            if cpe:
                # Try exact CPE match
                secfixes = alpine_db_by_cpe.get(cpe, [])
                if secfixes:
                    print(f"    Found secfixes via exact CPE match: {cpe}")
                    return secfixes
                
                # Try matching against both cpe_alpine and cpe_vendor patterns
                # by checking if any indexed CPE starts with the same base pattern
                cpe_base = ':'.join(cpe.split(':')[:5])  # Get cpe:2.3:a:vendor:product part
                for indexed_cpe, indexed_secfixes in alpine_db_by_cpe.items():
                    # Check if keys have the same base (first 5 segments)
                    if indexed_cpe.startswith(cpe_base):
                        return indexed_secfixes
                    # Handle case where indexed_cpe is shorter (e.g. less specific)
                    if len(indexed_cpe) < len(cpe_base) and cpe.startswith(indexed_cpe):
                         if len(cpe) == len(indexed_cpe) or cpe[len(indexed_cpe)] == ':':
                             return indexed_secfixes
    
    return []

def load_cvss_bt_cache(csv_path="out/cache/data-source/cvss-bt.csv"):
    cvss_bt_data = {}
    try:
        with open(csv_path, "r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                cve_id = row.get("CVE") or row.get("cve")
                if cve_id:
                    cvss_bt_data[cve_id.lower()] = row
        print(f"Loaded {len(cvss_bt_data)} CVSS BT entries from {csv_path}")
    except FileNotFoundError:
        print(f"Warning: CVSS BT file not found: {csv_path}")
    except Exception as e:
        print(f"Error loading CVSS BT data: {e}")
    
    return cvss_bt_data

def get_osv_vulnerabilities(name=None, version=None, ecosystem=None, purl=None, max_pages=100):
    """Note: Use either (name + ecosystem) OR purl, but not both."""
    url = "https://api.osv.dev/v1/query"
    payload = {}
    
    if purl:
        # when using purl, do NOT include name or ecosystem
        payload["package"] = {"purl": purl}
    elif name and ecosystem:
        # when using name, ecosystem is required
        payload["package"] = {
            "name": name,
            "ecosystem": ecosystem
        }
    else:
        print("Error: Must provide either (name AND ecosystem) OR purl")
        return None
    
    if version:
        payload["version"] = version
    
    all_vulns = []
    page_token = None
    page_count = 0
    try:
        while page_count < max_pages:
            page_count += 1
            # add page_token if we're fetching subsequent pages
            if page_token:
                payload["page_token"] = page_token
            elif "page_token" in payload:
                # Remove page_token from payload if we're back to first page
                del payload["page_token"]
            
            response = requests.post(url, json=payload, timeout=30)
            if response.status_code != 200:
                print(f"Error: HTTP {response.status_code}")
                if response.text:
                    print(f"Response: {response.text[:200]}")
                return None
            
            data = response.json()
            if "vulns" in data and data["vulns"]:
                all_vulns.extend(data["vulns"])
            elif "next_page_token" in data and data["next_page_token"]:
                # Rare case: only page token, no vulnerabilities yet (API timeout)
                print(f"  Page {page_count}: no vulns yet, continuing with next page token...")
            
            # Check if there are more pages
            if "next_page_token" in data and data["next_page_token"]:
                page_token = data["next_page_token"]
            else:
                break
        
        if page_count >= max_pages:
            print(f"Warning: Reached max page limit ({max_pages})")
        
        return {"vulns": all_vulns} if all_vulns else {}
        
    except requests.exceptions.Timeout:
        print(f"Error: Request timed out after fetching {len(all_vulns)} vulnerabilities")
        return {"vulns": all_vulns} if all_vulns else None
    except Exception as e:
        print(f"Error querying OSV API: {e}")
        return {"vulns": all_vulns} if all_vulns else None

def load_linux_kernel_db(cache_dir="out/cache/osv"):
    os.makedirs(cache_dir, exist_ok=True)
    zip_path = os.path.join(cache_dir, "Linux_all.zip")
    url = "https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip"
    
    should_download = True
    if os.path.exists(zip_path):
        # Check if file is older than 24 hours
        file_age = time.time() - os.path.getmtime(zip_path)
        if file_age < 86400:
            should_download = False
            print(f"Using cached Linux DB (age: {file_age/3600:.1f} hours)")
    
    if should_download:
        print(f"Downloading Linux DB from {url}...")
        try:
            response = requests.get(url, timeout=120)
            if response.status_code == 200:
                with open(zip_path, "wb") as f:
                    f.write(response.content)
            else:
                print(f"Error downloading Linux DB: {response.status_code}")
                if not os.path.exists(zip_path):
                    return []
        except Exception as e:
            print(f"Exception downloading Linux DB: {e}")
            if not os.path.exists(zip_path):
                return []

    print("Loading Linux DB into memory...")
    vulns = []
    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            for filename in z.namelist():
                if filename.endswith(".json"):
                    with z.open(filename) as f:
                        try:
                            vulns.append(json.load(f))
                        except: pass
    except Exception as e:
        print(f"Error reading Linux DB zip: {e}")
        return []

    print(f"Loaded {len(vulns)} Linux vulnerability records.")
    return vulns


# this is hacky 
def get_eve_kernel_version(eve_tag):
    ref = eve_tag
    if eve_tag.startswith("master"):
        ref = "master"
    
    urls = [
        f"https://raw.githubusercontent.com/lf-edge/eve/{ref}/kernel-version.mk",
        f"https://raw.githubusercontent.com/lf-edge/eve/refs/tags/{ref}/kernel-version.mk"
    ]
    
    content = None
    for url in urls:
        print(f"Fetching kernel version from {url}...")
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                content = resp.text
                break
        except Exception as e:
            print(f"Warning: Failed to fetch {url}: {e}")
            
    if not content:
        print("Error: Could not fetch kernel-version.mk")
        return None
    
    lines = content.split('\n')
    in_amd64 = False
    kernel_ver = None
    
    for line in lines:
        line = line.strip()
        # Detect start of amd64 block
        if line.startswith('ifeq') and 'amd64' in line and 'ZARCH' in line:
            in_amd64 = True
            continue
        # Skip non-amd64 ZARCH blocks
        if line.startswith('ifeq') and 'ZARCH' in line and not in_amd64:
            pass 
            
        if in_amd64:
            # Stop if we hit another ZARCH block (e.g. else ifeq ($(ZARCH), arm64))
            if 'ZARCH' in line and ('else' in line or 'ifeq' in line):
                break
                
            if line.startswith('KERNEL_VERSION='):
                val = line.split('=')[1].strip()
                if val:
                    kernel_ver = val

    return kernel_ver


def check_linux_kernel_vulns(version_str, db):
    found_vulns = []
    try:
        target_ver = packaging_version.parse(version_str)
    except:
        return []

    for vuln in db:
        affected_list = vuln.get('affected', [])
        for affected in affected_list:
            pkg = affected.get('package', {})
            # Match strictly against "Linux" ecosystem. Name usually "Kernel" or "Linux".
            if pkg.get('ecosystem') != 'Linux':
                continue
                
            ranges = affected.get('ranges', [])
            for r in ranges:
                if r.get('type') in ['SEMVER', 'ECOSYSTEM']:
                    events = r.get('events', [])
                    is_vuln_in_range = False
                    
                    for event in events:
                        if 'introduced' in event:
                            intro = event['introduced']
                            try:
                                if intro == '0' or target_ver >= packaging_version.parse(intro):
                                    is_vuln_in_range = True
                            except: pass
                        elif 'fixed' in event:
                            fixed = event['fixed']
                            try:
                                if target_ver >= packaging_version.parse(fixed):
                                    is_vuln_in_range = False
                            except: pass
                        elif 'last_affected' in event:
                            last = event['last_affected']
                            try:
                                if target_ver > packaging_version.parse(last):
                                    is_vuln_in_range = False
                            except: pass
                            
                    if is_vuln_in_range:
                        found_vulns.append(vuln)
                        break 
    return found_vulns
    
def get_package_vulnerabilities(package_name, version, ecosystem, max_retries=10):
    delay = 0.1
    for attempt in range(max_retries):
        try:
            vulnerabilities = get_osv_vulnerabilities(
                name=package_name, 
                version=version, 
                ecosystem=ecosystem
            )
            return vulnerabilities
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                sleep_time = delay * (2 ** attempt) + random.uniform(0, 0.1)
                print(f"Retrying in {sleep_time:.2f} seconds...")
                time.sleep(sleep_time)
    
    print("Max retries reached. Moving on...")
    return None

def get_cache_dir():
    current_date = datetime.now().strftime("%Y-%m-%d")
    cache_dir = os.path.join("/tmp", f"cve_cache_{current_date}")
    return cache_dir

def main(eve_tag, sbom_file, cvss_bt_path, alpine_db_path, output_dir):
    cache_dir = get_cache_dir()
    cache = Cache(cache_dir)
    spdx_packages = parse_spdx(sbom_file)
    if not spdx_packages:
        print("No SPDX data found at file: " + sbom_file)
        return
    
    print(f"Found {len(spdx_packages)} packages in SPDX file")

    cvss_data = load_cvss_bt_cache(cvss_bt_path)
    if not cvss_data:
        print("No CVSS BT data loaded.")
        cvss_data = {}

    alpine_db, alpine_db_by_cpe = load_alpine_db(alpine_db_path)
    linux_db = None

    # Check for Linux kernel in packages
    kernel_found = False
    for pkg in spdx_packages:
        p_info = extract_package_info(pkg)
        if p_info['ecosystem'] == 'Linux' or p_info['name'] == 'Kernel' or p_info['name'] == 'Linux':
            kernel_found = True
            break
            
    if not kernel_found:
        print("Linux Kernel NOT found in SBOM. Fetching from remote...")
        remote_k_ver = get_eve_kernel_version(eve_tag)
        if remote_k_ver:
            print(f"Adding remote Linux Kernel version: {remote_k_ver}")
            clean_ver = remote_k_ver
            if clean_ver.startswith('v'):
                clean_ver = clean_ver[1:]
            
            spdx_packages.append({
                "name": "Kernel",
                "versionInfo": clean_ver,
                "externalRefs": [
                    {
                        "referenceType": "purl", 
                        "referenceLocator": f"pkg:generic/kernel@{clean_ver}"
                    }
                ]
            })
        else:
             print("Warning: Failed to determine remote kernel version.")

    release_vulns = []
    for pkg in spdx_packages:
        pkg_info = extract_package_info(pkg)
        print(f"Checking package: {pkg_info['name']} Version: {pkg_info['version']} Ecosystem: {pkg_info['ecosystem']}")
        
        vulns_data = None

        if pkg_info['ecosystem'] == 'Linux' or pkg_info['name'] == 'Kernel':
            pkg_info['version'] = re.match(r'\d+\.\d+\.\d+', pkg_info['version'])[0]
            print(f"    Checking Linux kernel vulnerabilities for version {pkg_info['version']}...")
            if linux_db is None:
                linux_db = load_linux_kernel_db()
            print(f"    Checking against local Linux DB...")
            vulns_list = check_linux_kernel_vulns(pkg_info['version'], linux_db)
            print(f"    Found {len(vulns_list)} Linux kernel vulnerabilities.")
            vulns_data = {"vulns": vulns_list}
        else:
            cache_key = (pkg_info['name'], pkg_info['version'], pkg_info['ecosystem'], pkg_info['purl'])
            if cache_key in cache:
                vulns_data = cache[cache_key]
                print("    Retrieved vulnerabilities from cache.")
            else :
                # try to get vulnerabilities from first by package name+ecosystem and version
                if pkg_info["name"] and pkg_info["ecosystem"]:
                    vulns_data = get_package_vulnerabilities(
                        package_name=pkg_info["name"],
                        version=pkg_info["version"],
                        ecosystem=pkg_info["ecosystem"]
                    )
                elif not pkg_info["purl"]:
                     print(f"    Warning: Skipping {pkg_info['name']} - Missing Ecosystem and PURL")

                if not vulns_data and pkg_info["purl"]:
                    # if no results, also try with PURL+version
                    vulns_data = get_osv_vulnerabilities(
                        purl=pkg_info["purl"],
                        version=pkg_info["version"]
                    )
            
                # store in cache ONLY if result is valid (non-None)
                # We don't want to cache temporary network errors
                if vulns_data is not None:
                    cache[cache_key] = vulns_data

        if vulns_data is None:
            print("    Skipping due to API error.")
        elif not vulns_data:
            print("    No vulnerabilities found.")
            
        if vulns_data and "vulns" in vulns_data:
            pkg_secfixes = get_secfixes_for_package(pkg, alpine_db, alpine_db_by_cpe)
            pkg_secfixes_set = set(s.lower() for s in pkg_secfixes)
            
            valid_vulns = []
            for vuln in vulns_data["vulns"]:
                vuln_id = vuln.get('id', 'Unknown')
                
                vuln['exploitablity'] = []
                # gather all CVEs
                cves = vuln.get('aliases', [])
                for entry in vuln.get('upstream', []):
                    if entry not in cves:
                        cves.append(entry)
                
                # Check secfixes
                in_secfixes = False
                for c in cves:
                    if c.lower() in pkg_secfixes_set:
                        in_secfixes = True
                        print(f"    Skipping {vuln_id} (alias {c}) as it is in secfixes for {pkg_info['name']}")
                        break
                
                if in_secfixes:
                    continue

                # check CVSS BT data for each CVE
                print(f"  Found vulnerability: {vuln_id} with aliases: {cves}")
                exploits = [ cvss_data[e.lower()] for e in cves if e.lower() in cvss_data ]
                if exploits:
                    vuln['exploitablity'] = exploits
                    print(f"    Added exploitability data for {vuln_id}")
                
                valid_vulns.append(vuln)

            if valid_vulns:
                release_vulns.append({
                    "package": pkg,
                    "vulnerabilities": valid_vulns
                })
        
    print(f"Total vulnerabilities found: {len(release_vulns)}")

    # Close cache to ensure all writes are flushed
    cache.close()
    print(f"Cache saved to {cache_dir} with {len(cache)} entries")

    # save results to JSON file
    output_file = os.path.join(output_dir, f"scan_results_{eve_tag.replace('/', '_')}.json")
    try:
        with open(output_file, "w", encoding="utf-8") as out_file:
            json.dump(release_vulns, out_file, indent=2)
        print(f"Scan results saved to {output_file}")
    except Exception as e:
        print(f"Error saving scan results: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python scanner/scanner.py <eve_tag> <spdx_sbom_file> <cvss_bt_path> <alpine_db_path> <output_dir>")
        sys.exit(1)
    else:
        main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
