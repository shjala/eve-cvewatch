#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Scan a PR for vulnerabilities and compare with master.
# Usage: ./pr-scan.sh <GIT_URL> [REVISION]

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <GIT_URL> [REVISION]"
    echo "Example: $0 https://github.com/lf-edge/eve.git master"
    exit 1
fi

GIT_URL="$1"
REVISION="${2:-HEAD}"

# Directories
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# cd "$BASE_DIR" 
source "$BASE_DIR/common.sh"

SCAN_DIR="out/scans"
CACHE_SOURCE_DIR="out/cache/data-source"
REPORT_FILE="out/scan_report.txt"
TEMP_DIR=""
ALPINE_CACHE=""
EVE_REPO_DIR=""

setup_environment() {
    setup_common_env
}

cleanup() {
    if [ -n "$TEMP_DIR" ]; then
        if [[ "$TEMP_DIR" == /tmp/* ]]; then
             cleanup_files "$TEMP_DIR"
        fi
    fi
    cleanup_files "$ALPINE_CACHE"
}
trap cleanup EXIT INT TERM


build_current_eve() {
    local sbom_dest="$1"
    local version_dest="$2"

    log_info "Building SBOM..."
    log_cmd make HV=kvm PLATFORM=generic ZARCH=amd64 LINUXKIT_PKG_TARGET=build pkgs sbom
    
    log_info "Getting SBOM path..."
    local sbom_rel_path
    if ! sbom_rel_path=$(make sbom_info 2>/dev/null); then
        log_warn "make sbom_info failed, trying to find file..."
    fi

    if [ -z "$sbom_rel_path" ] || [ ! -f "$sbom_rel_path" ]; then
        # Fallback to find
        sbom_rel_path=$(find dist -name "*.spdx.json" | head -n 1)
    fi
    
    if [ -z "$sbom_rel_path" ] || [ ! -f "$sbom_rel_path" ]; then
        log_error "SBOM file not found after build."
        return 1
    fi

    log_info "Found SBOM at $sbom_rel_path"
    cp "$sbom_rel_path" "$sbom_dest"
    
    # Get Alpine version
    if [ -f "pkg/alpine/Dockerfile" ]; then
        local alpine_version
        alpine_version=$(grep -oE "ARG ALPINE_VERSION=[0-9]+\.[0-9]+" pkg/alpine/Dockerfile | head -n 1 | cut -d= -f2)
        if [ -n "$alpine_version" ]; then
            if [[ ! "$alpine_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                alpine_version="${alpine_version}.0"
            fi
            echo "$alpine_version" > "$version_dest"
        else
            log_error "Could not find ALPINE_VERSION in Dockerfile"
            return 1
        fi
    else
        log_error "pkg/alpine/Dockerfile not found"
        return 1
    fi
}

# Clone EVE from GIT_URL and checkout REVISION
clone_and_build_eve() {
    log_info "Cloning EVE from $GIT_URL..."
    EVE_REPO_DIR="$TEMP_DIR/eve"
    log_cmd git clone "$GIT_URL" "$EVE_REPO_DIR"
    
    pushd "$EVE_REPO_DIR" > /dev/null
    if [ "$REVISION" != "HEAD" ]; then
        log_info "Checking out $REVISION..."
        log_cmd git checkout "$REVISION"
    fi
    
    local commit_info
    commit_info=$(git log -1 --format='%h %s')
    echo "$commit_info" > "$TEMP_DIR/pr-commit-info"
    log_info "PR Commit: $commit_info"

    # Save the CVE ignore file from the PR revision, if present. The repo
    # tree may be re-checked out to master later, so keep a copy.
    if [ -f ".cve-ignore" ]; then
        cp ".cve-ignore" "$TEMP_DIR/cve-ignore"
        log_info "Found .cve-ignore in the EVE repo"
    fi

    if ! build_current_eve "$TEMP_DIR/pr-sbom.json" "$TEMP_DIR/pr-alpine-version"; then
        log_error "Failed to build PR version"
        popd > /dev/null
        exit 1
    fi
    
    popd > /dev/null
}

generate_pr_alpine_db() {
    local alpine_version
    alpine_version=$(cat "$TEMP_DIR/pr-alpine-version")
    local alpine_tag="v$alpine_version"
    local db_path="$CACHE_SOURCE_DIR/alpine_packages_${alpine_version}.json"
    
    generate_alpine_db "$alpine_tag" "$db_path"
}

get_master_info() {
    log_info "Getting Master SBOM..."
    local master_sbom_path="$TEMP_DIR/master-sbom.json"
    local master_version_path="$TEMP_DIR/master-alpine-version"
    
    # Try to get from docker first
    if log_cmd bash "$BASE_DIR/eve/get_sbom.sh" "master" "$master_sbom_path"; then
        # We need master's alpine version.
        # Fetch from GitHub raw content
        log_info "Fetching Master Alpine version..."
        local master_version
        if ! master_version=$(get_remote_alpine_version "master"); then
            log_error "Could not retrieve master alpine version"
            exit 1
        fi
        echo "$master_version" > "$master_version_path"

        # Fetch master commit info
        log_info "Fetching Master commit info..."
        local master_commit_info
        if master_commit_info=$(curl -s "https://api.github.com/repos/lf-edge/eve/commits/master" | jq -r '.sha[0:8] + " " + .commit.message' | head -n 1); then
             echo "$master_commit_info" > "$TEMP_DIR/master-commit-info"
             log_info "Master Commit (Remote): $master_commit_info"
        else
             echo "Unknown Master Commit" > "$TEMP_DIR/master-commit-info"
        fi

    else
        log_warn "Failed to get master SBOM from docker image. Falling back to build from source."
        
        if [ -z "${EVE_REPO_DIR:-}" ] || [ ! -d "$EVE_REPO_DIR" ]; then
             log_error "EVE source directory not found. Cannot build master."
             exit 1
        fi

        pushd "$EVE_REPO_DIR" > /dev/null
        log_info "Checking out master..."
        log_cmd git checkout master
        
        local commit_info
        commit_info=$(git log -1 --format='%h %s')
        echo "$commit_info" > "$TEMP_DIR/master-commit-info"
        log_info "Master Commit: $commit_info"

        if ! build_current_eve "$master_sbom_path" "$master_version_path"; then
             log_error "Failed to build master from source."
             popd > /dev/null
             exit 1
        fi
        popd > /dev/null
    fi
    
    local master_version
    master_version=$(cat "$master_version_path")
    
    local master_alpine_tag="v$master_version"
    local master_db_path="$CACHE_SOURCE_DIR/alpine_packages_${master_version}.json"
    
    generate_alpine_db "$master_alpine_tag" "$master_db_path"
}

run_scans() {
    local cvss_bt_path="$CACHE_SOURCE_DIR/cvss-bt.csv"
    
    # Get versions
    local pr_version
    pr_version=$(cat "$TEMP_DIR/pr-alpine-version")
    local pr_db_path="$CACHE_SOURCE_DIR/alpine_packages_${pr_version}.json"

    local master_version
    master_version=$(cat "$TEMP_DIR/master-alpine-version")
    local master_db_path="$CACHE_SOURCE_DIR/alpine_packages_${master_version}.json"

    local pr_commit="Unknown"
    [ -f "$TEMP_DIR/pr-commit-info" ] && pr_commit=$(cat "$TEMP_DIR/pr-commit-info")
    
    local master_commit="Unknown"
    [ -f "$TEMP_DIR/master-commit-info" ] && master_commit=$(cat "$TEMP_DIR/master-commit-info")

    # Scan PR
    log_info "------------------------------------------------------------"
    log_info "Starting PR Scan (Alpine v$pr_version)..."
    log_info "Commit: $pr_commit"
    log_info "PR SBOM Checksum: $(md5sum "$TEMP_DIR/pr-sbom.json" | awk '{print $1}')"
    log_info "------------------------------------------------------------"
    local pr_sbom_path="$TEMP_DIR/pr-sbom.json"
    
    if ! run_cve_scanner "pr" "$pr_sbom_path" "$pr_db_path" "$TEMP_DIR" "$cvss_bt_path"; then
        log_error "PR scan failed"
        exit 1
    fi
    log_info "------------------------------------------------------------"
    log_info "PR Scan Finished."
    log_info "------------------------------------------------------------"

    # Scan Master
    log_info "------------------------------------------------------------"
    log_info "Starting Master Scan (Alpine v$master_version)..."
    log_info "Commit: $master_commit"
    log_info "Master SBOM Checksum: $(md5sum "$TEMP_DIR/master-sbom.json" | awk '{print $1}')"
    log_info "------------------------------------------------------------"
    local master_sbom_path="$TEMP_DIR/master-sbom.json"
    
    if ! run_cve_scanner "master" "$master_sbom_path" "$master_db_path" "$TEMP_DIR" "$cvss_bt_path"; then
        log_error "Master scan failed"
        exit 1
    fi
    log_info "------------------------------------------------------------"
    log_info "Master Scan Finished."
    log_info "------------------------------------------------------------"
}

run_compare() {
    log_info "Comparing results..."
    if [ -f "$TEMP_DIR/cve-ignore" ]; then
        log_info "Applying CVE ignore list from the EVE repo (.cve-ignore)"
        log_cmd "$BASE_DIR/compare.sh" "$TEMP_DIR/scan_results_master.json" "$TEMP_DIR/scan_results_pr.json" "$REPORT_FILE" "$TEMP_DIR/cve-ignore"
    else
        log_cmd "$BASE_DIR/compare.sh" "$TEMP_DIR/scan_results_master.json" "$TEMP_DIR/scan_results_pr.json" "$REPORT_FILE"
    fi
}

# Main execution
LOG_FILE="$LOG_DIR/pr-scan.log"
export LOG_FILE

setup_environment

log_info "Running PR scan..."
download_cvss_db "$CACHE_SOURCE_DIR"

log_info "Building EVE from $GIT_URL : $REVISION "
clone_and_build_eve
generate_pr_alpine_db

log_info "Getting Master Info..."
get_master_info

log_info "Running Scans..."
run_scans
log_info "Scan Phase Completed."

# Compare results (allow failure to propagate, output to stdout)
set +e
run_compare
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -ne 0 ]; then
    log_error "Comparison failed (Exit code: $EXIT_CODE)"
    exit $EXIT_CODE
fi

log_info "Done."
