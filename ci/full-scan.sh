#!/bin/bash
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
set -euo pipefail


LOG_DIR="out/logs"
SCAN_DIR="out/scans"
CACHE_SOURCE_DIR="out/cache/data-source"
CVSS_BT_URL="https://api.github.com/repos/t0sche/cvss-bt/releases/latest"
EVE_COMMITS_URL="https://api.github.com/repos/lf-edge/eve/commits/master"
REPO_URL="https://github.com/lf-edge/eve.git"
SUPPORTED_VERSIONS=("16.0" "14.5" "13.4" "12.0" "11.0" "10.4" "9.4")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

PARALLEL=false
FETCH_ONLY=false
ALL_TAGS=""
ALPINE_CACHE=""
TEMP_DIR=""

cleanup() {
    cleanup_files "$TEMP_DIR" "$ALPINE_CACHE"
}
trap cleanup EXIT

setup_environment() {
    setup_common_env
}

fetch_eve_tags() {
    log_info "Cloning EVE repository..." >&2
    if ! git clone --quiet --branch master --single-branch --depth 1 $REPO_URL "$TEMP_DIR/eve_clone"; then
        log_error "Failed to clone repository"
        return 1
    fi
    
    pushd "$TEMP_DIR/eve_clone" > /dev/null

    log_info "Fetching tags..." >&2
    if ! git fetch --tags; then
        log_error "Failed to fetch tags"
        popd > /dev/null
        return 1
    fi

    local all_lts_tags
    all_lts_tags=$(git tag -l '*-lts')
    if [ -z "$all_lts_tags" ]; then
        log_error "No LTS tags found in the repository"
        popd > /dev/null
        return 1
    fi
    
    local lts_tags_raw=""
    for version in "${SUPPORTED_VERSIONS[@]}"; do
        local version_tags
        version_tags=$(echo "$all_lts_tags" | grep "^${version}\.")
        if [ -n "$version_tags" ]; then
            lts_tags_raw="$lts_tags_raw $version_tags"
            local count
            count=$(echo "$version_tags" | wc -w)
            log_info "Found $count tags for $version.x" >&2
        else
            log_info "No tags found for $version.x" >&2
        fi
    done

    if [ -z "$lts_tags_raw" ]; then
        log_error "No supported LTS tags found"
        popd > /dev/null
        return 1
    fi

    # sort tags
    local sorted_lts_tags
    sorted_lts_tags=$(echo "$lts_tags_raw" | tr ' ' '\n' | sort -V -r | tr '\n' ' ')

    # get master
    log_info "Fetching latest master commit..." >&2
    local latest_commit_hash
    latest_commit_hash=$(curl -s $EVE_COMMITS_URL | jq -r '.sha' | cut -c 1-8)
    if [ -z "$latest_commit_hash" ] || [ "$latest_commit_hash" = "null" ]; then
        log_error "Failed to fetch the latest commit hash"
        popd > /dev/null
        return 1
    fi
    local master_tag="master-$latest_commit_hash"
    log_info "Latest master: $master_tag" >&2

    popd > /dev/null
    
    echo "$master_tag $sorted_lts_tags"
}

prefetch_alpine_versions() {
    local tags="$1"
    for tag in $tags; do
        local eve_arg
        if [[ "$tag" == master-* ]]; then
            eve_arg="master"
        else
            eve_arg="$tag"
        fi
        
        log_info "Pre-fetching Alpine version for $tag..."
        local alpine_version
        if ! alpine_version=$(get_remote_alpine_version "$eve_arg"); then
            log_error "Failed to get Alpine version for $tag"
            continue
        fi
        echo "$tag|v${alpine_version}" >> "$ALPINE_CACHE"
        log_info "  $tag -> Alpine ${alpine_version}"
        sleep 0.5
    done
}

prep_tags() {
    local tag="$1"
    log_info "=== Processing tag: $tag ==="
    
    local eve_arg
    if [[ "$tag" == master-* ]]; then
        eve_arg="master"
    else
        eve_arg="$tag"
    fi
    
    local alpine_tag
    alpine_tag=$(grep "^${tag}|" "$ALPINE_CACHE" | cut -d'|' -f2)
    
    if [ -z "$alpine_tag" ]; then
        log_error "Alpine version not found for $tag"
        return 1
    fi
    
    local db_path="out/cache/aports/${alpine_tag}_packages.json"
    local sbom_path="out/cache/sbom/eve-sbom-${tag}.json"
    
    log_info "  - Alpine tag: $alpine_tag"
    log_info "  - DB path: $db_path"
    log_info "  - SBOM path: $sbom_path"
    
    log_info "  - Building Alpine package info..."
    if ! generate_alpine_db "$alpine_tag" "$db_path"; then
        log_warn "Failed to build Alpine package info for $tag"
    fi
    
    log_info "  - Getting SBOM..."
    if ! log_cmd bash eve/get_sbom.sh "$eve_arg" "$sbom_path"; then
        log_warn "Failed to get SBOM for $tag"
    fi
}

run_scanner() {
    local tag="$1"
    local sbom_path="$2"
    local eve_arg="$3"

    local alpine_tag
    alpine_tag=$(grep "^${tag}|" "$ALPINE_CACHE" | cut -d'|' -f2)
    if [ -z "$alpine_tag" ]; then
        log_error "Alpine version not found for $tag"
        return 1
    fi
    
    local db_path="out/cache/aports/${alpine_tag}_packages.json"
    
    # Ensure DB exists
    if [ ! -f "$db_path" ]; then
        if ! generate_alpine_db "$alpine_tag" "$db_path"; then
            log_warn "Failed to build Alpine package info for $tag"
            return 1
        fi
    fi

    local cvss_bt_path="out/cache/data-source/cvss-bt.csv"

    log_info "  - DB path: $db_path"
    log_info "  - SBOM path: $sbom_path"
    
    log_info "  - Running scanner..."
    if ! run_cve_scanner "$eve_arg" "$sbom_path" "$db_path" "$SCAN_DIR" "$cvss_bt_path"; then
        log_warn "Scanner failed for $tag"
        return 1
    fi
    log_info "  - Completed scanning $tag"
}

# main starts here...
while [[ $# -gt 0 ]]; do
  case $1 in
    -p|--parallel)
      PARALLEL=true
      shift
      ;;
    -f|--fetch-only)
      FETCH_ONLY=true
      shift
      ;;
    *)
      log_error "Unknown option: $1"
      exit 1
      ;;
  esac
done

LOG_FILE="$LOG_DIR/full-scan.log"
export LOG_FILE

setup_environment
download_cvss_db "$CACHE_SOURCE_DIR" "$CVSS_BT_URL"

# fetch all eve lts tags + master
log_info "Fetching EVE tags..."
ALL_TAGS=$(fetch_eve_tags)
if [ -z "$ALL_TAGS" ]; then
    log_error "Error: Failed to fetch tags."
    exit 1
fi

# prefetch Alpine versions
prefetch_alpine_versions "$ALL_TAGS"

# prep (get SBOMs and generate alpine DBs)
for TAG in $ALL_TAGS; do
    prep_tags "$TAG"
done

if [ "$FETCH_ONLY" = true ]; then
  log_info "Fetch-only mode enabled. Skipping scanning."
  log_info "All processing completed!"
  exit 0
fi

log_info "Start CVE scanning..."
if [ "$PARALLEL" = true ]; then
  log_info "Running scanners in parallel..."
  PIDS=()
  TAG_ARRAY=()
  
  for TAG in $ALL_TAGS; do
    if [[ "$TAG" == master-* ]]; then
      EVE_ARG="master"
    else
      EVE_ARG="$TAG"
    fi
    SBOM_PATH="cache/sbom/eve-sbom-${TAG}.json"
    
    (
      run_scanner "$TAG" "$SBOM_PATH" "$EVE_ARG"
    ) > "${LOG_DIR}/scanner-${TAG}.log" 2>&1 &
    
    PID=$!
    PIDS+=("$PID")
    TAG_ARRAY+=("$TAG")
    log_info "Started scanner for $TAG (PID: $PID) - log: ${LOG_DIR}/scanner-${TAG}.log"
  done
  
  log_info ""
  log_info "Waiting for all scanners to complete..."
  FAILED=0
  for i in "${!PIDS[@]}"; do
    PID=${PIDS[$i]}
    TAG=${TAG_ARRAY[$i]}
    if wait $PID; then
      log_info "✓ Scanner for $TAG completed successfully"
    else
      log_error "✗ Scanner for $TAG failed (check ${LOG_DIR}/scanner-${TAG}.log)"
      FAILED=$((FAILED + 1))
    fi
  done
  
  if [ $FAILED -eq 0 ]; then
    log_info "All scanners completed successfully!"
  else
    log_warn "$FAILED scanner(s) failed"
  fi
else
  for TAG in $ALL_TAGS; do
    log_info "=== Scanning tag: $TAG ==="
    if [[ "$TAG" == master-* ]]; then
      EVE_ARG="master"
    else
      EVE_ARG="$TAG"
    fi
     SBOM_PATH="cache/sbom/eve-sbom-${TAG}.json"
     run_scanner "$TAG" "$SBOM_PATH" "$EVE_ARG"
  done
  
  log_info "All processing completed!"
fi
