#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Retrieve Software Bill of Materials (SBOM) from EVE-OS Docker images.
# Pulls the specified EVE image, extracts the SPDX SBOM, and saves it locally.
set -euo pipefail

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CI_DIR="$(dirname "$SCRIPT_DIR")"

# Source common functions if available
if [ -f "$CI_DIR/common.sh" ]; then
    source "$CI_DIR/common.sh"
fi

EVE_TAG="${1:-}"
SBOM_PATH="${2:-}"

if [ -z "$EVE_TAG" ] || [ -z "$SBOM_PATH" ]; then
    log_error "EVE tag and SBOM path are required"
    log_error "Usage: $0 <EVE_TAG> <SBOM_PATH>"
    exit 1
fi

EVE_COMMITS_URL="https://api.github.com/repos/lf-edge/eve/commits/master"

# create directory if needed
mkdir -p "$(dirname "$SBOM_PATH")"

# handle master branch
if [[ "$EVE_TAG" == "master" ]]; then
    log_info "Fetching latest master commit..."
    latest_commit_hash=$(curl -s $EVE_COMMITS_URL | jq -r '.sha' | cut -c 1-8)
    if [ -z "$latest_commit_hash" ] || [ "$latest_commit_hash" = "null" ]; then
        log_error "Failed to fetch the latest commit hash"
        exit 1
    fi

    TAG="master-$latest_commit_hash"
  
    if [ -f "$SBOM_PATH" ]; then
        log_info "SKIP: SBOM already exists at $SBOM_PATH"
        exit 0
    fi
  
    log_info "Processing master: $TAG"

    if ! docker pull lfedge/eve:0.0.0-master-$latest_commit_hash-kvm-amd64; then
        log_error "Failed to pull docker image for master $latest_commit_hash"
        exit 1
    fi

    if ! docker run --rm lfedge/eve:0.0.0-master-$latest_commit_hash-kvm-amd64 sbom > $SBOM_PATH; then
        log_error "Failed to generate SBOM for master $latest_commit_hash"
        exit 1
    fi

    if ! docker rmi lfedge/eve:0.0.0-master-$latest_commit_hash-kvm-amd64; then
        log_warn "Failed to remove docker image for master $latest_commit_hash"
    fi

    log_info "Successfully saved SBOM for master-$latest_commit_hash"
    exit 0
fi

# handle LTS tag
if [ -f "$SBOM_PATH" ]; then
    log_info "SKIP: SBOM already exists at $SBOM_PATH"
    exit 0
fi

log_info "Processing LTS tag: $EVE_TAG"

if ! docker pull lfedge/eve:$EVE_TAG; then
    log_error "Failed to pull docker image for tag $EVE_TAG"
    exit 1
fi

if ! docker run --rm lfedge/eve:$EVE_TAG sbom > $SBOM_PATH; then
    log_error "Failed to generate SBOM for tag $EVE_TAG"
    exit 1
fi

if ! docker rmi lfedge/eve:$EVE_TAG; then
    log_warn "Failed to remove docker image for tag $EVE_TAG"
fi

log_info "Successfully saved SBOM for tag $EVE_TAG"
