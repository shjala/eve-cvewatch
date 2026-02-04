#!/bin/bash
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Compare two scan results files and fail if new vulnerabilities are found.
# usage: ./compare.sh <master_scan.json> <pr_scan.json>

set -euo pipefail

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <master_scan.json> <pr_scan.json>" >&2
    exit 1
fi

MASTER_FILE="$1"
PR_FILE="$2"

setup_python_env

if [ ! -f "scan/compare.py" ]; then
    log_error "Error: Cannot find scan/compare.py"
    log_error "Please run this script from the ci/ directory."
    exit 1
fi

# Run comparison
log_info "Running comparison between master and PR scan results..."
log_cmd python3 scan/compare.py "$MASTER_FILE" "$PR_FILE"
