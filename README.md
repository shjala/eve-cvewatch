# CVE Watch

Tools for scanning EVE-OS for vulnerabilities and gating Pull Requests.

## GitHub Action Usage

Use this workflow in the EVE repository to block PRs that introduce new vulnerabilities.

Create `.github/workflows/cve-gate.yml`:

```yaml
name: CVE PR Gate

on:
  pull_request:
    branches: [ "master" ]

jobs:
  cve-scan:
    name: Scan PR for Vulnerabilities
    uses: shjala/eve-cvewatch/.github/workflows/pr-scan.yml@v1.0.0
    with:
      eve-repo-url: ${{ github.event.pull_request.head.repo.clone_url }}
      eve-revision: ${{ github.event.pull_request.head.sha }}
```

## Local Usage

You can run the PR scanner locally to check a branch before pushing.

```bash
# Usage: ./ci/pr-scan.sh <GIT_URL> [REVISION]
./ci/pr-scan.sh https://github.com/lf-edge/eve.git my-feature-branch
```
