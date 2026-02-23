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

## Full Scan with Upload

Scans all supported EVE LTS tags + master and uploads results to a CVEWatch instance.

```bash
# Required environment variables
export CVEWATCH_URL=http://10.208.13.68   # CVEWatch server URL
export CVEWATCH_TOKEN=<upload-token>       # Generate via UI: Profile → Upload Tokens

# Run once
./ci/full-scan.sh --upload

# Parallel scanning (faster, one scanner per tag)
./ci/full-scan.sh --upload --parallel
```

### Automated Daily Scan (cron)

```bash
sudo crontab -e
```

```cron
0 3 * * * cd /path/to/ci && CVEWATCH_URL=http://10.208.13.68 CVEWATCH_TOKEN=<token> ./full-scan.sh --upload --parallel >> /var/log/cvewatch-scan.log 2>&1
```

### Options

| Flag | Description |
|------|-------------|
| `-u`, `--upload` | Upload scan results to `CVEWATCH_URL` |
| `-p`, `--parallel` | Run scanners in parallel |
| `-f`, `--fetch-only` | Fetch SBOMs and Alpine data only, skip scanning |
