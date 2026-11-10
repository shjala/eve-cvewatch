# CVE Watch — moved to eve-tools

CVE Watch's standalone scanner and CI workflows have moved to
[lf-edge/eve-tools](https://github.com/lf-edge/eve-tools/tree/master/cvewatch).

Use the upstream repository for documentation, development, and new issues:

- [Scanner documentation and local usage](https://github.com/lf-edge/eve-tools/blob/master/cvewatch/README.md)
- [Reusable CI workflow](https://github.com/lf-edge/eve-tools/blob/master/.github/workflows/cve-scan.yml)
- [Issue tracker](https://github.com/lf-edge/eve-tools/issues)

For GitHub Actions, update your reusable workflow reference to
`lf-edge/eve-tools/.github/workflows/cve-scan.yml@<reviewed-commit-sha>`, replacing
`<reviewed-commit-sha>` with the full SHA of a reviewed upstream commit containing
the workflow. See the upstream documentation for inputs and examples.

Existing references to `shjala/eve-cvewatch` are not automatically redirected.
This repository retains its code and tags for existing consumers and historical
reference; future development belongs in `lf-edge/eve-tools`.
