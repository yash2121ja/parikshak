# Parikshak

Fast Docker image vulnerability scanner. Finds CVEs, secrets, and misconfigurations.

```bash
pip install parikshak
parikshak scan nginx:latest
```

## What It Does

```
$ parikshak scan python:3.12-slim

  parikshak v1.0.0 — scanning python:3.12-slim

  Extracting image...      done (1200ms)
  Detecting packages...    88 packages (45ms)
  Matching advisories...   12 vulnerabilities (700ms)
  Scanning secrets...      0 secrets (180ms)
  Checking misconfigs...   3 issues (25ms)

  ┌─────────────────────────────────────────────────────────────┐
  │  RESULTS: python:3.12-slim                                  │
  ├────────┬────────┬────────┬────────┬────────┬───────────────┤
  │  CRIT  │  HIGH  │  MED   │  LOW   │ TOTAL  │ Secrets/Misc  │
  │   0    │   6    │   8    │   74   │  88    │   0 / 3       │
  └────────┴────────┴────────┴────────┴────────┴───────────────┘
```

## Features

- **Fast** — Rust-powered package detection, parallel scanning
- **Accurate** — Uses distro-specific advisories (Debian Tracker, Alpine SecDB), not raw NVD
- **More than CVEs** — Also finds hardcoded secrets and misconfigurations
- **No daemon needed** — Works without Docker daemon (pulls via registry API)
- **Offline mode** — Download DB once, scan without internet
- **CI/CD ready** — Exit code 1 on critical/high findings, JSON/SARIF output
- **CISA KEV** — Flags actively exploited vulnerabilities

## Install

```bash
pip install parikshak
```

## Usage

```bash
# Scan an image
parikshak scan nginx:latest
parikshak scan python:3.12-slim --severity HIGH,CRITICAL

# Output formats
parikshak scan nginx:latest --format json
parikshak scan nginx:latest --format sarif
parikshak scan nginx:latest --format csv

# CI/CD mode (exit 1 if critical/high found)
parikshak scan nginx:latest --exit-code 1 --severity CRITICAL,HIGH

# Offline mode
parikshak db update
parikshak scan nginx:latest --offline

# SBOM generation
parikshak sbom nginx:latest --format cyclonedx
parikshak sbom nginx:latest --format spdx
```

## GitHub Actions

```yaml
- name: Scan container image
  run: |
    pip install parikshak
    parikshak scan myapp:${{ github.sha }} --exit-code 1 --severity CRITICAL,HIGH
```

## Advisory Database

Powered by [vuln-intel-db](https://github.com/yash2121ja/vuln-intel-db) — aggregates advisories from Debian, Alpine, GHSA, CISA KEV, EPSS. Updated every 6 hours.

## License

Apache 2.0
