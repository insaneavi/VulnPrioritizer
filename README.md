# VulnPrioritizer

A lightweight, Docker-based vulnerability review and prioritization dashboard built around Rapid7 finding-level exports.

## Current Release — v0.2.0

VulnPrioritizer now enriches Rapid7 CVEs using **locally cached bulk threat-intelligence datasets**.

### v0.2.0 highlights
- FIRST EPSS bulk dataset synchronization
- CISA Known Exploited Vulnerabilities (KEV) synchronization
- Local-only CVE matching; Rapid7 findings are not sent to FIRST or CISA
- Persistent Docker volume for public threat-intelligence catalogs
- Dataset date/version, last attempted update, and last successful update
- Manual ad-hoc threat-intelligence refresh
- Detailed DNS / TCP / TLS / HTTP diagnostics
- Last-known-good catalog protection
- EPSS probability and percentile in Vulnerability Overview
- KEV status, KEV asset counts, and EPSS threshold filtering
- In-app Release Notes page

## Network requirements

Runtime threat-intelligence updates require outbound HTTPS/TCP 443 access to:

| Purpose | Destination |
|---|---|
| FIRST EPSS bulk dataset | `epss.empiricalsecurity.com` |
| CISA KEV JSON feed | `www.cisa.gov` |

No Rapid7 IP addresses, hostnames, Rapid7 asset IDs, or organization-specific vulnerability report is transmitted to these sources.

## Portainer / Docker

The included Compose file publishes the application on port `8085` and creates the persistent named volume `vulnprioritizer_intel`.

After updating the Git repository, redeploy/rebuild the Portainer stack.

## Rapid7 input

Expected columns:

`asset_id`, `ip_address`, `hostname`, `nexpose_id`, `cve`, `title`, `date_published`, `severity_score`, `cvss_v3_score`

Rapid7 uploads are processed transiently and are not intentionally persisted by the application.

---

# Release Notes

## v0.2.0 — 2026-09-21 — Threat Intelligence
- Added local FIRST EPSS bulk-dataset synchronization.
- Added local CISA KEV synchronization.
- Added persistent last-known-good threat intelligence cache.
- Added dataset date/version and update timestamps.
- Added manual ad-hoc updates.
- Added detailed network diagnostics for troubleshooting corporate firewall/proxy failures.
- Added EPSS probability, EPSS percentile, and CISA KEV enrichment.
- Added KEV and high-EPSS dashboard metrics and filters.
- Added Threat Intelligence and Release Notes pages.
- Rapid7 data remains transient and is not written to the threat-intelligence volume.

## v0.1.0 — 2026-09-21 — Initial Foundation
- Rapid7 CSV upload and validation.
- Vulnerability Overview aggregated by CVE.
- Asset Overview aggregated by Rapid7 asset.
- Summary and data-quality metrics.
- Docker/Portainer deployment support.
- No application database.
