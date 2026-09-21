# VulnPrioritizer

A lightweight, Docker-based vulnerability review and prioritization dashboard built around Rapid7 finding-level exports.

## Current Release — v0.5.0

VulnPrioritizer now enriches Rapid7 CVEs using **locally cached bulk threat-intelligence datasets**.

### v0.4.1 highlights
- Fixed investigation sessions across multiple Gunicorn workers
- Shared temporary container-filesystem analysis storage
- Rapid7 sessions remain non-persistent and outside the threat-intelligence volume
- Atomic temporary-session writes and bounded session cleanup

### v0.4.0 highlights
- Clickable CVE and asset investigation
- Dedicated CVE Investigation pages
- Dedicated Asset Investigation pages
- Bidirectional CVE → Asset → CVE navigation
- CISA KEV investigation context
- Temporary in-memory analysis sessions; no Rapid7 database
- Breadcrumbs and investigation-table search

### v0.3.0 highlights
- Host/local timezone support and human-readable timestamps
- New Information page explaining CVSS, EPSS, percentile and CISA KEV
- End-to-end VulnPrioritizer workflow documentation
- Data-handling/privacy and corporate network documentation
- Dashboard intelligence tooltips
- New Priority Review tab using transparent exploitation/severity signals

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

## v0.5.0 — 2026-09-21 — Priority Drill-Down & Corporate Proxy
- Clickable Priority Review drill-downs for KEV, High EPSS, Assets with KEV, and Critical Findings.
- Persistent proxy configuration for EPSS/CISA KEV with Save, Test, Clear/Disable and optional authentication.
- Separate configuration volume; Rapid7 analysis remains temporary.
- TLS-inspection CA guidance; TLS verification remains enabled.


## v0.4.1 — 2026-09-21 — Shared Investigation Session Hotfix
- Fixed CVE/Asset Investigation links losing the current analysis when Gunicorn routed requests to another worker.
- Replaced worker-local memory sessions with shared temporary container-filesystem sessions.
- Rapid7 analysis remains non-persistent and is not stored in `vulnprioritizer_intel`.
- Added atomic session writes and cleanup of older temporary sessions.
- FIRST EPSS and CISA KEV persistence is unchanged.


## v0.4.0 — 2026-09-21 — Investigation & Navigation
- Added temporary in-memory analysis sessions for navigation without a Rapid7 database.
- Added clickable CVEs, assets, and hostnames.
- Added CVE Investigation with EPSS, percentile, KEV, CVSS, affected assets, and Rapid7 context.
- Added CISA KEV detail fields where available.
- Added Asset Investigation with CVE, KEV, high-EPSS, critical-finding, and severity context.
- Added CVE-to-Asset-to-CVE navigation, breadcrumbs, and searchable investigation tables.
- Updated Information documentation for temporary analysis sessions.


## v0.3.0 — 2026-09-21 — Usability & Intelligence Guidance
- Added host/local timezone support and human-readable local timestamps.
- Added an Information page explaining the VulnPrioritizer workflow.
- Added educational guidance for CVSS, EPSS, EPSS percentile, and CISA KEV.
- Added data-handling/privacy and corporate network documentation.
- Added contextual dashboard tooltips.
- Added a Priority Review tab using transparent KEV, EPSS, CVSS, and affected-asset signals.
- Continued to avoid a proprietary organizational risk score until business/CMDB context is available.


## v0.2.1 — 2026-09-21 — Release Notes Hotfix
- Fixed the Release Notes page 500 error caused by a Jinja dictionary key collision with the built-in `items()` method.
- Confirmed FIRST EPSS bulk synchronization and local cache operation.
- Confirmed CISA KEV bulk synchronization and local cache operation.
- No changes to Rapid7 parsing, threat-intelligence matching, or persistent volume behavior.


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
