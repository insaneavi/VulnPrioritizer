# VulnPrioritizer

A lightweight, Docker-based vulnerability review and prioritization dashboard built around Rapid7 finding-level exports.

## Current Release — v0.6.3

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

Optional OS fields used by the Operations/Patching report:

`operating_system`, `os_vendor`, `os_family`, `os_name`, `os_version`, `os_architecture`, `last_scan_date`

`last_scan_data` is also accepted as a compatibility alias for randomized/test exports. Scan freshness: Current <3 days; Aging 3–10 days; Stale >10 days; Unknown = no valid scan date.

Rapid7 uploads are processed transiently and are not intentionally persisted by the application.

---

# Release Notes

## v0.6.3 — 2026-09-23 — Rapid7 Scan Freshness
- Added optional Rapid7 `last_scan_date` ingestion (`last_scan_data` compatibility alias).
- Added dynamic Last Scan, Scan Age, and Scan Status throughout asset review.
- Freshness thresholds: Current <3 days; Aging 3–10 days; Stale >10 days; Unknown when no valid scan date exists.
- Added scan freshness to Security and Operations reports and data-quality summaries.
- Scan freshness is a data-confidence indicator and does not change priority ranking.


## v0.6.2 — 2026-09-22 — Transparent Review Prioritization
- Added explained default prioritization to Vulnerability Overview and Asset Overview.
- Vulnerabilities: KEV → EPSS → CVSS → affected assets → age/context.
- Assets: KEV count → High EPSS count → Critical CVSS findings → maximum CVSS → overall exposure.
- Added visible Priority Signals so users can understand why records appear near the top.
- Added the same methodology to the Security Excel report; no proprietary risk score is introduced.


## v0.6.1 — 2026-09-21 — Operations Patching Report
- Added a separate downstream Operations/Patching workbook.
- Added OS-aware Windows 10, Windows 11, Windows Server, generic Windows, and Microsoft Edge patch campaigns.
- Every campaign includes its generation date/time, affected assets, findings, CVEs, KEV and high-EPSS context.
- Added technical asset worksheets and consolidated Campaign Finding Data for Operations filtering/ticket creation.
- Added optional Rapid7 OS fields while preserving compatibility with the original nine-column export.
- Operations guidance requires approved patch/change processes and post-patch validation.


## v0.6.0 — 2026-09-21 — Reporting & Export
- Added a Reporting page and generated Excel workbook with 10 purpose-built worksheets.
- Added color-coded KEV, EPSS, CVSS, asset-exposure and data-quality indicators with explicit labels.
- Added Attention Reason to explain why a CVE is surfaced.
- Added Executive Summary, operational worksheets, report methodology and normalized Raw Rapid7 Data.
- Rapid7 report data remains in temporary analysis-session storage only.


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
