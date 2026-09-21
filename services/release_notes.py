RELEASES = [
    {"version":"0.6.0","date":"2026-09-21","title":"Reporting & Export","items":["Added a dedicated Reporting page for each temporary Rapid7 analysis.","Added a professionally formatted Excel workbook with Executive Summary, Priority Review, Vulnerability Overview, Asset Overview, CISA KEV, High EPSS, Critical CVSS, Data Quality, Report Information, and Raw Rapid7 Data worksheets.","Added consistent color coding for KEV, EPSS, CVSS, asset exposure, and data-quality review while retaining explicit labels and numeric values.","Added an Attention Reason field showing the transparent signals that surfaced each CVE.","Retained normalized finding-level Rapid7 rows only in temporary analysis-session storage to support report generation; no Rapid7 data is added to persistent volumes.","Added filters, frozen headers, formatted percentages, readable column sizing, and workbook legends for operational review." ]},
    {"version":"0.5.0","date":"2026-09-21","title":"Priority Drill-Down & Corporate Proxy","items":["Made all Priority Review cards clickable with filtered CVE or asset results.","Added Known Exploited, High EPSS, Assets with KEV, and Critical Findings drill-downs.","Added persistent corporate proxy configuration for FIRST EPSS and CISA KEV downloads.","Added proxy Save, Test, and Clear/Disable controls with optional authentication.","Added a separate persistent configuration volume; Rapid7 analysis remains temporary.","Added TLS-inspection CA guidance without disabling certificate verification."]},
    {
        "version": "0.4.1",
        "date": "2026-09-21",
        "title": "Shared Investigation Session Hotfix",
        "items": [
            "Fixed CVE and Asset Investigation links incorrectly reporting that the analysis session was unavailable when Gunicorn routed requests to different workers.",
            "Replaced per-process in-memory session storage with shared temporary container-filesystem session storage accessible by all Gunicorn workers.",
            "Rapid7 analysis sessions remain non-persistent and are not stored in the vulnprioritizer_intel Docker volume.",
            "Session files are written atomically and the temporary store retains only the most recent analysis sessions.",
            "No changes were made to persistent FIRST EPSS or CISA KEV threat-intelligence storage."
        ]
    },
    {
        "version": "0.4.0",
        "date": "2026-09-21",
        "title": "Investigation & Navigation",
        "items": [
            "Added temporary in-memory analysis sessions to support investigation without creating a Rapid7 database.",
            "Made CVEs clickable from the Vulnerability Overview.",
            "Made assets and hostnames clickable from the Asset Overview.",
            "Added dedicated CVE Investigation pages with CVSS, EPSS, percentile, KEV, publication age, Rapid7 ID, and affected assets.",
            "Added CISA KEV vendor, product, date added, due date, ransomware-use, description, and required-action context where available.",
            "Added dedicated Asset Investigation pages with finding counts, CVEs, KEVs, high-EPSS exposure, critical findings, and highest CVSS.",
            "Added bidirectional CVE-to-Asset-to-CVE investigation navigation.",
            "Added breadcrumbs, back navigation, search within investigation tables, and related exposure context.",
            "Updated Information documentation to explain temporary analysis-session handling."
        ]
    },
    {
        "version": "0.3.0",
        "date": "2026-09-21",
        "title": "Usability & Intelligence Guidance",
        "items": [
            "Added host/local timezone support and human-readable local timestamps.",
            "Added an Information page explaining VulnPrioritizer's end-to-end workflow.",
            "Added educational guidance for CVSS, EPSS, EPSS percentile, and CISA KEV.",
            "Added data-handling and privacy documentation explaining that Rapid7 data remains local.",
            "Added corporate network requirements for FIRST EPSS and CISA KEV.",
            "Added contextual information tooltips to vulnerability intelligence columns.",
            "Added a Priority Review tab using transparent KEV, EPSS, CVSS, and affected-asset signals.",
            "Continued to avoid a proprietary organizational risk score until business/CMDB context is available."
        ]
    },
    {
        "version": "0.2.1",
        "date": "2026-09-21",
        "title": "Release Notes Hotfix",
        "items": [
            "Fixed the Release Notes page 500 error caused by a Jinja dictionary key collision with the built-in items() method.",
            "Confirmed FIRST EPSS bulk synchronization and local cache operation.",
            "Confirmed CISA KEV bulk synchronization and local cache operation.",
            "No changes to Rapid7 parsing, threat-intelligence matching, or persistent volume behavior."
        ]
    },
    {
        "version": "0.2.0",
        "date": "2026-09-21",
        "title": "Threat Intelligence",
        "items": [
            "Added local FIRST EPSS bulk-dataset synchronization.",
            "Added local CISA Known Exploited Vulnerabilities (KEV) synchronization.",
            "Added persistent last-known-good threat intelligence cache.",
            "Added dataset date, last attempted update, and last successful update timestamps.",
            "Added manual Update Threat Intelligence Now workflow.",
            "Added detailed DNS, TCP, TLS, HTTP, redirect, download-size, duration, and error diagnostics.",
            "Added EPSS probability, EPSS percentile, and CISA KEV enrichment to vulnerability analysis.",
            "Added KEV and EPSS metrics and filters to the dashboard.",
            "Added Threat Intelligence and Release Notes pages.",
            "Rapid7 data remains transient and is not written to the threat-intelligence volume."
        ]
    },
    {
        "version": "0.1.0",
        "date": "2026-09-21",
        "title": "Initial Foundation",
        "items": [
            "Added Rapid7 finding-level CSV upload and validation.",
            "Added vulnerability overview aggregated by CVE.",
            "Added asset overview aggregated by Rapid7 asset.",
            "Added summary and data-quality metrics.",
            "Added Docker and Portainer-compatible deployment files.",
            "No application database used."
        ]
    }
]
