RELEASES = [
    {"version":"0.7.4","date":"2026-09-25","title":"Workstation Classification & Interactive Asset Review","items":["Renamed the Laptop asset group to Workstation.","Added NYV* and NYD* hostname rules to the existing NYL* workstation classification for New York internally managed endpoints.","Made Asset Classification Review summary counts clickable so selecting an Asset Group immediately filters the asset table below.","Updated classification documentation and report terminology to reflect the expanded workstation rules."]},
    {"version":"0.7.3","date":"2026-09-25","title":"Asset Classification Reporting Fix","items":["Fixed the v0.7.2 startup failure caused by an unavailable xlsxwriter dependency.","Rebuilt the Asset Classification Excel export using the existing openpyxl dependency.","Preserved Classification Summary, Classification Detail, UNKNOWN Assets, scan-status colors, and classification provenance fields."]},
    {"version":"0.7.2","date":"2026-09-25","title":"Asset Classification Review & Reporting","items":["Added a dedicated Asset Classification Review page with one row per Rapid7 asset and filters for Asset Group, Location, Classification Source, and Scan Status.","Added Classification Rule provenance so every asset shows exactly which hostname or Rapid7 OS rule assigned its tags.","Added a dedicated Asset Classification Excel report with Classification Summary, Classification Detail, and UNKNOWN Assets worksheets.","Corrected the Information page to display the complete current classification rules using wildcard notation and precedence.","Preserved green Current, yellow Aging, red Stale, and gray Unknown scan freshness indicators in the classification review and export."]},
    {"version":"0.7.1","date":"2026-09-25","title":"Asset Classification Rule Corrections","items":["Changed hostname classification from fixed digit counts to prefix/wildcard matching, so names such as NYL004 correctly classify as laptops.","Added HLSNY200* and exact HLSNY201 NetApp hostname overrides ahead of the general HLSNY* server rule.","Added LHT* classification as IBM iSeries.","Added VMware ESXi Server classification when Rapid7 operating-system data explicitly identifies VMware ESXi.","Preserved Rapid7 OS values while recording whether classification came from a Hostname Rule, Hostname Override, Rapid7 OS, or No Match.","Updated Information documentation with rule precedence and UNKNOWN handling."]},
    {"version":"0.7.0","date":"2026-09-25","title":"Asset Classification & Inventory Visibility","items":["Added deterministic hostname-based asset classification without relying on incomplete CMDB data.","Added Printer, Laptop, Server, Domain Controller, location and management tags for the defined NY/London hostname patterns.","Added explicit UNKNOWN classification for assets that do not match a defined naming rule so they can be researched rather than guessed.","Operating system remains sourced from Rapid7 and is not inferred from hostname patterns.","Added asset classification fields to Asset Overview and Asset Investigation and an UNKNOWN Assets worksheet to the Security Excel report.","Added green Current, yellow Aging, red Stale and gray Unknown scan-status badges in Asset Overview and Asset Investigation.","Documented asset classification rules, UNKNOWN handling and scan-freshness colors on the Information page."]},
    {"version":"0.6.4","date":"2026-09-23","title":"Proxy & Threat Intelligence Reliability","items":["Fixed corporate-proxy downloads incorrectly failing direct destination DNS/TCP/TLS preflight checks before the configured proxy could be used.","When a proxy is enabled, destination DNS and HTTPS CONNECT are now handled through the configured proxy path, matching Python requests behavior.","Added independent Update FIRST EPSS Only and Update CISA KEV Only controls plus Update All Sources.","A failed source update no longer prevents another source from being refreshed; last-known-good data remains preserved independently.","Improved diagnostics to display the connection method and distinguish direct connectivity from proxy-mediated connectivity.","Updated the proxy test to validate HTTPS access to the FIRST EPSS endpoint through the saved proxy configuration."]},
    {"version":"0.6.3","date":"2026-09-23","title":"Rapid7 Scan Freshness","items":["Added optional Rapid7 last_scan_date ingestion, with last_scan_data accepted as a compatibility alias for the randomized test dataset.","Added dynamic asset scan-age calculation at analysis time.","Added scan freshness classifications: Current <3 days, Aging 3–10 days, Stale >10 days, Unknown when no valid scan date exists.","Added Last Scan, Scan Age, and Scan Status to Asset Overview and Asset Investigation.","Added scan-freshness summary metrics and missing-scan-date data-quality visibility.","Added scan freshness to Security and Operations Excel reports, including campaign asset and finding data.","Scan freshness is explicitly treated as a data-confidence indicator and does not alter vulnerability or asset priority ranking."]},
    {"version":"0.6.2","date":"2026-09-22","title":"Transparent Review Prioritization","items":["Added explicit prioritization methodology directly to Vulnerability Overview and Asset Overview.","Vulnerability Overview now orders by CISA KEV, EPSS, CVSS, affected asset count, then age as contextual tie-breaker.","Asset Overview now orders by KEV CVE count, High EPSS CVE count, Critical CVSS findings, maximum CVSS, then overall CVE/finding exposure.","Added Priority Signals columns so users can see why a CVE or asset appears near the top.","Clarified that CVSS represents technical severity and does not by itself indicate exploitation likelihood.","Updated Security Excel report with the same prioritization methodology and signals. No proprietary risk score is introduced."]},
    {"version":"0.6.1","date":"2026-09-21","title":"Operations Patching Report","items":["Added a separate downstream Operations/Patching Excel report for technical remediation teams.","Added OS-aware patch campaigns for Windows 10, Windows 11, detected Windows Server versions, generic Windows systems, and Microsoft Edge.","Each patch campaign includes a local generation date/time, affected assets, findings addressed, unique CVEs, CISA KEVs, high-EPSS CVEs, and recommended remediation guidance.","Added per-campaign asset worksheets plus consolidated Campaign Finding Data for filtering and ticket creation.","Rapid7 OS inventory fields are now accepted and retained when present while older nine-column exports remain backward compatible.","Patch guidance explicitly requires normal change/patch procedures and post-patch validation rather than claiming one update remediates every finding."]},
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
