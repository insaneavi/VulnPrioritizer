RELEASES = [
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
