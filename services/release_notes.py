RELEASES = [
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
