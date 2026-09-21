# VulnPrioritizer

Rapid7 vulnerability review dashboard.

## v0.1.0
Upload a finding-level Rapid7 CSV to create a Vulnerability Overview, Asset Overview, summary metrics, and data-quality indicators.

Expected columns: `asset_id`, `ip_address`, `hostname`, `nexpose_id`, `cve`, `title`, `date_published`, `severity_score`, `cvss_v3_score`.

## Docker
```bash
git clone https://github.com/insaneavi/VulnPrioritizer.git
cd VulnPrioritizer
docker compose up -d --build
```
Open `http://SERVER-IP:8085`.

No application database is used. Do not commit real vulnerability exports.

Roadmap: EPSS, CISA KEV, Priority Review, Excel export, optional CMDB enrichment.
