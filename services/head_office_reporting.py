from collections import defaultdict
from datetime import datetime
import math


def _clean(value):
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    return str(value).strip()


def _short_hostname(value):
    host = _clean(value)
    return host.split(".", 1)[0] if host else "UNKNOWN"


def build_head_office_items(analysis):
    groups = defaultdict(list)
    for row in analysis.get("raw_findings", []):
        solution_id = _clean(row.get("solution_id"))
        solution_summary = _clean(row.get("solution_summary"))
        if not solution_id and not solution_summary:
            continue
        key = solution_id or f"summary:{solution_summary}"
        groups[key].append(row)

    items = []
    for key, rows in groups.items():
        summary = next((_clean(r.get("solution_summary")) for r in rows if _clean(r.get("solution_summary"))), "Rapid7 remediation available")
        fix = next((_clean(r.get("solution_fix")) for r in rows if _clean(r.get("solution_fix"))), "")
        estimate = next((_clean(r.get("solution_estimate")) for r in rows if _clean(r.get("solution_estimate"))), "")

        cve_scores = {}
        for r in rows:
            cve = _clean(r.get("cve")).upper()
            if not cve.startswith("CVE-"):
                continue
            try:
                score = float(r.get("cvss_v3_score"))
                if math.isnan(score): score = -1.0
            except (TypeError, ValueError):
                score = -1.0
            cve_scores[cve] = max(cve_scores.get(cve, -1.0), score)
        ordered_cves = sorted(cve_scores, key=lambda c: (cve_scores[c], c), reverse=True)
        primary = ordered_cves[0] if ordered_cves else "No CVE Reference"
        primary_score = cve_scores.get(primary, -1.0)
        assets = sorted({_short_hostname(r.get("hostname")) for r in rows if _clean(r.get("hostname"))})
        items.append({
            "solution_id": _clean(rows[0].get("solution_id")),
            "resolution": summary,
            "fix": fix,
            "estimate": estimate,
            "primary_cve": primary,
            "primary_cvss": None if primary_score < 0 else primary_score,
            "assets": assets,
            "also_resolves": ordered_cves[1:],
            "cve_count": len(ordered_cves),
            "asset_count": len(assets),
        })
    items.sort(key=lambda x: (x["primary_cvss"] is not None, x["primary_cvss"] or -1, x["asset_count"]), reverse=True)
    return items


def build_head_office_text(analysis):
    items = build_head_office_items(analysis)
    lines = [
        "HEAD OFFICE VULNERABILITY MANAGEMENT REPORT",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "Source: VulnPrioritizer / Rapid7 remediation relationships",
        "",
        "Note: Each section groups findings by Rapid7 solution. The headline CVE is the highest-CVSS CVE in that solution group.",
        "'Also Expected to Resolve' lists other CVEs associated by Rapid7 with the same solution in this analysis.",
        "",
    ]
    if not items:
        lines += ["No Rapid7 solution/remediation data was available in this analysis.", "", "Use the expanded Rapid7 export containing solution_id, solution_summary, solution_fix, and solution_estimate."]
        return "\n".join(lines)
    for item in items:
        lines.append("=" * 72)
        score = "N/A" if item["primary_cvss"] is None else f'{item["primary_cvss"]:.1f}'
        lines.append(f'{item["primary_cve"]} (Highest CVSS: {score})')
        lines.append("")
        lines.append("Resolution:")
        lines.append(item["resolution"])
        lines.append("")
        lines.append(f'Assets Affected ({item["asset_count"]}):')
        lines.extend(item["assets"] or ["None listed"])
        lines.append("")
        lines.append(f'Also Expected to Resolve ({len(item["also_resolves"])}):')
        lines.extend(item["also_resolves"] or ["None"])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
