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


def _score(value):
    try:
        score = float(value)
        return -1.0 if math.isnan(score) else score
    except (TypeError, ValueError):
        return -1.0


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
    for rows in groups.values():
        summary = next((_clean(r.get("solution_summary")) for r in rows if _clean(r.get("solution_summary"))), "Rapid7 remediation available")
        fix = next((_clean(r.get("solution_fix")) for r in rows if _clean(r.get("solution_fix"))), "")
        estimate = next((_clean(r.get("solution_estimate")) for r in rows if _clean(r.get("solution_estimate"))), "")

        cve_data = {}
        for r in rows:
            cve = _clean(r.get("cve")).upper()
            if not cve.startswith("CVE-"):
                continue
            d = cve_data.setdefault(cve, {"score": -1.0, "title": ""})
            d["score"] = max(d["score"], _score(r.get("cvss_v3_score")))
            if not d["title"]:
                d["title"] = _clean(r.get("title"))

        ordered_cves = sorted(cve_data, key=lambda c: (cve_data[c]["score"], c), reverse=True)
        primary = ordered_cves[0] if ordered_cves else "No CVE Reference"
        primary_data = cve_data.get(primary, {"score": -1.0, "title": ""})

        # Evidence is deliberately scoped to the headline CVE only.  Each asset
        # receives only evidence from its own Rapid7 asset/vulnerability instance.
        evidence_by_asset = defaultdict(list)
        primary_rows = [r for r in rows if _clean(r.get("cve")).upper() == primary]
        for r in primary_rows:
            host = _short_hostname(r.get("hostname"))
            evidence = _clean(r.get("finding_evidence"))
            if evidence and evidence not in evidence_by_asset[host]:
                evidence_by_asset[host].append(evidence)
        primary_assets = sorted({_short_hostname(r.get("hostname")) for r in primary_rows if _clean(r.get("hostname"))})
        asset_evidence = [{"hostname": h, "evidence": evidence_by_asset.get(h, [])} for h in primary_assets]

        related = [{"cve": c, "title": cve_data[c]["title"]} for c in ordered_cves[1:]]
        items.append({
            "solution_id": _clean(rows[0].get("solution_id")),
            "resolution": summary,
            "fix": fix,
            "estimate": estimate,
            "primary_cve": primary,
            "primary_title": primary_data["title"],
            "primary_cvss": None if primary_data["score"] < 0 else primary_data["score"],
            "assets": primary_assets,
            "asset_evidence": asset_evidence,
            "also_resolves": related,
            "cve_count": len(ordered_cves),
            "asset_count": len(primary_assets),
        })
    items.sort(key=lambda x: (x["primary_cvss"] is not None, x["primary_cvss"] or -1, x["asset_count"]), reverse=True)
    return items


def build_head_office_text(analysis):
    items = build_head_office_items(analysis)
    lines = [
        "HEAD OFFICE VULNERABILITY MANAGEMENT REPORT",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "Source: VulnPrioritizer / Rapid7 remediation relationships and finding-level evidence",
        "",
        "Note: Each section groups findings by Rapid7 solution. The headline CVE is the highest-CVSS CVE in that solution group.",
        "Finding Evidence is displayed only for the headline CVE and the specific asset/vulnerability instance supplied by Rapid7.",
        "'Also Expected to Resolve' lists other CVEs and their Rapid7 vulnerability titles associated with the same solution in this analysis.",
        "",
    ]
    if not items:
        lines += ["No Rapid7 solution/remediation data was available in this analysis.", "", "Use the expanded Rapid7 export containing solution_id, solution_summary, solution_fix, solution_estimate, and finding_evidence."]
        return "\n".join(lines)

    for item in items:
        lines.append("=" * 72)
        score = "N/A" if item["primary_cvss"] is None else f'{item["primary_cvss"]:.1f}'
        lines.append(item["primary_cve"])
        if item["primary_title"]:
            lines.append(item["primary_title"])
        lines.append(f"CVSS Score: {score}")
        lines.append("")
        lines.append("Resolution:")
        lines.append(item["resolution"])
        lines.append("")
        lines.append(f'Assets Affected ({item["asset_count"]}):')
        if item["asset_evidence"]:
            for asset in item["asset_evidence"]:
                lines.append("")
                lines.append(asset["hostname"])
                lines.append("Evidence:")
                if asset["evidence"]:
                    for ev in asset["evidence"]:
                        lines.append(ev)
                else:
                    lines.append("No finding-level evidence supplied in the Rapid7 export for this asset/CVE instance.")
        else:
            lines.append("None listed")
        lines.append("")
        lines.append(f'Also Expected to Resolve ({len(item["also_resolves"])}):')
        if item["also_resolves"]:
            for related in item["also_resolves"]:
                lines.append("")
                lines.append(related["cve"])
                lines.append(related["title"] or "Rapid7 vulnerability title unavailable in this export")
        else:
            lines.append("None")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
