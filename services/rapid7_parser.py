import pandas as pd
from services.asset_classification import classify_asset

REQUIRED_COLUMNS={"asset_id","ip_address","hostname","nexpose_id","cve","title","date_published","severity_score","cvss_v3_score"}

def _fmt_date(value):
    return "" if pd.isna(value) else value.strftime("%Y-%m-%d")

def parse_rapid7_csv(file_obj, intel):
    df=pd.read_csv(file_obj,low_memory=False)
    df.columns=[str(c).strip().lower() for c in df.columns]
    missing=sorted(REQUIRED_COLUMNS-set(df.columns))
    if missing:
        raise ValueError("Missing expected Rapid7 columns: "+", ".join(missing))

    text_columns=["asset_id","ip_address","hostname","nexpose_id","cve","title"]
    optional_os=["operating_system","os_vendor","os_family","os_name","os_version","os_architecture"]
    for c in optional_os:
        if c not in df.columns:
            df[c]=""
        text_columns.append(c)
    for c in text_columns:
        df[c]=df[c].fillna("").astype(str).str.strip()
    df["cve"]=df["cve"].str.upper()
    df["cvss_v3_score"]=pd.to_numeric(df["cvss_v3_score"],errors="coerce")
    df["severity_score"]=pd.to_numeric(df["severity_score"],errors="coerce")
    df["date_published"]=pd.to_datetime(df["date_published"],errors="coerce")
    scan_source = "last_scan_date" if "last_scan_date" in df.columns else ("last_scan_data" if "last_scan_data" in df.columns else None)
    if scan_source:
        df["last_scan_date"] = pd.to_datetime(df[scan_source], errors="coerce")
    else:
        df["last_scan_date"] = pd.NaT

    epss=intel.load_epss()
    kev=intel.load_kev()
    valid=df[df["cve"].str.startswith("CVE-")].copy()

    # CVE aggregates
    vuln=valid.groupby("cve",as_index=False).agg(
        title=("title","first"),
        nexpose_id=("nexpose_id","first"),
        cvss_v3_score=("cvss_v3_score","max"),
        affected_assets=("asset_id","nunique"),
        findings=("asset_id","size"),
        date_published=("date_published","min"))
    vuln["age_days"]=(pd.Timestamp.now().normalize()-vuln["date_published"]).dt.days
    vuln["epss"]=vuln["cve"].map(lambda c:epss.get(c,{}).get("epss"))
    vuln["percentile"]=vuln["cve"].map(lambda c:epss.get(c,{}).get("percentile"))
    vuln["kev"]=vuln["cve"].isin(kev)
    vuln=vuln.sort_values(["kev","epss","cvss_v3_score","affected_assets","age_days"],ascending=[False,False,False,False,False],na_position="last")

    kev_cves=set(vuln.loc[vuln.kev,"cve"])
    high_epss=set(vuln.loc[vuln.epss.fillna(0)>=.10,"cve"])

    # Asset aggregates
    asset=df.groupby("asset_id",as_index=False).agg(
        hostname=("hostname",lambda s:next((x for x in s if x),"")),
        ip_address=("ip_address",lambda s:next((x for x in s if x),"")),
        findings=("nexpose_id","size"),
        unique_cves=("cve",lambda s:s[s.str.startswith("CVE-")].nunique()),
        max_cvss=("cvss_v3_score","max"),
        critical_findings=("cvss_v3_score",lambda s:int((s>=9).sum())),
        operating_system=("operating_system",lambda s:next((x for x in s if x),"")),
        os_vendor=("os_vendor",lambda s:next((x for x in s if x),"")),
        os_family=("os_family",lambda s:next((x for x in s if x),"")),
        os_name=("os_name",lambda s:next((x for x in s if x),"")),
        os_version=("os_version",lambda s:next((x for x in s if x),"")),
        os_architecture=("os_architecture",lambda s:next((x for x in s if x),"")),
        last_scan_date=("last_scan_date","max"))
    now = pd.Timestamp.now()
    def scan_age_days(v):
        if pd.isna(v): return None
        return max(0, int((now - v).total_seconds() // 86400))
    def scan_status(days):
        if days is None: return "Unknown"
        if days < 3: return "Current"
        if days <= 10: return "Aging"
        return "Stale"
    asset["scan_age_days"] = asset["last_scan_date"].map(scan_age_days)
    asset["scan_status"] = asset["scan_age_days"].map(scan_status)

    asset["kev_cves"]=asset.asset_id.map(lambda a:df[(df.asset_id==a)&(df.cve.isin(kev_cves))].cve.nunique())
    asset["high_epss_cves"]=asset.asset_id.map(lambda a:df[(df.asset_id==a)&(df.cve.isin(high_epss))].cve.nunique())
    asset=asset.sort_values(["kev_cves","high_epss_cves","critical_findings","max_cvss","unique_cves","findings"],ascending=[False,False,False,False,False,False],na_position="last")

    vulns=[]
    cve_index={}
    for r in vuln.itertuples(index=False):
        item={"cve":r.cve,"title":r.title,"nexpose_id":r.nexpose_id,
              "cvss":"" if pd.isna(r.cvss_v3_score) else f"{r.cvss_v3_score:.1f}",
              "cvss_raw":None if pd.isna(r.cvss_v3_score) else float(r.cvss_v3_score),
              "epss":"" if pd.isna(r.epss) else f"{r.epss*100:.2f}%",
              "epss_raw":0 if pd.isna(r.epss) else float(r.epss),
              "percentile":"" if pd.isna(r.percentile) else f"{r.percentile*100:.2f}%",
              "percentile_raw":None if pd.isna(r.percentile) else float(r.percentile),
              "kev":bool(r.kev),"affected_assets":int(r.affected_assets),"findings":int(r.findings),
              "published":_fmt_date(r.date_published),
              "age_days":"" if pd.isna(r.age_days) else int(r.age_days)}
        signals=[]
        if item["kev"]: signals.append("Known Exploited (KEV)")
        if item["epss_raw"]>=.10: signals.append("High EPSS")
        if (item["cvss_raw"] or 0)>=9: signals.append("Critical CVSS")
        item["priority_signals"]=" · ".join(signals) if signals else "CVSS / exposure context"
        vulns.append(item); cve_index[r.cve]=item

    assets=[]
    asset_index={}
    for r in asset.itertuples(index=False):
        item={"asset_id":r.asset_id,"hostname":r.hostname or "—","ip_address":r.ip_address or "—",
              "findings":int(r.findings),"unique_cves":int(r.unique_cves),
              "kev_cves":int(r.kev_cves),"high_epss_cves":int(r.high_epss_cves),
              "critical_findings":int(r.critical_findings),
              "max_cvss":"" if pd.isna(r.max_cvss) else f"{r.max_cvss:.1f}",
              "operating_system":r.operating_system or "Unknown",
              "os_vendor":r.os_vendor or "Unknown","os_family":r.os_family or "Unknown",
              "os_name":r.os_name or "Unknown","os_version":r.os_version or "Unknown",
              "os_architecture":r.os_architecture or "Unknown",
              "last_scan_date":_fmt_date(r.last_scan_date),
              "last_scan_timestamp":"" if pd.isna(r.last_scan_date) else r.last_scan_date.strftime("%Y-%m-%d %H:%M:%S"),
              "scan_age_days":None if pd.isna(r.scan_age_days) else int(r.scan_age_days),
              "scan_status":r.scan_status}
        item.update(classify_asset(r.hostname, r.operating_system))
        signals=[]
        if item["kev_cves"]: signals.append(f'KEV: {item["kev_cves"]}')
        if item["high_epss_cves"]: signals.append(f'High EPSS: {item["high_epss_cves"]}')
        if item["critical_findings"]: signals.append(f'Critical: {item["critical_findings"]}')
        item["priority_signals"]=" · ".join(signals) if signals else "Exposure / CVSS context"
        assets.append(item); asset_index[r.asset_id]=item

    # Cross-links: CVE -> affected assets
    cve_assets={}
    for cve,group in valid.groupby("cve"):
        rows=[]
        for aid in group["asset_id"].drop_duplicates():
            if aid in asset_index:
                rows.append(asset_index[aid])
        cve_assets[cve]=sorted(rows,key=lambda x:(x["kev_cves"],x["high_epss_cves"],x["critical_findings"],float(x["max_cvss"] or 0),x["unique_cves"],x["findings"]),reverse=True)

    # Cross-links: asset -> vulnerabilities
    asset_cves={}
    for aid,group in valid.groupby("asset_id"):
        rows=[]
        for cve in group["cve"].drop_duplicates():
            if cve in cve_index:
                rows.append(cve_index[cve])
        asset_cves[aid]=sorted(rows,key=lambda x:(x["kev"],x["epss_raw"],x["cvss_raw"] or 0),reverse=True)

    # CISA detail subset is public intelligence only
    kev_details={}
    for cve in kev_cves:
        k=kev.get(cve,{})
        kev_details[cve]={
            "vendor":k.get("vendorProject",""),
            "product":k.get("product",""),
            "date_added":k.get("dateAdded",""),
            "due_date":k.get("dueDate",""),
            "required_action":k.get("requiredAction",""),
            "ransomware":k.get("knownRansomwareCampaignUse",""),
            "short_description":k.get("shortDescription","")
        }

    return {
      "metrics":{"findings":len(df),"assets":df.loc[df.asset_id!="","asset_id"].nunique(),
        "cves":valid.cve.nunique(),"kev_cves":int(vuln.kev.sum()),
        "kev_assets":df[df.cve.isin(kev_cves)].asset_id.nunique(),
        "high_epss_cves":int((vuln.epss.fillna(0)>=.10).sum()),
        "critical_findings":int((df.cvss_v3_score>=9).sum()),
        "scan_current":int((asset.scan_status=="Current").sum()),
        "scan_aging":int((asset.scan_status=="Aging").sum()),
        "scan_stale":int((asset.scan_status=="Stale").sum()),
        "scan_unknown":int((asset.scan_status=="Unknown").sum()),
        "asset_group_unknown":int(sum(1 for a in assets if a["asset_group"]=="UNKNOWN")),
        "asset_group_counts":{g:sum(1 for a in assets if a["asset_group"]==g) for g in sorted(set(a["asset_group"] for a in assets))}},
      "quality":{"missing_cve":int((~df.cve.str.startswith("CVE-")).sum()),
        "missing_hostname":int((df.hostname=="").sum()),"missing_cvss":int(df.cvss_v3_score.isna().sum()),
        "missing_scan_date":int((asset.scan_status=="Unknown").sum())},
      "intel_status":intel.get_status(),"vulnerabilities":vulns,"assets_table":assets,
      "cve_index":cve_index,"asset_index":asset_index,"cve_assets":cve_assets,
      "asset_cves":asset_cves,"kev_details":kev_details,
      # Normalized finding-level rows are retained only inside the temporary analysis
      # session so Reporting can produce a Raw Rapid7 Data worksheet.
      "raw_findings": df.where(pd.notna(df), None).to_dict(orient="records")
    }
