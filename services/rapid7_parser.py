import pandas as pd

REQUIRED_COLUMNS={"asset_id","ip_address","hostname","nexpose_id","cve","title","date_published","severity_score","cvss_v3_score"}

def parse_rapid7_csv(file_obj):
    df=pd.read_csv(file_obj,low_memory=False)
    df.columns=[str(c).strip().lower() for c in df.columns]
    missing=sorted(REQUIRED_COLUMNS-set(df.columns))
    if missing:
        raise ValueError("Missing expected Rapid7 columns: "+", ".join(missing))
    for c in ["asset_id","ip_address","hostname","nexpose_id","cve","title"]:
        df[c]=df[c].fillna("").astype(str).str.strip()
    df["cve"]=df["cve"].str.upper()
    df["cvss_v3_score"]=pd.to_numeric(df["cvss_v3_score"],errors="coerce")
    df["severity_score"]=pd.to_numeric(df["severity_score"],errors="coerce")
    df["date_published"]=pd.to_datetime(df["date_published"],errors="coerce")

    valid=df[df["cve"].str.startswith("CVE-")].copy()
    vuln=valid.groupby("cve",as_index=False).agg(
        title=("title","first"),cvss_v3_score=("cvss_v3_score","max"),
        affected_assets=("asset_id","nunique"),findings=("asset_id","size"),
        date_published=("date_published","min"))
    vuln["age_days"]=(pd.Timestamp.now().normalize()-vuln["date_published"]).dt.days
    vuln=vuln.sort_values(["affected_assets","cvss_v3_score"],ascending=[False,False])

    asset=df.groupby("asset_id",as_index=False).agg(
        hostname=("hostname",lambda s:next((x for x in s if x),"")),
        ip_address=("ip_address",lambda s:next((x for x in s if x),"")),
        findings=("nexpose_id","size"),
        unique_cves=("cve",lambda s:s[s.str.startswith("CVE-")].nunique()),
        max_cvss=("cvss_v3_score","max"),
        critical_findings=("cvss_v3_score",lambda s:int((s>=9).sum())))
    asset=asset.sort_values(["findings","max_cvss"],ascending=[False,False])

    vulns=[{"cve":r.cve,"title":r.title,"cvss":"" if pd.isna(r.cvss_v3_score) else f"{r.cvss_v3_score:.1f}",
            "affected_assets":int(r.affected_assets),"findings":int(r.findings),
            "published":"" if pd.isna(r.date_published) else r.date_published.strftime("%Y-%m-%d"),
            "age_days":"" if pd.isna(r.age_days) else int(r.age_days)} for r in vuln.head(500).itertuples(index=False)]
    assets=[{"asset_id":r.asset_id,"hostname":r.hostname or "—","ip_address":r.ip_address or "—",
             "findings":int(r.findings),"unique_cves":int(r.unique_cves),
             "max_cvss":"" if pd.isna(r.max_cvss) else f"{r.max_cvss:.1f}",
             "critical_findings":int(r.critical_findings)} for r in asset.head(500).itertuples(index=False)]
    return {"metrics":{"findings":len(df),"assets":df.loc[df.asset_id!="","asset_id"].nunique(),
            "cves":valid.cve.nunique(),"critical_findings":int((df.cvss_v3_score>=9).sum())},
            "quality":{"missing_cve":int((~df.cve.str.startswith("CVE-")).sum()),
            "missing_hostname":int((df.hostname=="").sum()),"missing_cvss":int(df.cvss_v3_score.isna().sum())},
            "vulnerabilities":vulns,"assets_table":assets}
