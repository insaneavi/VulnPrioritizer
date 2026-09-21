import pandas as pd

REQUIRED_COLUMNS={"asset_id","ip_address","hostname","nexpose_id","cve","title","date_published","severity_score","cvss_v3_score"}

def parse_rapid7_csv(file_obj, intel):
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

    epss=intel.load_epss()
    kev=intel.load_kev()
    valid=df[df["cve"].str.startswith("CVE-")].copy()

    vuln=valid.groupby("cve",as_index=False).agg(
        title=("title","first"),cvss_v3_score=("cvss_v3_score","max"),
        affected_assets=("asset_id","nunique"),findings=("asset_id","size"),
        date_published=("date_published","min"))
    vuln["age_days"]=(pd.Timestamp.now().normalize()-vuln["date_published"]).dt.days
    vuln["epss"]=vuln["cve"].map(lambda c:epss.get(c,{}).get("epss"))
    vuln["percentile"]=vuln["cve"].map(lambda c:epss.get(c,{}).get("percentile"))
    vuln["kev"]=vuln["cve"].isin(kev)
    vuln=vuln.sort_values(["kev","epss","affected_assets","cvss_v3_score"],ascending=[False,False,False,False],na_position="last")

    kev_cves=set(vuln.loc[vuln.kev,"cve"])
    high_epss=set(vuln.loc[vuln.epss.fillna(0)>=.10,"cve"])

    asset=df.groupby("asset_id",as_index=False).agg(
        hostname=("hostname",lambda s:next((x for x in s if x),"")),
        ip_address=("ip_address",lambda s:next((x for x in s if x),"")),
        findings=("nexpose_id","size"),
        unique_cves=("cve",lambda s:s[s.str.startswith("CVE-")].nunique()),
        max_cvss=("cvss_v3_score","max"))
    asset["kev_cves"]=asset.asset_id.map(lambda a:df[(df.asset_id==a)&(df.cve.isin(kev_cves))].cve.nunique())
    asset["high_epss_cves"]=asset.asset_id.map(lambda a:df[(df.asset_id==a)&(df.cve.isin(high_epss))].cve.nunique())
    asset=asset.sort_values(["kev_cves","high_epss_cves","findings"],ascending=False)

    vulns=[]
    for r in vuln.itertuples(index=False):
        vulns.append({"cve":r.cve,"title":r.title,"cvss":"" if pd.isna(r.cvss_v3_score) else f"{r.cvss_v3_score:.1f}",
          "epss":"" if pd.isna(r.epss) else f"{r.epss*100:.2f}%","epss_raw":0 if pd.isna(r.epss) else float(r.epss),
          "percentile":"" if pd.isna(r.percentile) else f"{r.percentile*100:.2f}%","kev":bool(r.kev),
          "affected_assets":int(r.affected_assets),"findings":int(r.findings),
          "published":"" if pd.isna(r.date_published) else r.date_published.strftime("%Y-%m-%d")})
    assets=[{"asset_id":r.asset_id,"hostname":r.hostname or "—","ip_address":r.ip_address or "—",
      "findings":int(r.findings),"unique_cves":int(r.unique_cves),"kev_cves":int(r.kev_cves),
      "high_epss_cves":int(r.high_epss_cves),"max_cvss":"" if pd.isna(r.max_cvss) else f"{r.max_cvss:.1f}"} for r in asset.itertuples(index=False)]

    return {"metrics":{"findings":len(df),"assets":df.loc[df.asset_id!="","asset_id"].nunique(),"cves":valid.cve.nunique(),
      "kev_cves":int(vuln.kev.sum()),"kev_assets":df[df.cve.isin(kev_cves)].asset_id.nunique(),
      "high_epss_cves":int((vuln.epss.fillna(0)>=.10).sum()),"critical_findings":int((df.cvss_v3_score>=9).sum())},
      "quality":{"missing_cve":int((~df.cve.str.startswith("CVE-")).sum()),"missing_hostname":int((df.hostname=="").sum()),
      "missing_cvss":int(df.cvss_v3_score.isna().sum())},"intel_status":intel.get_status(),
      "vulnerabilities":vulns,"assets_table":assets}
