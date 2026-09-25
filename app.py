from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from services.rapid7_parser import parse_rapid7_csv
from services.threat_intel import ThreatIntelManager
from services.release_notes import RELEASES
from services.time_utils import display_time
from services.analysis_store import AnalysisStore
from services.network_config import NetworkConfig
from services.reporting import build_report
from services.operations_reporting import build_operations_report
from datetime import datetime

app = Flask(__name__)
app.secret_key = "vulnprioritizer-local-session-key"
APP_VERSION = "0.7.0"
RELEASE_DATE = "2026-09-25"
intel = ThreatIntelManager()
analysis_store = AnalysisStore(max_sessions=5)
network_config = NetworkConfig()

@app.context_processor
def inject_globals():
    return {"app_version": APP_VERSION, "release_date": RELEASE_DATE, "releases": RELEASES, "display_time": display_time, "proxy": network_config.public(), "proxy_method": network_config.masked_proxy()}

@app.get("/")
def index():
    return render_template("index.html", intel_status=intel.get_status())

@app.get("/threat-intelligence")
def threat_intelligence():
    return render_template("threat_intelligence.html", intel_status=intel.get_status(), diagnostics=intel.get_diagnostics())

@app.post("/threat-intelligence/update")
def update_threat_intelligence():
    source = request.form.get("source", "all")
    if source == "epss":
        ok = intel.update_epss()
        flash("FIRST EPSS update completed successfully." if ok else "FIRST EPSS update failed. Last-known-good EPSS data was preserved.")
    elif source == "kev":
        ok = intel.update_kev()
        flash("CISA KEV update completed successfully." if ok else "CISA KEV update failed. Last-known-good KEV data was preserved.")
    else:
        result = intel.update_all()
        if result["success"]:
            flash("All threat intelligence sources updated successfully.")
        else:
            succeeded = [name for name in ("epss", "kev") if result.get(name)]
            failed = [name for name in ("epss", "kev") if not result.get(name)]
            flash(f"Threat intelligence update completed. Successful: {', '.join(succeeded) or 'none'}. Failed: {', '.join(failed) or 'none'}. Last-known-good data was preserved for failed sources.")
    return redirect(url_for("threat_intelligence"))

@app.get("/information")
def information():
    return render_template("information.html")

@app.get("/release-notes")
def release_notes():
    return render_template("release_notes.html")

@app.post("/analyze")
def analyze():
    upload = request.files.get("rapid7_file")
    if not upload or not upload.filename:
        flash("Select a Rapid7 CSV file.")
        return redirect(url_for("index"))
    try:
        result = parse_rapid7_csv(upload, intel)
        analysis_id = analysis_store.create(result)
        return redirect(url_for("dashboard", analysis_id=analysis_id))
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("index"))
    except Exception as exc:
        app.logger.exception("Rapid7 analysis failed")
        flash(f"Unable to analyze the file: {exc}")
        return redirect(url_for("index"))


@app.get("/analysis/<analysis_id>")
def dashboard(analysis_id):
    analysis = analysis_store.get(analysis_id)
    if not analysis:
        flash("This analysis session is no longer available. Upload the Rapid7 report again.")
        return redirect(url_for("index"))
    return render_template("dashboard.html", analysis_id=analysis_id, **analysis)

@app.get("/analysis/<analysis_id>/cve/<cve>")
def cve_investigation(analysis_id, cve):
    analysis = analysis_store.get(analysis_id)
    if not analysis:
        flash("This analysis session is no longer available. Upload the Rapid7 report again.")
        return redirect(url_for("index"))
    cve = cve.upper()
    vuln = analysis["cve_index"].get(cve)
    if not vuln:
        flash(f"{cve} was not found in this analysis.")
        return redirect(url_for("dashboard", analysis_id=analysis_id))
    affected = analysis["cve_assets"].get(cve, [])
    related_unique = set()
    other_kev_assets = 0
    for a in affected:
        for v in analysis["asset_cves"].get(a["asset_id"], []):
            related_unique.add(v["cve"])
        if a["kev_cves"] > (1 if vuln["kev"] else 0):
            other_kev_assets += 1
    context = {"related_unique_cves":len(related_unique),"assets_with_other_kev":other_kev_assets}
    return render_template("cve_detail.html", analysis_id=analysis_id, vuln=vuln,
                           affected_assets=affected, kev_detail=analysis["kev_details"].get(cve,{}),
                           context=context)

@app.get("/analysis/<analysis_id>/asset/<asset_id>")
def asset_investigation(analysis_id, asset_id):
    analysis = analysis_store.get(analysis_id)
    if not analysis:
        flash("This analysis session is no longer available. Upload the Rapid7 report again.")
        return redirect(url_for("index"))
    asset = analysis["asset_index"].get(asset_id)
    if not asset:
        flash("Asset was not found in this analysis.")
        return redirect(url_for("dashboard", analysis_id=analysis_id))
    return render_template("asset_detail.html", analysis_id=analysis_id, asset=asset,
                           vulnerabilities=analysis["asset_cves"].get(asset_id, []))


@app.post("/threat-intelligence/proxy")
def save_proxy():
    old=network_config.load()
    network_config.save({"enabled":request.form.get("enabled")=="on","protocol":request.form.get("protocol","http"),"host":request.form.get("host","").strip(),"port":request.form.get("port","").strip(),"username":request.form.get("username","").strip(),"password":request.form.get("password","") or old.get("password","")})
    flash("Proxy configuration saved."); return redirect(url_for("threat_intelligence"))

@app.post("/threat-intelligence/proxy/test")
def test_proxy():
    import socket, requests as rq
    c=network_config.load()
    if not c["enabled"]: flash("Proxy is currently disabled."); return redirect(url_for("threat_intelligence"))
    try:
        socket.create_connection((c["host"],int(c["port"])),timeout=8).close()
        r=rq.get("https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",proxies=network_config.proxies(),timeout=30,stream=True)
        flash(f"Proxy {network_config.masked_proxy()}: TCP SUCCESS | EPSS HTTPS through proxy: HTTP {r.status_code}")
    except Exception as e: flash("Proxy test FAILED: "+str(e))
    return redirect(url_for("threat_intelligence"))

@app.post("/threat-intelligence/proxy/clear")
def clear_proxy():
    network_config.save({"enabled":False,"protocol":"http","host":"","port":"","username":"","password":""}); flash("Proxy configuration cleared."); return redirect(url_for("threat_intelligence"))

@app.get("/analysis/<analysis_id>/priority/<category>")
def priority_drilldown(analysis_id,category):
    a=analysis_store.get(analysis_id)
    if not a: flash("This analysis session is no longer available. Upload the Rapid7 report again."); return redirect(url_for("index"))
    if category=="kev": title,ex,mode,rows="Known Exploited","CVEs currently listed in CISA KEV.","vulns",[v for v in a["vulnerabilities"] if v["kev"]]
    elif category=="epss": title,ex,mode,rows="High EPSS","CVEs with EPSS probability of 10% or greater.","vulns",[v for v in a["vulnerabilities"] if v["epss_raw"]>=.10]
    elif category=="kev-assets": title,ex,mode,rows="Assets with KEV","Assets containing at least one CISA KEV vulnerability.","assets",[x for x in a["assets_table"] if x["kev_cves"]>0]
    elif category=="critical": title,ex,mode,rows="Critical Findings",f'{a["metrics"]["critical_findings"]:,} findings have CVSS v3 ≥ 9.0; results are grouped by unique CVE.',"vulns",[v for v in a["vulnerabilities"] if v["cvss_raw"] is not None and v["cvss_raw"]>=9]
    else: return redirect(url_for("dashboard",analysis_id=analysis_id))
    return render_template("priority_detail.html",analysis_id=analysis_id,title=title,explanation=ex,mode=mode,rows=rows)


@app.get("/analysis/<analysis_id>/reporting")
def reporting(analysis_id):
    analysis=analysis_store.get(analysis_id)
    if not analysis:
        flash("This analysis session is no longer available. Upload the Rapid7 report again.")
        return redirect(url_for("index"))
    return render_template("reporting.html",analysis_id=analysis_id,**analysis)

@app.get("/analysis/<analysis_id>/reporting/excel")
def reporting_excel(analysis_id):
    analysis=analysis_store.get(analysis_id)
    if not analysis:
        flash("This analysis session is no longer available. Upload the Rapid7 report again.")
        return redirect(url_for("index"))
    report=build_report(analysis)
    filename=f"VulnPrioritizer_Report_{datetime.now().strftime('%Y-%m-%d_%H%M')}.xlsx"
    return send_file(report,as_attachment=True,download_name=filename,mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.get("/analysis/<analysis_id>/reporting/operations")
def reporting_operations_excel(analysis_id):
    analysis=analysis_store.get(analysis_id)
    if not analysis:
        flash("This analysis session is no longer available. Upload the Rapid7 report again.")
        return redirect(url_for("index"))
    report,_=build_operations_report(analysis)
    filename=f"VulnPrioritizer_Operations_Patching_{datetime.now().strftime('%Y-%m-%d_%H%M')}.xlsx"
    return send_file(report,as_attachment=True,download_name=filename,mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8085)
