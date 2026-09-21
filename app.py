from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from services.rapid7_parser import parse_rapid7_csv
from services.threat_intel import ThreatIntelManager
from services.release_notes import RELEASES
from services.time_utils import display_time
from services.analysis_store import AnalysisStore

app = Flask(__name__)
app.secret_key = "vulnprioritizer-local-session-key"
APP_VERSION = "0.4.1"
RELEASE_DATE = "2026-09-21"
intel = ThreatIntelManager()
analysis_store = AnalysisStore(max_sessions=5)

@app.context_processor
def inject_globals():
    return {"app_version": APP_VERSION, "release_date": RELEASE_DATE, "releases": RELEASES, "display_time": display_time}

@app.get("/")
def index():
    return render_template("index.html", intel_status=intel.get_status())

@app.get("/threat-intelligence")
def threat_intelligence():
    return render_template("threat_intelligence.html", intel_status=intel.get_status(), diagnostics=intel.get_diagnostics())

@app.post("/threat-intelligence/update")
def update_threat_intelligence():
    result = intel.update_all()
    if result["success"]:
        flash("Threat intelligence update completed.")
    else:
        flash("Threat intelligence update completed with one or more failures. Last-known-good data was preserved.")
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8085)
