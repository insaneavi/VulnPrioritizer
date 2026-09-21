from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from services.rapid7_parser import parse_rapid7_csv
from services.threat_intel import ThreatIntelManager
from services.release_notes import RELEASES

app = Flask(__name__)
app.secret_key = "vulnprioritizer-local-session-key"
APP_VERSION = "0.2.1"
RELEASE_DATE = "2026-09-21"
intel = ThreatIntelManager()

@app.context_processor
def inject_globals():
    return {"app_version": APP_VERSION, "release_date": RELEASE_DATE, "releases": RELEASES}

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
        return render_template("dashboard.html", **result)
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("index"))
    except Exception as exc:
        app.logger.exception("Rapid7 analysis failed")
        flash(f"Unable to analyze the file: {exc}")
        return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8085)
