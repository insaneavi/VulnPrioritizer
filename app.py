from flask import Flask, render_template, request, redirect, url_for, flash
from services.rapid7_parser import parse_rapid7_csv

app = Flask(__name__)
app.secret_key = "vulnprioritizer-dev-key"
APP_VERSION = "0.1.0"
RELEASE_DATE = "2026-09-21"

@app.context_processor
def inject_version():
    return {"app_version": APP_VERSION, "release_date": RELEASE_DATE}

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/analyze")
def analyze():
    upload = request.files.get("rapid7_file")
    if not upload or not upload.filename:
        flash("Select a Rapid7 CSV file.")
        return redirect(url_for("index"))
    try:
        return render_template("dashboard.html", **parse_rapid7_csv(upload))
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("index"))
    except Exception as exc:
        app.logger.exception("Analysis failed")
        flash(f"Unable to analyze the file: {exc}")
        return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8085)
