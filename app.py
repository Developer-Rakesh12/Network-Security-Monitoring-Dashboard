from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from pathlib import Path
from datetime import datetime, timezone
import csv, io, json

from monitor import load_and_analyze, SAMPLE_FILE

app = Flask(__name__)
app.secret_key = "local-demo-change-me"
latest = None


@app.route("/", methods=["GET", "POST"])
def index():
    global latest
    if request.method == "POST":
        uploaded = request.files.get("traffic_file")
        if uploaded and uploaded.filename:
            if not uploaded.filename.lower().endswith(".csv"):
                flash("Please upload a CSV file.", "error")
                return redirect(url_for("index"))
            raw = uploaded.stream.read().decode("utf-8-sig")
            latest = load_and_analyze(io.StringIO(raw))
        else:
            latest = load_and_analyze(SAMPLE_FILE)
        latest["generated_at"] = datetime.now(timezone.utc).isoformat()
        return render_template("dashboard.html", report=latest)
    return render_template("index.html")


@app.route("/sample")
def sample():
    return send_file(SAMPLE_FILE, as_attachment=True, download_name="sample_network_traffic.csv")


@app.route("/report/json")
def report_json():
    if not latest:
        flash("Run the dashboard analysis first.", "error")
        return redirect(url_for("index"))
    data = json.dumps(latest, indent=2)
    return send_file(io.BytesIO(data.encode()), mimetype="application/json",
                     as_attachment=True, download_name="network_monitoring_report.json")


@app.route("/report/csv")
def report_csv():
    if not latest:
        flash("Run the dashboard analysis first.", "error")
        return redirect(url_for("index"))
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["timestamp", "source", "destination", "protocol", "bytes", "status", "reason"])
    writer.writeheader()
    writer.writerows(latest["events"])
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv",
                     as_attachment=True, download_name="network_monitoring_events.csv")


if __name__ == "__main__":
    # Local dashboard only.
    app.run(host="127.0.0.1", port=5001, debug=False)
