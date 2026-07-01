from flask import Flask, render_template, jsonify, send_file, request
import json
import os
from detector import load_logs, run_detections, get_summary
from report_generator import generate_report

app = Flask(__name__)

SIMULATED_PATH = "data/simulated_logs.json"
CLOUDTRAIL_PATH = "data/cloudtrail_logs.json"

def get_logs(source="simulated"):
    if source == "cloudtrail" and os.path.exists(CLOUDTRAIL_PATH):
        return load_logs(CLOUDTRAIL_PATH)
    return load_logs(SIMULATED_PATH)

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/analyze")
def analyze():
    source = request.args.get("source", "simulated")
    try:
        logs = get_logs(source)
        results = run_detections(logs)
        summary = get_summary(results)
        return jsonify({"results": results, "summary": summary, "source": source, "total_logs": len(logs)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/report")
def download_report():
    source = request.args.get("source", "simulated")
    try:
        logs = get_logs(source)
        results = run_detections(logs)
        summary = get_summary(results)
        path = generate_report(results, summary)
        return send_file(path, as_attachment=True, download_name="identity_threat_report.xlsx")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ingest-cloudtrail", methods=["POST"])
def ingest_cloudtrail():
    try:
        from cloudtrail_ingest import fetch_cloudtrail_logs
        data = request.get_json() or {}
        region = data.get("region", "us-east-1")
        hours = int(data.get("hours", 24))
        fetch_cloudtrail_logs(region=region, hours=hours)
        return jsonify({"status": "success", "message": f"CloudTrail logs fetched for region {region}, last {hours}h"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    if not os.path.exists(SIMULATED_PATH):
        import subprocess
        subprocess.run(["python", "data/generate_logs.py"])
    app.run(host="0.0.0.0", port=5000, debug=True)