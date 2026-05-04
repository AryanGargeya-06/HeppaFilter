"""
Heppafilter — REST API
Flask-based API that the Chrome extension calls.

Endpoints:
    POST /predict          {"url": "https://..."}
    POST /predict/batch    {"urls": ["https://...", ...]}
    GET  /health

Run:
    python api.py
    # Server starts at http://localhost:5000
"""

import os
import sys
import json
from functools import wraps

BASE_DIR = os.path.dirname(__file__)
sys.path.insert(0, BASE_DIR)

try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
except ImportError:
    print("[ERROR] Flask not found. Run: pip install flask flask-cors")
    sys.exit(1)

from heppafilter.detector import HeppafilterDetector

app      = Flask(__name__)
CORS(app)  # Allow Chrome extension to call the API
detector = HeppafilterDetector()


# ── Helpers ────────────────────────────────────────────────────────────────

def require_json(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        return f(*args, **kwargs)
    return wrapper


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model": "heppafilter_rf_v1"})


@app.route("/predict", methods=["POST"])
@require_json
def predict():
    data = request.get_json()
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Missing 'url' field"}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL exceeds maximum length (2048 chars)"}), 400

    result = detector.predict(url)
    return jsonify(result)


@app.route("/predict/batch", methods=["POST"])
@require_json
def predict_batch():
    data = request.get_json()
    urls = data.get("urls", [])

    if not urls or not isinstance(urls, list):
        return jsonify({"error": "Missing or invalid 'urls' array"}), 400
    if len(urls) > 100:
        return jsonify({"error": "Batch limited to 100 URLs per request"}), 400

    results = detector.predict_batch(urls)
    summary = {
        "total":      len(results),
        "phishing":   sum(1 for r in results if r["label"] == "PHISHING"),
        "legitimate": sum(1 for r in results if r["label"] == "LEGITIMATE"),
    }
    return jsonify({"summary": summary, "results": results})


# ── Run ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[Heppafilter API] Starting on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
