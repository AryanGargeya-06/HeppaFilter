# 🛡 Heppafilter — ML-Powered Phishing URL Detector

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-RandomForest-F7931E?style=flat&logo=scikit-learn&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1566-red?style=flat)
![Accuracy](https://img.shields.io/badge/Accuracy-95%25-brightgreen?style=flat)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat)

> **MSc Cybersecurity Dissertation Project — Nottingham Trent University, 2024**
>
> Real-time phishing URL detection using Machine Learning and NLP. Detection logic validated against **MITRE ATT&CK T1566 (Phishing)**. Achieves **95%+ accuracy** across 6,000+ URL dataset.

---

## Overview

Heppafilter is a browser extension + Python backend that detects phishing URLs in real time using a Random Forest classifier trained on 22 hand-crafted URL features. It surfaces risk signals that map directly to MITRE ATT&CK techniques, making it relevant for SOC alert triage, SIEM rule development, and threat intelligence workflows.

```
User visits URL
      │
      ▼
Chrome Extension (Manifest V3)
      │  POST /predict
      ▼
Flask API (localhost:5000)
      │
      ▼
Feature Extraction (22 features)
  • URL length & structure
  • Domain entropy (Shannon)
  • Suspicious keywords
  • IP-as-domain detection
  • HTTPS / TLS check
  • Subdomain depth
  • Special character counts
      │
      ▼
Random Forest Classifier
  (200 estimators, balanced class weights)
      │
      ▼
Risk Score + MITRE ATT&CK Mapping
      │
      ▼
Extension Popup / CLI Output
```

---

## Features

| Feature | Description |
|---|---|
| **Real-time detection** | Checks every page navigation against the ML model |
| **22 lexical features** | URL structure, entropy, keyword signals, TLS status |
| **MITRE ATT&CK mapping** | Flags detections against T1566 with technique context |
| **Risk levels** | LOW / MEDIUM / HIGH / CRITICAL with confidence score |
| **CLI tool** | Scan individual URLs or batch-process files |
| **REST API** | Flask endpoint for integration with SIEM/SOAR platforms |
| **Chrome Extension** | Real-time popup with colour-coded risk indicators |

---

## Results

| Metric | Score |
|---|---|
| Accuracy | **95%+** |
| Precision (Phishing) | 0.96 |
| Recall (Phishing) | 0.94 |
| F1 Score | 0.95 |
| CV (5-fold) | 95% ± 1.2% |

**Top predictive features:**
1. `is_https` — absence of HTTPS is the strongest single indicator
2. `url_length` — phishing URLs tend to be longer for obfuscation
3. `digits_in_domain` — numeric substitution (paypa1, g00gle)
4. `domain_entropy` — high entropy = obfuscated/randomised domain
5. `suspicious_keyword` — login, verify, secure, update, etc.

---

## Installation

```bash
# Clone the repo
git clone https://github.com/aryan-eswara/heppafilter.git
cd heppafilter

# Install dependencies
pip install -r requirements.txt

# Generate training data & train the model
python heppafilter/train.py --eval
```

---

## Usage

### CLI
```bash
# Check a single URL
python -m heppafilter.detector https://suspicious-site.tk/login

# Batch check from file
python -m heppafilter.detector --batch urls.txt

# JSON output (for SIEM integration)
python -m heppafilter.detector --json https://example.com
```

**Example output:**
```
────────────────────────────────────────────────────────────
  URL      : http://paypa1-secure-login.tk/account/verify
  Result   : PHISHING
  Risk     : CRITICAL  (confidence: 98.4%)
  MITRE    : T1566 — Phishing
  Signals  :
    ⚠  Suspicious keyword detected
    ⚠  High domain entropy (obfuscation)
    ⚠  Not HTTPS
    ⚠  Excessive hyphens in domain
────────────────────────────────────────────────────────────
```

### API
```bash
# Start the API server
python heppafilter/api.py

# Check a URL
curl -X POST http://localhost:5000/predict \
     -H "Content-Type: application/json" \
     -d '{"url": "http://paypal-login.tk/verify"}'
```

**API Response:**
```json
{
  "url": "http://paypal-login.tk/verify",
  "label": "PHISHING",
  "confidence": 0.984,
  "risk_level": "CRITICAL",
  "risk_signals": [
    "Suspicious keyword detected",
    "Not HTTPS",
    "High domain entropy (obfuscation)"
  ],
  "mitre_technique": "T1566 — Phishing"
}
```

### Chrome Extension
1. Start the API: `python heppafilter/api.py`
2. Open Chrome → `chrome://extensions`
3. Enable **Developer Mode**
4. Click **Load unpacked** → select the `extension/` folder
5. Browse to any site — the extension checks it automatically

---

## MITRE ATT&CK Alignment

| ATT&CK Technique | Description | How Heppafilter Detects It |
|---|---|---|
| T1566 | Phishing | Core detection objective — trained on phishing URL patterns |
| T1566.001 | Spearphishing Attachment | Detects suspicious keywords + file paths in URLs |
| T1566.002 | Spearphishing Link | Identifies lookalike/typosquatting domains |
| T1036 | Masquerading | Detects brand impersonation via keyword analysis |

---

## Project Structure

```
heppafilter/
├── heppafilter/
│   ├── features.py      # 22-feature URL feature extractor
│   ├── train.py         # Model training + evaluation
│   ├── detector.py      # CLI detection engine
│   └── api.py           # Flask REST API
├── extension/
│   ├── manifest.json    # Chrome Manifest V3
│   ├── background.js    # Service worker + navigation listener
│   ├── popup.html       # Extension UI
│   └── popup.js         # Popup logic
├── data/
│   └── generate_dataset.py  # Synthetic URL dataset generator
├── models/              # Trained model (auto-generated)
└── requirements.txt
```

---

## Tech Stack

- **ML:** scikit-learn (RandomForestClassifier), NumPy
- **API:** Flask, Flask-CORS
- **Extension:** Chrome Manifest V3 (JS, HTML)
- **Validation:** MITRE ATT&CK T1566, OWASP Phishing Datasets

---

## Author

**Aryan Gargeya Eswara Venekata**
MSc Cybersecurity — Nottingham Trent University, 2024

[![LinkedIn](https://img.shields.io/badge/LinkedIn-aryan--eswara-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/aryan-eswara)
[![GitHub](https://img.shields.io/badge/GitHub-aryan--eswara-181717?style=flat&logo=github)](https://github.com/aryan-eswara)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
