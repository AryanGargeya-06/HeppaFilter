"""
Heppafilter — Phishing URL Detector
Core detection engine. Loads a trained model and scores URLs.

Usage (CLI):
    python -m heppafilter.detector https://suspicious-site.tk/login
    python -m heppafilter.detector --batch urls.txt
"""

import os
import sys
import pickle
import argparse

BASE_DIR   = os.path.dirname(os.path.dirname(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "heppafilter_model.pkl")


def _load_model():
    if not os.path.exists(MODEL_PATH):
        print("[INFO] No trained model found. Training now...")
        sys.path.insert(0, BASE_DIR)
        from heppafilter.train import train
        return train()
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


class HeppafilterDetector:
    """
    Phishing URL detection engine.

    Example:
        detector = HeppafilterDetector()
        result   = detector.predict("http://paypa1-login.tk/verify")
        print(result)
        # {'url': '...', 'label': 'PHISHING', 'confidence': 0.96, 'risk_level': 'HIGH'}
    """

    RISK_THRESHOLDS = {
        "LOW":    (0.0,  0.40),
        "MEDIUM": (0.40, 0.70),
        "HIGH":   (0.70, 0.90),
        "CRITICAL": (0.90, 1.01),
    }

    def __init__(self):
        sys.path.insert(0, BASE_DIR)
        from heppafilter.features import features_to_vector, extract_features
        self._features_to_vector = features_to_vector
        self._extract_features   = extract_features
        self.model = _load_model()

    def _risk_level(self, prob_phishing: float) -> str:
        for level, (lo, hi) in self.RISK_THRESHOLDS.items():
            if lo <= prob_phishing < hi:
                return level
        return "LOW"

    def predict(self, url: str) -> dict:
        """Predict whether a URL is phishing or legitimate."""
        vec        = [self._features_to_vector(url)]
        proba      = self.model.predict_proba(vec)[0]
        prob_phish = float(proba[1])
        label      = "PHISHING" if prob_phish >= 0.50 else "LEGITIMATE"
        features   = self._extract_features(url)

        # Key risk signals
        signals = []
        if features["has_ip_address"]:        signals.append("IP address used as domain")
        if features["suspicious_keyword"]:     signals.append("Suspicious keyword detected")
        if features["at_count"] > 0:           signals.append("'@' character in URL (redirection trick)")
        if features["double_slash_count"] > 0: signals.append("Double slash after protocol")
        if features["domain_entropy"] > 3.5:   signals.append("High domain entropy (obfuscation)")
        if features["url_length"] > 100:        signals.append("Abnormally long URL")
        if not features["is_https"]:           signals.append("Not HTTPS")
        if features["hyphen_count"] > 3:        signals.append("Excessive hyphens in domain")

        return {
            "url":             url,
            "label":           label,
            "confidence":      round(prob_phish if label == "PHISHING" else 1 - prob_phish, 4),
            "phishing_prob":   round(prob_phish, 4),
            "legitimate_prob": round(float(proba[0]), 4),
            "risk_level":      self._risk_level(prob_phish),
            "risk_signals":    signals,
            "mitre_technique": "T1566 — Phishing" if label == "PHISHING" else None,
        }

    def predict_batch(self, urls: list) -> list:
        """Predict a batch of URLs."""
        return [self.predict(u) for u in urls]


# ── CLI ────────────────────────────────────────────────────────────────────

def _print_result(result: dict):
    colours = {"LEGITIMATE": "\033[92m", "PHISHING": "\033[91m"}
    reset   = "\033[0m"
    risk_c  = {"LOW": "\033[92m", "MEDIUM": "\033[93m", "HIGH": "\033[91m", "CRITICAL": "\033[31m"}

    c = colours.get(result["label"], "")
    r = risk_c.get(result["risk_level"], "")

    print(f"\n{'─'*60}")
    print(f"  URL      : {result['url']}")
    print(f"  Result   : {c}{result['label']}{reset}")
    print(f"  Risk     : {r}{result['risk_level']}{reset}  (confidence: {result['confidence']*100:.1f}%)")
    if result.get("mitre_technique"):
        print(f"  MITRE    : {result['mitre_technique']}")
    if result["risk_signals"]:
        print(f"  Signals  :")
        for sig in result["risk_signals"]:
            print(f"    ⚠  {sig}")
    print(f"{'─'*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Heppafilter — ML Phishing URL Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m heppafilter.detector https://google.com
  python -m heppafilter.detector http://paypa1-login.tk/verify
  python -m heppafilter.detector --batch urls.txt
        """
    )
    parser.add_argument("url", nargs="?", help="URL to analyse")
    parser.add_argument("--batch", metavar="FILE", help="Text file with one URL per line")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    detector = HeppafilterDetector()

    if args.batch:
        with open(args.batch) as f:
            urls = [line.strip() for line in f if line.strip()]
        results = detector.predict_batch(urls)
        if args.json:
            import json
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                _print_result(r)
        phish_count = sum(1 for r in results if r["label"] == "PHISHING")
        print(f"\nSummary: {phish_count}/{len(results)} URLs flagged as PHISHING")

    elif args.url:
        result = detector.predict(args.url)
        if args.json:
            import json
            print(json.dumps(result, indent=2))
        else:
            _print_result(result)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
