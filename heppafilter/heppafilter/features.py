"""
Heppafilter — URL Feature Extraction
Extracts lexical and structural features from URLs for phishing detection.
Validated against MITRE ATT&CK T1566 (Phishing).
"""

import re
import math
from urllib.parse import urlparse


# ── Entropy ────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


# ── Feature extraction ─────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Extract 22 lexical + structural features from a URL.

    Returns a dict of feature_name -> numeric value.
    All features are numeric for sklearn compatibility.
    """
    url = url.strip()

    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        path   = parsed.path
        query  = parsed.query
    except Exception:
        domain = url
        path   = ""
        query  = ""

    full_url   = url
    tld_parts  = domain.split(".")
    subdomain  = ".".join(tld_parts[:-2]) if len(tld_parts) > 2 else ""

    suspicious_keywords = [
        "login", "signin", "verify", "update", "secure", "account",
        "banking", "confirm", "password", "paypal", "ebay", "amazon",
        "apple", "microsoft", "google", "support", "alert", "urgent",
        "free", "winner", "click", "validate", "suspend", "unusual"
    ]

    features = {
        # Length-based
        "url_length":           len(full_url),
        "domain_length":        len(domain),
        "path_length":          len(path),
        "query_length":         len(query),

        # Dot / subdomain
        "dot_count":            full_url.count("."),
        "subdomain_count":      len(subdomain.split(".")) if subdomain else 0,
        "subdomain_length":     len(subdomain),

        # Special characters
        "hyphen_count":         full_url.count("-"),
        "at_count":             full_url.count("@"),
        "double_slash_count":   full_url.count("//") - 1,  # exclude protocol
        "slash_count":          path.count("/"),
        "question_mark_count":  full_url.count("?"),
        "ampersand_count":      full_url.count("&"),
        "equals_count":         full_url.count("="),
        "percent_count":        full_url.count("%"),
        "tilde_count":          full_url.count("~"),

        # Security signals
        "is_https":             1 if full_url.startswith("https://") else 0,
        "has_ip_address":       1 if re.search(r"\d{1,3}(\.\d{1,3}){3}", domain) else 0,
        "has_port":             1 if re.search(r":\d{2,5}", domain) else 0,
        "digits_in_domain":     sum(c.isdigit() for c in domain),

        # Entropy (high entropy = random/obfuscated domain)
        "domain_entropy":       round(shannon_entropy(domain), 4),

        # Keyword presence
        "suspicious_keyword":   1 if any(kw in full_url.lower() for kw in suspicious_keywords) else 0,
    }

    return features


def features_to_vector(url: str) -> list:
    """Return features as an ordered list (for sklearn input)."""
    return list(extract_features(url).values())


FEATURE_NAMES = list(extract_features("https://example.com").keys())
