"""
Heppafilter — Synthetic Dataset Generator
Generates a labelled phishing / legitimate URL dataset for training.

Legitimate URLs are drawn from Alexa Top-1M patterns.
Phishing URLs replicate common evasion techniques catalogued in MITRE ATT&CK T1566.
"""

import random
import csv
import os

random.seed(42)

# ── Legitimate domain pools ────────────────────────────────────────────────
LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "twitter.com", "amazon.com",
    "wikipedia.org", "reddit.com", "linkedin.com", "bbc.co.uk", "gov.uk",
    "apple.com", "microsoft.com", "github.com", "stackoverflow.com", "netflix.com",
    "paypal.com", "ebay.co.uk", "nhs.uk", "hmrc.gov.uk", "barclays.co.uk",
    "lloydsbank.com", "hsbc.co.uk", "santander.co.uk", "nationwide.co.uk",
    "sky.com", "bbc.com", "theguardian.com", "independent.co.uk", "ft.com",
]

LEGIT_PATHS = [
    "/", "/about", "/contact", "/login", "/account", "/search", "/news",
    "/products", "/services", "/support", "/faq", "/privacy", "/terms",
    "/blog/2024/cybersecurity", "/help/centre", "/account/settings",
]

# ── Phishing pattern templates ─────────────────────────────────────────────
PHISHING_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "hsbc", "barclays", "lloyds", "halifax", "santander", "natwest",
    "ebay", "facebook", "instagram", "twitter", "linkedin", "gov",
]

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "confirm", "validate", "suspended", "unlock", "unusual-activity",
    "password-reset", "billing", "invoice", "refund",
]

PHISHING_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".pw", ".cc", ".biz", ".info", ".online", ".site", ".web",
]

LEGIT_TLDS = [".com", ".co.uk", ".org", ".net", ".gov.uk", ".edu"]

IP_POOL = [
    f"192.168.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)
]


def _rand_str(length=8):
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(length))


def generate_legitimate_url():
    domain = random.choice(LEGIT_DOMAINS)
    path   = random.choice(LEGIT_PATHS)
    proto  = "https://"
    return proto + domain + path


def generate_phishing_url():
    technique = random.choice([
        "brand_typosquat",
        "brand_subdomain",
        "ip_address",
        "long_url",
        "keyword_stuffing",
        "lookalike_tld",
        "homograph",
    ])

    brand   = random.choice(PHISHING_BRANDS)
    keyword = random.choice(PHISHING_KEYWORDS)
    tld     = random.choice(PHISHING_TLDS)
    rand    = _rand_str(6)

    if technique == "brand_typosquat":
        # e.g. paypa1-secure.tk/login
        mutations = [brand + rand, brand + "-" + keyword, brand.replace("a", "4"),
                     brand[:-1] + brand[-1] + brand[-1]]
        domain = random.choice(mutations) + tld
        path   = "/" + keyword + "/" + _rand_str(12)
        return "http://" + domain + path

    elif technique == "brand_subdomain":
        # e.g. paypal.secure-login.xyz/account/verify
        host_domain = _rand_str(8) + random.choice(LEGIT_TLDS)
        return f"http://{brand}.{keyword}.{host_domain}/{keyword}?token={_rand_str(16)}"

    elif technique == "ip_address":
        ip = random.choice(IP_POOL)
        return f"http://{ip}/{brand}/{keyword}?id={_rand_str(8)}"

    elif technique == "long_url":
        # Legitimate-looking but very long URL
        legit = random.choice(LEGIT_DOMAINS)
        fake  = _rand_str(10) + tld
        return (f"http://{fake}/{brand}-{keyword}/" +
                "/".join(_rand_str(6) for _ in range(4)) +
                f"?redirect=https://{legit}&token={_rand_str(24)}")

    elif technique == "keyword_stuffing":
        kws = "-".join(random.sample(PHISHING_KEYWORDS, k=3))
        return f"http://{brand}-{kws}{tld}/{_rand_str(8)}"

    elif technique == "lookalike_tld":
        return f"https://{brand}{random.choice(LEGIT_TLDS[:-1])}.{_rand_str(5)}{tld}/{keyword}"

    else:  # homograph-style
        homographs = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}
        mutated = "".join(homographs.get(c, c) for c in brand)
        return f"http://{mutated}{tld}/{keyword}?session={_rand_str(20)}"


def generate_dataset(n_legit=2000, n_phish=2000, output_path="data/urls.csv"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    rows = []

    for _ in range(n_legit):
        rows.append({"url": generate_legitimate_url(), "label": 0})
    for _ in range(n_phish):
        rows.append({"url": generate_phishing_url(), "label": 1})

    random.shuffle(rows)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Dataset generated: {len(rows)} URLs → {output_path}")
    print(f"  Legitimate : {n_legit}")
    print(f"  Phishing   : {n_phish}")
    return output_path


if __name__ == "__main__":
    generate_dataset()
