from urllib.parse import urlparse
import re


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "banking",
    "confirm",
    "password",
    "signin",
    "wallet",
    "payment",
    "recover"
]


def extract_features(url):

    url = str(url).strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    url = url.lower()

    parsed = urlparse(url)

    domain = parsed.hostname or ""

    # Remove www so model does not learn www as a safety signal
    if domain.startswith("www."):
        domain = domain[4:]

    # Also remove www from URL used for length/count features
    feature_url = url.replace("://www.", "://", 1)

    suspicious_word_count = 0

    for word in SUSPICIOUS_WORDS:
        if word in feature_url:
            suspicious_word_count += 1

    features = {
        "url_length": len(feature_url),
        "domain_length": len(domain),
        "dot_count": domain.count("."),
        "hyphen_count": domain.count("-"),
        "at_count": feature_url.count("@"),
        "slash_count": feature_url.count("/"),
        "digit_count": sum(char.isdigit() for char in feature_url),
        "https": 1 if parsed.scheme == "https" else 0,
        "has_ip": 1 if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", domain) else 0,
        "suspicious_word_count": suspicious_word_count
    }

    return features


if __name__ == "__main__":
    tests = [
        "https://www.google.com",
        "https://google.com",
        "https://gla.ac.in",
        "http://192.168.1.25/login/verify/account"
    ]

    for url in tests:
        print(url)
        print(extract_features(url))
        print()
