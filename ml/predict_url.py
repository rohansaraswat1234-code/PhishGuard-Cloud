import pickle
import pandas as pd
from pathlib import Path

from ml.url_features import extract_features


FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "dot_count",
    "hyphen_count",
    "at_count",
    "slash_count",
    "digit_count",
    "https",
    "has_ip",
    "suspicious_word_count"
]


MODEL_PATH = Path(__file__).resolve().parent / "models" / "phishing_model_real.pkl"

with open(MODEL_PATH, "rb") as file:
    model = pickle.load(file)


def predict_url(url):
    from urllib.parse import urlsplit, urlunsplit

    parsed = urlsplit(url)

    # Root "/" and no query/fragment means same site as no trailing slash.
    # Normalize it so bulk and single URL scanning use identical ML features.
    if parsed.path == "/" and not parsed.query and not parsed.fragment:
        url = urlunsplit((
            parsed.scheme,
            parsed.netloc,
            "",
            "",
            ""
        ))

    features = extract_features(url)

    row = pd.DataFrame(
        [[features[name] for name in FEATURE_NAMES]],
        columns=FEATURE_NAMES
    )

    prediction = model.predict(row)[0]
    probability = model.predict_proba(row)[0][1]

    return {
        "prediction": "PHISHING" if prediction == 1 else "SAFE",
        "phishing_probability": float(round(probability * 100, 2))
    }


if __name__ == "__main__":
    tests = [
        "https://google.com",
        "http://192.168.1.25/login/verify/account",
        "http://bit.ly/verify-account"
    ]

    for url in tests:
        print()
        print(url)
        print(predict_url(url))
