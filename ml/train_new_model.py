import pickle
import random
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from ml.url_features import extract_features
from ml.predict_url import FEATURE_NAMES

print("=== 1. Loading Real Dataset ===")
df = pd.read_csv("dataset/phiusiil_real.csv")

# In UCI: 1 = Legitimate (Safe), 0 = Phishing
raw_safe_urls = df[df["label"] == 1]["URL"].dropna().astype(str).sample(n=25000, random_state=42).tolist()
raw_phish_urls = df[df["label"] == 0]["URL"].dropna().astype(str).sample(n=25000, random_state=42).tolist()

# Common benign paths to augment legitimate root URLs so model learns paths exist on safe websites
benign_paths = [
    "/", "/search?q=info", "/about", "/contact", "/docs/guide", "/blog/post/1",
    "/article/news", "/profile/user", "/help/faq", "/app/dashboard", "/products/item",
    "/privacy-policy", "/terms", "/home", "/index.html", "/en/overview", "/explore"
]

augmented_safe_urls = []
for u in raw_safe_urls:
    u = u.strip()
    augmented_safe_urls.append(u)
    if random.random() < 0.5:
        path = random.choice(benign_paths)
        augmented_safe_urls.append(u.rstrip("/") + path)

print(f"Total Safe URLs: {len(augmented_safe_urls)} | Total Phishing URLs: {len(raw_phish_urls)}")

print("=== 2. Extracting Features ===")
X_data = []
y_data = []

# Label: 0 = SAFE, 1 = PHISHING
for u in augmented_safe_urls:
    feats = extract_features(u)
    X_data.append([feats[name] for name in FEATURE_NAMES])
    y_data.append(0)

for u in raw_phish_urls:
    feats = extract_features(u)
    X_data.append([feats[name] for name in FEATURE_NAMES])
    y_data.append(1)

X = pd.DataFrame(X_data, columns=FEATURE_NAMES)
y = np.array(y_data)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

print(f"Training on {len(X_train)} samples, testing on {len(X_test)} samples...")

print("=== 3. Training Random Forest Classifier (100 Trees) ===")
rf = RandomForestClassifier(
    n_estimators=100,
    max_depth=12,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)
rf.fit(X_train, y_train)

preds = rf.predict(X_test)
acc = accuracy_score(y_test, preds)
prec = precision_score(y_test, preds)
rec = recall_score(y_test, preds)
f1 = f1_score(y_test, preds)

print(f"Accuracy : {acc*100:.2f}%")
print(f"Precision: {prec*100:.2f}%")
print(f"Recall   : {rec*100:.2f}%")
print(f"F1 Score : {f1*100:.2f}%")
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, preds))

print("\nFeature Importances:")
for name, imp in sorted(zip(FEATURE_NAMES, rf.feature_importances_), key=lambda x: x[1], reverse=True):
    print(f"  {name:22s}: {imp*100:.2f}%")

# Save model
with open("ml/models/phishing_model_real.pkl", "wb") as f:
    pickle.dump(rf, f)
print("\nModel saved successfully to ml/models/phishing_model_real.pkl!")

# Verification test
print("\n=== 4. Testing Against Real Benchmark URLs ===")
from ml.predict_url import predict_url
test_urls = [
    "https://google.com",
    "https://google.com/search?q=test",
    "https://gemini.google.com/app/69dedfd9d5ac5bb1?hl=en-IN",
    "https://github.com/torvalds/linux",
    "http://192.168.1.10/login",
    "http://paypal-verify-account.tk/login"
]
for u in test_urls:
    res = predict_url(u)
    print(f"{u:55s} -> {res['prediction']:8s} ({res['phishing_probability']}%)")
