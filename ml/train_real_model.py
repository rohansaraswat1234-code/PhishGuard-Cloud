import pickle
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from ml.url_features import extract_features


print("Loading real dataset...")

df = pd.read_csv("dataset/phiusiil_real.csv")

# UCI:
# 1 = legitimate
# 0 = phishing
#
# PhishGuard model:
# 0 = SAFE
# 1 = PHISHING

safe = df[df["label"] == 1].sample(
    n=50000,
    random_state=42
)

phishing = df[df["label"] == 0].sample(
    n=50000,
    random_state=42
)

data = pd.concat([safe, phishing])
data = data.sample(frac=1, random_state=42).reset_index(drop=True)

print("Training URLs:", len(data))
print("Extracting URL features...")


feature_names = [
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


feature_rows = []

for url in data["URL"].astype(str):
    features = extract_features(url)
    feature_rows.append(
        [features[name] for name in feature_names]
    )

X = pd.DataFrame(
    feature_rows,
    columns=feature_names
)

# Invert UCI labels
y = 1 - data["label"].astype(int)


X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


models = {
    "Decision Tree": DecisionTreeClassifier(
        max_depth=10,
        min_samples_leaf=5,
        random_state=42
    ),

    "Logistic Regression": make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=1000)
    )
}


best_model = None
best_name = None
best_f1 = -1


for name, model in models.items():

    print("\n==============================")
    print(name)
    print("==============================")

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)
    f1 = f1_score(y_test, predictions)

    print("Accuracy :", round(accuracy * 100, 2), "%")
    print("Precision:", round(precision * 100, 2), "%")
    print("Recall   :", round(recall * 100, 2), "%")
    print("F1 Score :", round(f1 * 100, 2), "%")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    if f1 > best_f1:
        best_f1 = f1
        best_model = model
        best_name = name


print("\n==============================")
print("BEST MODEL:", best_name)
print("==============================")

with open("ml/models/phishing_model_real.pkl", "wb") as file:
    pickle.dump(best_model, file)

print("Real model saved:")
print("ml/models/phishing_model_real.pkl")
