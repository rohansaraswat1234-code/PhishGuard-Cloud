import pandas as pd
import pickle
from pathlib import Path

from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report


data = pd.read_csv("dataset/phishing_training.csv")

X = data.drop("label", axis=1)
y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

model = DecisionTreeClassifier(max_depth=5, random_state=42)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("Model trained successfully")
print("Accuracy:", accuracy)

print("\nClassification Report:")
print(classification_report(y_test, predictions, zero_division=0))

Path("ml/models").mkdir(parents=True, exist_ok=True)

with open("ml/models/phishing_model.pkl", "wb") as file:
    pickle.dump(model, file)

print("\nModel saved at: ml/models/phishing_model.pkl")
