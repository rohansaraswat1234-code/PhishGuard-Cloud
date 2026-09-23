from ucimlrepo import fetch_ucirepo
import pandas as pd
from pathlib import Path

print("Downloading real phishing dataset from UCI...")

dataset = fetch_ucirepo(id=967)

X = dataset.data.features
y = dataset.data.targets

print("Dataset downloaded successfully")
print("Features shape:", X.shape)
print("Target shape:", y.shape)

print("\nAvailable columns:")
print(X.columns.tolist())

print("\nTarget columns:")
print(y.columns.tolist())

Path("dataset").mkdir(exist_ok=True)

combined = pd.concat([X, y], axis=1)

combined.to_csv(
    "dataset/phiusiil_real.csv",
    index=False
)

print("\nSaved as: dataset/phiusiil_real.csv")
print("Total rows:", len(combined))
