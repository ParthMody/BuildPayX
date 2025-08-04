import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import os

# ----- Step 1: Generate Dummy Data -----
np.random.seed(42)
num_samples = 300

data = {
    "po_amount": np.random.normal(loc=100000, scale=20000, size=num_samples),
    "po_days": np.random.randint(15, 90, size=num_samples),
    "supplier_score": np.random.uniform(0.5, 1.0, size=num_samples),
    "retention_rate": np.random.uniform(0.0, 0.2, size=num_samples),
    "compliance_score": np.random.uniform(0.5, 1.0, size=num_samples),
    "early_payment_flag": np.random.randint(0, 2, size=num_samples),
    "subcontractor_history": np.random.randint(0, 10, size=num_samples)
}

df = pd.DataFrame(data)

# ----- Step 2: Define Fake Risk Labels -----
# Simple rule: high po_amount + low compliance = risky
conditions = [
    (df["compliance_score"] > 0.85) & (df["po_amount"] < 120000),
    (df["compliance_score"] <= 0.85) & (df["po_amount"] < 140000),
    (df["compliance_score"] <= 0.7) | (df["po_amount"] >= 140000)
]
choices = [0, 1, 2]  # Green, Yellow, Red
df["risk_label"] = np.select(conditions, choices, default=1)

# ----- Step 3: Train-Test Split -----
X = df.drop("risk_label", axis=1)
y = df["risk_label"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ----- Step 4: Train the Model -----
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ----- Step 5: Evaluate the Model -----
y_pred = model.predict(X_test)

class_names = {0: "Green", 1: "Yellow", 2: "Red"}
labels = sorted(np.unique(y_test))
target_names = [class_names[l] for l in labels]

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred, labels=labels))
print("\nClassification Report:")
print(classification_report(y_test, y_pred, labels=labels, target_names=target_names))

# ----- Step 6: Save the Model -----
model_path = os.path.join(os.path.dirname(__file__), "risk_model.pkl")
with open(model_path, "wb") as f:
    pickle.dump(model, f)

print(f"\n✅ Dummy model saved to: {model_path}")
