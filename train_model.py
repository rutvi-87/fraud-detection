import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# ✅ Step 1: Load the dataset
data = pd.read_csv("fraud_domains.csv")  # Make sure the dataset is in the same directory

# ✅ Step 2: Separate features and labels
X = data.drop(columns=["domain"])  # Drop domain name (not a feature)
y = data["is_fraudulent"]  # Labels (1 = fraud, 0 = safe)

# ✅ Step 3: Split into training & test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ✅ Step 4: Train the model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ✅ Step 5: Evaluate model performance
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\nModel Performance Metrics:")
print(f"Accuracy: {accuracy:.2%}")
print(f"Precision: {precision:.2%}")
print(f"Recall: {recall:.2%}")
print(f"F1 Score: {f1:.2%}")

# Save metrics to a file for frontend use
with open("model_metrics.json", "w") as f:
    import json
    json.dump({
        "accuracy": round(accuracy * 100, 2),
        "precision": round(precision * 100, 2),
        "recall": round(recall * 100, 2),
        "f1": round(f1 * 100, 2)
    }, f)

# ✅ Step 6: Save the trained model
joblib.dump(model, "fraud_detector.pkl")
print("\n🎉 AI Model Trained & Saved as fraud_detector.pkl!")
