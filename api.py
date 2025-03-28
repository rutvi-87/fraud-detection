from flask import Flask, request, jsonify
import joblib
import numpy as np

app = Flask(__name__)

# Load trained model
model = joblib.load("fraud_detector.pkl")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    features = np.array(data["features"]).reshape(1, -1)
    prediction = model.predict(features)[0]  # 1 = Fraud, 0 = Safe
    probability = model.predict_proba(features)[0][1] * 100  # Probability of fraud
    return jsonify({"fraud_risk": int(prediction), "risk_score": probability})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
