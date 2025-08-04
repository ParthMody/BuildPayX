import pandas as pd
import numpy as np
import pickle
import os

# Load the trained model
MODEL_PATH = os.path.join(os.path.dirname(__file__), "risk_model.pkl")
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# Expected columns the model was trained on
EXPECTED_FEATURES = [
    "po_amount", "po_days", "supplier_score", "retention_rate",
    "compliance_score", "early_payment_flag", "subcontractor_history"
]

def preprocess_input(input_data):
    """
    Preprocess input dictionary or DataFrame row to match the model's expected features.
    """
    if isinstance(input_data, dict):
        df = pd.DataFrame([input_data])
    elif isinstance(input_data, pd.Series):
        df = pd.DataFrame([input_data.to_dict()])
    elif isinstance(input_data, pd.DataFrame):
        df = input_data.copy()
    else:
        raise ValueError("Unsupported input format for prediction.")

    # Ensure correct feature order
    df = df[EXPECTED_FEATURES]

    # Optional: scale/encode if model requires it (you can add transformers here)
    return df

def predict_scenario(po_data):
    """
    Takes a dict or DataFrame row of PO data and returns risk prediction and probability.
    """
    try:
        features = preprocess_input(po_data)
        prediction = model.predict(features)[0]

        # If it's a classifier with probability
        if hasattr(model, "predict_proba"):
            probability = model.predict_proba(features)[0][1]  # Probability of 'risky' class
        else:
            probability = None

        return {
            "prediction": int(prediction),
            "probability": float(probability) if probability is not None else None
        }

    except Exception as e:
        return {
            "error": str(e)
        }
