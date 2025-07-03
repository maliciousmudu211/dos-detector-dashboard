import joblib
import pandas as pd
from live_feature_extractor import capture_and_extract_features

# === Load model ===
model = joblib.load("cicids_rf_model.joblib")

# === Get model's expected feature names ===
model_columns = model.feature_names_in_

# === Capture and extract live features ===
live_df = capture_and_extract_features(duration=30, max_packets=500)

if live_df.empty:
    print("No live flows captured.")
else:
    # Strip spaces from live_df columns first
    live_df.columns = [c.strip() for c in live_df.columns]

    # Drop Label column if present
    if "Label" in live_df.columns:
        live_df = live_df.drop(columns=["Label"])

    # Rename columns to exactly match model feature names
    # Match columns by ignoring spaces
    col_map = {col.strip(): col for col in model_columns}
    live_df = live_df.rename(columns=lambda x: col_map.get(x, x))

    # Add missing columns
    for col in model_columns:
        if col not in live_df.columns:
            live_df[col] = 0.0

    # Ensure order matches model
    live_df = live_df[model_columns]

    print("Columns BEFORE prediction:", live_df.columns.tolist())

    # Predict
    predictions = model.predict(live_df)
    live_df["Prediction"] = predictions

    # Save
    live_df.to_csv("live_predictions.csv", index=False)
    print("[+] Predictions saved to live_predictions.csv")
    print("[+] Example prediction summary:")
    print(live_df["Prediction"].value_counts())
