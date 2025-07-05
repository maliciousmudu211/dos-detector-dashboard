import pandas as pd
import joblib
from live_feature_extractor import capture_and_extract_features

# === Load trained model and label encoder ===
clf = joblib.load("cicids_rf_model.joblib")
le = joblib.load("label_encoder.joblib")

# === Capture live features ===
print("[*] Starting live capture for 30 seconds or 500 packets...")
live_df = capture_and_extract_features(duration=30, max_packets=500)

# Save extracted features
live_df.to_csv("live_flows_features.csv", index=False)
print("[+] Features saved to live_flows_features.csv")

# Keep only columns used for training
expected_features = ["Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets"]
live_df_features = live_df[expected_features]

# Predict
predictions = clf.predict(live_df_features)

# Decode numeric predictions to labels
decoded_predictions = le.inverse_transform(predictions)

# Save predictions
live_df["Prediction"] = decoded_predictions
live_df.to_csv("live_predictions.csv", index=False)
print("[+] Predictions saved to live_predictions.csv")

# Print summary
summary = live_df["Prediction"].value_counts()
print("[+] Example prediction summary:")
print(summary)

