import pandas as pd
import numpy as np

# Path to your CSV
csv_file = "MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv"

# Load
df = pd.read_csv(csv_file)

print("Original shape:", df.shape)

# Drop columns with all NaNs or constant values
df = df.dropna(axis=1, how='all')
df = df.loc[:, df.nunique() > 1]
print("Shape after dropping NaNs and constants:", df.shape)

# Identify non-numeric columns
non_numeric = df.select_dtypes(exclude=["number"]).columns

# Check if " Label" (with space) is present
label_col = " Label"
if label_col in non_numeric:
    non_numeric_to_drop = [col for col in non_numeric if col != label_col]
    df = df.drop(non_numeric_to_drop, axis=1)
    print("Shape after dropping other non-numeric columns (but keeping Label):", df.shape)
    
    # Standardize label values (optional)
    df[label_col] = df[label_col].replace("BENIGN", "Benign")
else:
    print("No 'Label' column found. Skipping label-related steps.")

# Save
df.to_csv("cicids_preprocessed.csv", index=False)
print("Preprocessed data saved to: cicids_preprocessed.csv")
