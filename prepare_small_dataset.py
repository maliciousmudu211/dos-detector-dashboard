import pandas as pd

df = pd.read_csv("cicids_preprocessed.csv")

# Strip columns
df.columns = [c.strip() for c in df.columns]

# Keep only these columns and label
selected = ["Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets", "Label"]
df_small = df[selected]

df_small.to_csv("cicids_small.csv", index=False)
print("Saved new simplified dataset as cicids_small.csv")

