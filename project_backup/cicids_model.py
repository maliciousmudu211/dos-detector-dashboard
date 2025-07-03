import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# === CONFIG: Replace with your actual filename ===
file_path ="Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"  # Example

# Load data
print("[*] Loading data...")
df = pd.read_csv(file_path, low_memory=False)

# Drop non-numeric or unnecessary columns
cols_to_drop = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Source Port', 'Destination Port', 'Protocol']
df = df.drop(cols_to_drop, axis=1, errors='ignore')

# Replace infinite values and drop NaNs
df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()

# Convert labels: Attack = 1, Benign = 0
print("[*] Encoding labels...")
df['Label'] = df['Label'].apply(lambda x: 'BENIGN' if x == 'BENIGN' else 'ATTACK')
le = LabelEncoder()
df['Label'] = le.fit_transform(df['Label'])

# Separate features and target
X = df.drop(['Label'], axis=1)
y = df['Label']

# Split
print("[*] Splitting data...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train
print("[*] Training model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
print("[*] Evaluating...")
y_pred = model.predict(X_test)
print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred))

print("[+] Done!")
