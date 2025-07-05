import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib

# Load simplified dataset
df = pd.read_csv("cicids_small.csv")
df.columns = [c.strip() for c in df.columns]

X = df.drop(columns=["Label"])
y = df["Label"]

le = LabelEncoder()
y_encoded = le.fit_transform(y)
joblib.dump(le, "label_encoder.joblib")

X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

joblib.dump(clf, "cicids_rf_model.joblib")
print("[+] Model saved as cicids_rf_model.joblib")
