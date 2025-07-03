import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import numpy as np

# Load preprocessed data
df = pd.read_csv("cicids_preprocessed.csv")

# Correct label column name
label_col = " Label"

# Separate features and label
X = df.drop(label_col, axis=1)
y = df[label_col]

# Replace inf/-inf with NaN
X = X.replace([np.inf, -np.inf], np.nan)

# Drop rows with NaN (you could also fill them if you prefer)
X = X.dropna()
y = y.loc[X.index]

# Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# Save
joblib.dump(clf, "cicids_rf_model.joblib")
print("Model saved to cicids_rf_model.joblib")
