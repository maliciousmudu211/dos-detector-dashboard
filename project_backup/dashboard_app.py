from flask import Flask, render_template, jsonify
import pandas as pd

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def data():
    try:
        df = pd.read_csv("live_predictions.csv")
        # In case there's whitespace in column name
        if "Prediction" not in df.columns:
            df.columns = [col.strip() for col in df.columns]
        counts = df["Prediction"].value_counts().to_dict()
        rows = df.to_dict(orient="records")
        return jsonify({"summary": counts, "rows": rows})
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
