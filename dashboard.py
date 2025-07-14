import streamlit as st
import pandas as pd
import plotly.express as px
import os
import time

st.set_page_config(page_title="🚨 DoS Attack Detection Dashboard", page_icon="⚡", layout="wide")

st.title("⚡ DoS Attack Detection Dashboard")
st.markdown(
    """
    Monitor your network predictions in real time.
    - **Green**: Benign traffic ✅
    - **Red**: Potential DoS attack 🚨
    """
)

# Sidebar refresh settings
st.sidebar.header("⚙️ Settings")
refresh_interval = st.sidebar.slider("⏰ Auto-refresh interval (seconds)", min_value=5, max_value=60, value=10)

# Countdown progress bar
progress_bar = st.sidebar.progress(0, text="Waiting for refresh...")

if not os.path.exists("live_predictions.csv"):
    st.warning("⚠️ No predictions found yet. Please run `live_predictor_combined.py` to generate predictions.")
    st.stop()

# Load prediction data
df = pd.read_csv("live_predictions.csv")

# Summarize predictions
summary = df["Prediction"].value_counts().reset_index()
summary.columns = ["Prediction", "Count"]

# Bar chart
fig_bar = px.bar(
    summary,
    x="Prediction",
    y="Count",
    color="Prediction",
    color_discrete_sequence=px.colors.qualitative.Safe,
    title="Prediction Counts",
    text_auto=True,
    height=500,
)
st.plotly_chart(fig_bar, use_container_width=True, key="bar_chart")

# Pie chart
fig_pie = px.pie(
    summary,
    names="Prediction",
    values="Count",
    color_discrete_sequence=px.colors.qualitative.Pastel,
    title="Prediction Distribution"
)
st.plotly_chart(fig_pie, use_container_width=True, key="pie_chart")

# Detailed table
st.subheader("🔎 Detailed Predictions")
st.dataframe(df, use_container_width=True)

st.markdown("---")
st.markdown("✨ Built with ❤️ using Streamlit & Plotly")

# Countdown loop with progress bar update
for i in range(refresh_interval):
    progress = (i + 1) / refresh_interval
    progress_bar.progress(progress, text=f"♻️ Refreshing in {refresh_interval - i}s...")
    time.sleep(1)

# Auto rerun
st.rerun()
