import streamlit as st
import pandas as pd
import plotly.express as px
import time

st.set_page_config(page_title="Network Attack Dashboard", layout="wide")

st.title("🚨 Network Intrusion Detection Dashboard")

# Add a slider to select refresh interval
refresh_interval = st.sidebar.slider("⏱️ Refresh interval (seconds)", min_value=5, max_value=60, value=10, step=1)

# Read predictions
df = pd.read_csv("live_predictions.csv")

# Show recent predictions
st.subheader("📄 Recent Predictions")
st.dataframe(df.tail(20), height=300, use_container_width=True)

# Count summary
summary = df['Prediction'].value_counts().reset_index()
summary.columns = ['Prediction', 'Count']

# Pie chart
fig_pie = px.pie(
    summary,
    values="Count",
    names="Prediction",
    title="Prediction Distribution",
    color_discrete_sequence=px.colors.sequential.RdBu
)
st.plotly_chart(fig_pie, use_container_width=True, key="pie_chart")

# Bar chart
fig_bar = px.bar(
    summary,
    x="Prediction",
    y="Count",
    title="Prediction Counts",
    color="Prediction",
    text="Count",
    color_discrete_sequence=px.colors.qualitative.Safe
)
fig_bar.update_traces(textposition='outside')
st.plotly_chart(fig_bar, use_container_width=True, key="bar_chart")

# Alerts
if any(df['Prediction'].str.contains("DoS")):
    st.error("⚠️ Potential DoS attack detected! Check network traffic immediately.")
else:
    st.success("✅ No attacks detected in recent captures.")

# Countdown progress bar
progress_text = "⏳ Refreshing in progress..."
my_bar = st.progress(0, text=progress_text)

for i in range(refresh_interval):
    percent_complete = (i + 1) / refresh_interval
    my_bar.progress(percent_complete, text=f"⏳ Refreshing in {refresh_interval - i - 1} seconds...")
    time.sleep(1)

st.rerun()
