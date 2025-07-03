import scapy.all as scapy
import pandas as pd
import numpy as np
import joblib
from collections import defaultdict
import time

# =============== CONFIG ===============
CAPTURE_TIME = 30  # seconds
PACKET_LIMIT = 500  # optional limit

# Path to model and columns file
MODEL_PATH = "cicids_rf_model.joblib"
COLUMNS_CSV = "cicids_preprocessed.csv"
# ======================================

# Load trained model
model = joblib.load(MODEL_PATH)

# Load columns from preprocessed CSV to match exactly
df_columns = pd.read_csv(COLUMNS_CSV, nrows=1).drop(columns=["Label"])
model_columns = df_columns.columns.tolist()

# Flow collector
flows = defaultdict(list)

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        ip_layer = packet[scapy.IP]
        proto = "TCP" if packet.haslayer(scapy.TCP) else "UDP" if packet.haslayer(scapy.UDP) else "OTHER"
        if proto == "OTHER":
            return
        sport = packet.sport if hasattr(packet, "sport") else 0
        dport = packet.dport if hasattr(packet, "dport") else 0
        flow_key = (ip_layer.src, ip_layer.dst, sport, dport, proto)
        flows[flow_key].append(len(packet))  # Save packet size

print("[*] Starting live capture for {} seconds or {} packets...".format(CAPTURE_TIME, PACKET_LIMIT))
start_time = time.time()

scapy.sniff(prn=packet_callback, timeout=CAPTURE_TIME, count=PACKET_LIMIT)

print("[*] Capture finished. Processing flows...")

feature_rows = []

for key, pkt_sizes in flows.items():
    src_ip, dst_ip, sport, dport, proto = key
    total_pkts = len(pkt_sizes)
    total_bytes = sum(pkt_sizes)
    pkt_len_mean = np.mean(pkt_sizes)
    pkt_len_std = np.std(pkt_sizes)
    pkt_len_min = np.min(pkt_sizes)
    pkt_len_max = np.max(pkt_sizes)
    
    # Simple example features
    features = {
        ' Destination Port': dport,
        ' Flow Duration': total_pkts * 1000,  # dummy, approximate
        ' Total Fwd Packets': total_pkts,
        ' Total Backward Packets': 0,  # dummy
        'Total Length of Fwd Packets': total_bytes,
        ' Total Length of Bwd Packets': 0,  # dummy
        ' Fwd Packet Length Max': pkt_len_max,
        ' Fwd Packet Length Min': pkt_len_min,
        ' Fwd Packet Length Mean': pkt_len_mean,
        ' Fwd Packet Length Std': pkt_len_std,
        # You can add or estimate more if needed
    }
    
    feature_rows.append(features)

df = pd.DataFrame(feature_rows)

# Fill missing columns with zeros
for col in model_columns:
    if col not in df.columns:
        df[col] = 0

# Reorder columns to match model
df = df[model_columns]

# Predict
predictions = model.predict(df)

df["Prediction"] = predictions

print("[+] Prediction results:")
print(df[[" Destination Port", "Prediction"]].head())

# Save
df.to_csv("live_flows_with_predictions.csv", index=False)
print("[+] Results saved to live_flows_with_predictions.csv")
