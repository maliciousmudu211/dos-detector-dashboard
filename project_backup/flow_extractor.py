from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib
import time
import numpy as np

# Load model
model = joblib.load("cicids_rf_model.joblib")

# Dict to store packets per flow
flows = {}

# Flow timeout (seconds)
FLOW_TIMEOUT = 60

# Define features list (simplified placeholder)
features_list = [
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Duration",
    # Add the rest of your columns here as needed (69 total)
]

def extract_features(flow_packets, src_ip):
    fwd_lengths = []
    bwd_lengths = []

    start_time = flow_packets[0].time
    end_time = flow_packets[-1].time
    duration = end_time - start_time

import scapy.all as scapy
import numpy as np
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP

def extract_features(flow_packets, src_ip):
    fwd_lengths = [len(pkt) for pkt in flow_packets if pkt.haslayer(IP) and pkt[IP].src == src_ip]
    bwd_lengths = [len(pkt) for pkt in flow_packets if pkt.haslayer(IP) and pkt[IP].src != src_ip]
    pkt_lengths = fwd_lengths + bwd_lengths

    duration = (flow_packets[-1].time - flow_packets[0].time) if len(flow_packets) > 1 else 0

    fwd_times = [pkt.time for pkt in flow_packets if pkt.haslayer(IP) and pkt[IP].src == src_ip]
    bwd_times = [pkt.time for pkt in flow_packets if pkt.haslayer(IP) and pkt[IP].src != src_ip]

    fwd_iat = np.diff(fwd_times) if len(fwd_times) > 1 else []
    bwd_iat = np.diff(bwd_times) if len(bwd_times) > 1 else []
    iat_list = np.diff([pkt.time for pkt in flow_packets]) if len(flow_packets) > 1 else []

    flags = {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 0}
    for pkt in flow_packets:
        if pkt.haslayer(TCP):
            if pkt[TCP].flags & 0x01: flags["FIN"] += 1
            if pkt[TCP].flags & 0x02: flags["SYN"] += 1
            if pkt[TCP].flags & 0x04: flags["RST"] += 1
            if pkt[TCP].flags & 0x08: flags["PSH"] += 1
            if pkt[TCP].flags & 0x10: flags["ACK"] += 1
            if pkt[TCP].flags & 0x20: flags["URG"] += 1
            if pkt[TCP].flags & 0x40: flags["ECE"] += 1

    total_bytes = sum(fwd_lengths) + sum(bwd_lengths)
    total_pkts = len(fwd_lengths) + len(bwd_lengths)

    features = {
        " Destination Port": flow_packets[0][TCP].dport if flow_packets[0].haslayer(TCP) else (flow_packets[0][UDP].dport if flow_packets[0].haslayer(UDP) else 0),
        " Flow Duration": duration,
        " Total Fwd Packets": len(fwd_lengths),
        " Total Backward Packets": len(bwd_lengths),
        "Total Length of Fwd Packets": sum(fwd_lengths),
        " Total Length of Bwd Packets": sum(bwd_lengths),
        " Fwd Packet Length Max": np.max(fwd_lengths) if fwd_lengths else 0,
        " Fwd Packet Length Min": np.min(fwd_lengths) if fwd_lengths else 0,
        " Fwd Packet Length Mean": np.mean(fwd_lengths) if fwd_lengths else 0,
        " Fwd Packet Length Std": np.std(fwd_lengths) if fwd_lengths else 0,
        "Bwd Packet Length Max": np.max(bwd_lengths) if bwd_lengths else 0,
        " Bwd Packet Length Min": np.min(bwd_lengths) if bwd_lengths else 0,
        " Bwd Packet Length Mean": np.mean(bwd_lengths) if bwd_lengths else 0,
        " Bwd Packet Length Std": np.std(bwd_lengths) if bwd_lengths else 0,
        "Flow Bytes/s": total_bytes / duration if duration > 0 else 0,
        " Flow Packets/s": total_pkts / duration if duration > 0 else 0,
        " Flow IAT Mean": np.mean(iat_list) if len(iat_list) > 0 else 0,
        " Flow IAT Std": np.std(iat_list) if len(iat_list) > 0 else 0,
        " Flow IAT Max": np.max(iat_list) if len(iat_list) > 0 else 0,
        " Flow IAT Min": np.min(iat_list) if len(iat_list) > 0 else 0,
        "Fwd IAT Total": fwd_times[-1] - fwd_times[0] if len(fwd_times) > 1 else 0,
        " Fwd IAT Mean": np.mean(fwd_iat) if len(fwd_iat) > 0 else 0,
        " Fwd IAT Std": np.std(fwd_iat) if len(fwd_iat) > 0 else 0,
        " Fwd IAT Max": np.max(fwd_iat) if len(fwd_iat) > 0 else 0,
        " Fwd IAT Min": np.min(fwd_iat) if len(fwd_iat) > 0 else 0,
        "Bwd IAT Total": bwd_times[-1] - bwd_times[0] if len(bwd_times) > 1 else 0,
        " Bwd IAT Mean": np.mean(bwd_iat) if len(bwd_iat) > 0 else 0,
        " Bwd IAT Std": np.std(bwd_iat) if len(bwd_iat) > 0 else 0,
        " Bwd IAT Max": np.max(bwd_iat) if len(bwd_iat) > 0 else 0,
        " Bwd IAT Min": np.min(bwd_iat) if len(bwd_iat) > 0 else 0,
        "Fwd PSH Flags": sum(1 for pkt in flow_packets if pkt.haslayer(TCP) and pkt[IP].src == src_ip and pkt[TCP].flags & 0x08),
        " Fwd Header Length": sum(pkt[IP].ihl for pkt in flow_packets if pkt.haslayer(IP) and pkt[IP].src == src_ip),
        " Bwd Header Length": sum(pkt[IP].ihl for pkt in flow_packets if pkt.haslayer(IP) and pkt[IP].src != src_ip),
        "Fwd Packets/s": len(fwd_lengths) / duration if duration > 0 else 0,
        " Bwd Packets/s": len(bwd_lengths) / duration if duration > 0 else 0,
        " Min Packet Length": np.min(pkt_lengths) if pkt_lengths else 0,
        " Max Packet Length": np.max(pkt_lengths) if pkt_lengths else 0,
        " Packet Length Mean": np.mean(pkt_lengths) if pkt_lengths else 0,
        " Packet Length Std": np.std(pkt_lengths) if pkt_lengths else 0,
        " Packet Length Variance": np.var(pkt_lengths) if pkt_lengths else 0,
        "FIN Flag Count": flags["FIN"],
        " SYN Flag Count": flags["SYN"],
        " RST Flag Count": flags["RST"],
        " PSH Flag Count": flags["PSH"],
        " ACK Flag Count": flags["ACK"],
        " URG Flag Count": flags["URG"],
        " ECE Flag Count": flags["ECE"],
        " Down/Up Ratio": len(bwd_lengths) / len(fwd_lengths) if len(fwd_lengths) > 0 else 0,
        " Average Packet Size": total_bytes / total_pkts if total_pkts > 0 else 0,
        " Avg Fwd Segment Size": np.mean(fwd_lengths) if fwd_lengths else 0,
        " Avg Bwd Segment Size": np.mean(bwd_lengths) if bwd_lengths else 0,
        " Fwd Header Length.1": sum(pkt[IP].ihl for pkt in flow_packets if pkt.haslayer(IP) and pkt[IP].src == src_ip),
        "Subflow Fwd Packets": len(fwd_lengths),
        " Subflow Fwd Bytes": sum(fwd_lengths),
        " Subflow Bwd Packets": len(bwd_lengths),
        " Subflow Bwd Bytes": sum(bwd_lengths),
        "Init_Win_bytes_forward": flow_packets[0][TCP].window if flow_packets[0].haslayer(TCP) and pkt[IP].src == src_ip else 0,
        " Init_Win_bytes_backward": flow_packets[0][TCP].window if flow_packets[0].haslayer(TCP) and pkt[IP].src != src_ip else 0,
        " act_data_pkt_fwd": sum(1 for pkt in flow_packets if pkt.haslayer(TCP) and pkt[IP].src == src_ip and len(pkt[TCP].payload) > 0),
        " min_seg_size_forward": min(fwd_lengths) if fwd_lengths else 0,
        "Active Mean": np.mean(iat_list) if len(iat_list) > 0 else 0,
        " Active Std": np.std(iat_list) if len(iat_list) > 0 else 0,
        " Active Max": np.max(iat_list) if len(iat_list) > 0 else 0,
        " Active Min": np.min(iat_list) if len(iat_list) > 0 else 0,
        "Idle Mean": 0, " Idle Std": 0, " Idle Max": 0, " Idle Min": 0
    }

    return features

# Example usage
if __name__ == "__main__":
    pkts = scapy.rdpcap("example.pcap")
    # You should split pkts into flows, then for each flow:
    features = extract_features(pkts, "192.168.1.2")
    df = pd.DataFrame([features])
    df.to_csv("flow_features.csv", index=False)
    print("Features extracted and saved to flow_features.csv")
