import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP

from collections import defaultdict
import time

# 🟢 You can change this to capture longer
CAPTURE_DURATION = 30  # seconds

# 🟢 Or change this to capture fixed number of packets
NUM_PACKETS = 500

# 🟢 How many packets before we save
SAVE_EVERY_N_PACKETS = 50

# Store flow stats
flows = defaultdict(list)

def process_packet(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
        src = ip_layer.src
        dst = ip_layer.dst
        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        
        # 5-tuple key
        flow_key = (src, dst, sport, dport, proto)
        flows[flow_key].append(pkt)

def extract_features(flows):
    data = []
    for key, pkts in flows.items():
        src, dst, sport, dport, proto = key
        
        pkt_lengths = [len(p) for p in pkts]
        duration = pkts[-1].time - pkts[0].time if len(pkts) > 1 else 0
        pkt_count = len(pkts)
        byte_count = sum(pkt_lengths)
        
        fwd_pkt_lengths = [len(p) for p in pkts if IP in p and p[IP].src == src]
        bwd_pkt_lengths = [len(p) for p in pkts if IP in p and p[IP].src == dst]
        
        fwd_pkt_count = len(fwd_pkt_lengths)
        bwd_pkt_count = len(bwd_pkt_lengths)

        avg_pkt_size = np.mean(pkt_lengths) if pkt_lengths else 0
        min_pkt_size = np.min(pkt_lengths) if pkt_lengths else 0
        max_pkt_size = np.max(pkt_lengths) if pkt_lengths else 0
        pkt_size_std = np.std(pkt_lengths) if pkt_lengths else 0

        # Basic example features (extend as needed)
        row = {
            "Src IP": src,
            "Dst IP": dst,
            "Src Port": sport,
            "Dst Port": dport,
            "Protocol": proto,
            "Duration": duration,
            "Total Pkts": pkt_count,
            "Total Bytes": byte_count,
            "Fwd Pkts": fwd_pkt_count,
            "Bwd Pkts": bwd_pkt_count,
            "Avg Pkt Size": avg_pkt_size,
            "Min Pkt Size": min_pkt_size,
            "Max Pkt Size": max_pkt_size,
            "Pkt Size Std": pkt_size_std,
        }
        data.append(row)
    return data

def main():
    print(f"[*] Starting live capture for {CAPTURE_DURATION} seconds or {NUM_PACKETS} packets...")

    start_time = time.time()
    sniff(prn=process_packet, timeout=CAPTURE_DURATION, count=NUM_PACKETS)

    print("[*] Capture finished. Processing flows...")

    data = extract_features(flows)
    df = pd.DataFrame(data)

    # Save
    df.to_csv("live_flows_features.csv", index=False)
    print("[+] Features saved to live_flows_features.csv")
    print("[+] Example preview:")
    print(df.head())

if __name__ == "__main__":
    main()


def capture_and_extract_features(duration=30, max_packets=500):
    import pyshark
    import pandas as pd

    print(f"[*] Starting live capture for {duration} seconds or {max_packets} packets...")

    # Capture
    cap = pyshark.LiveCapture(interface="wlo1")  # Change 'eth0' if needed
    cap.sniff(timeout=duration, packet_count=max_packets)

    print("[*] Capture finished. Processing flows...")

    # Example simplified feature extraction (just as placeholder)
    flows = []
    for pkt in cap.sniff_continuously(packet_count=max_packets):
        try:
            length = int(pkt.length)
        except:
            length = 0

        flow_features = {
            "Total Fwd Packets": 1,
            "Total Backward Packets": 1,
            "Total Length of Fwd Packets": length,
            # ... (Add other fields you want to fill here — 69 total)
        }
        flows.append(flow_features)

    df = pd.DataFrame(flows)

    if not df.empty:
        df.to_csv("live_flows_features.csv", index=False)
        print("[+] Features saved to live_flows_features.csv")
    else:
        print("[!] No flows found.")

    return df

