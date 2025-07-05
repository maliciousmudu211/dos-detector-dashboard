import pyshark
import pandas as pd
import time

def capture_and_extract_features(interface="wlp2s0", duration=30, max_packets=500):
    print(f"[*] Starting live capture for {duration} seconds or {max_packets} packets...")

    # Capture packets
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(timeout=duration)

    # Limit packets
    packets = list(capture.sniff_continuously(packet_count=max_packets))

    # Prepare features
    feature_list = []

    for pkt in packets:
        try:
            total_fwd_packets = 1  # Each packet counts as one fwd packet (simplified)
            total_backward_packets = 0  # We do not analyze direction in this simplified version
            total_length_fwd_packets = int(pkt.length)

            feature_list.append({
                "Total Fwd Packets": total_fwd_packets,
                "Total Backward Packets": total_backward_packets,
                "Total Length of Fwd Packets": total_length_fwd_packets
            })
        except AttributeError:
            # Ignore packets without certain fields
            continue

    # Convert to DataFrame
    df = pd.DataFrame(feature_list)

    if not df.empty:
        df.to_csv("live_flows_features.csv", index=False)
        print("[+] Features saved to live_flows_features.csv")
    else:
        print("[-] No valid packets captured.")

    return df

if __name__ == "__main__":
    df = capture_and_extract_features()
    print(df.head())
