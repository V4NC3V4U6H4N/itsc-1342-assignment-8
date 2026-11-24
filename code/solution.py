# Vance Vaughan - Assignment 8

import json
import os

def analyze_capture_records(records):
    report = {
        "protocols": {},
        "unique_destinations": []
    }
    unique_dsts = set()
    
    for pkt in records:
        if not isinstance(pkt, dict):
            continue

        # Extract from nested JSON
        if "_source" in pkt and "layers" in pkt["_source"]:
            layers = pkt["_source"]["layers"]
            ws_col = layers.get("_ws.col", {})
            ip_layer = layers.get("ip", {})

            proto = ws_col.get("_ws.col.protocol", "UNKNOWN").upper()
            dst = ip_layer.get("ip.dst")
        else:
            # Catchall
            proto = pkt.get("proto", "UNKNOWN").upper()
            dst = pkt.get("dst")

        report["protocols"][proto] = report["protocols"].get(proto, 0) + 1

        if dst:
            unique_dsts.add(dst)

    # Sort IPs
    report["unique_destinations"] = sorted(unique_dsts)
    return report

# Execution on your live Wireshark capture
if __name__ == "__main__":
    capture_path = os.path.join(os.path.dirname(__file__), "capture.json")
    with open(capture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    summary = analyze_capture_records(data)
    print("LIVE CAPTURE SUMMARY:")
    print(summary)