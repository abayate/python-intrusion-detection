# Python Host-Based Intrusion Detection System (IDS)

This project is a **host-based Intrusion Detection System** built in Python and tested on **Windows 11**.  
It captures live network traffic from a local interface, extracts flow-level features, and applies both:

- **Signature-based detection** (SYN floods, port scanning)
- **Anomaly-based detection** using `IsolationForest` from scikit-learn

Alerts are written to a log file and printed to the console in a SOC-style format.

---

## Features

- 🕵️‍♂️ **Real-time packet capture** with Scapy + Npcap on Windows  
- 📈 **Flow-based analysis** (per `(src_ip, dst_ip, src_port, dst_port)`):
  - Packet count, byte count, duration
  - Packet rate, byte rate
  - TCP flags (SYN/ACK/RST), window size
- 🧩 **Signature detections**:
  - SYN flood heuristic (high rate, many SYNs, no ACKs)
  - Stateful TCP port scan heuristic (same source → many ports on a target)
- 🤖 **Anomaly detection**:
  - IsolationForest trained on a baseline window of “normal” traffic
- 🚨 **Alerting**:
  - Logs alerts to `ids_alerts.log`
  - Prints concise `[ALERT] ...` lines to console
- 🧪 **Offline test harness** (`test_ids.py`):
  - Simulates SYN floods and port scans with synthetic Scapy packets
  - Validates detection logic without needing a second machine

---

## Architecture

```text
[ Scapy Sniffer ]
        |
        v
[ PacketCapture ] --(queue.Queue)--> [ TrafficAnalyzer ] --> [ DetectionEngine ] --> [ AlertSystem ]
                                                           |                       |
                                                (features per flow)             (alerts to log/console)
