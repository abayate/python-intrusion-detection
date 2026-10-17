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
```

---

## Quick start

### 1. Offline test (no admin rights, no Npcap)

```bash
pip install -r requirements.txt
python test_ids.py
```

Actual output:

```text
[TEST] SYN flood simulation
[DETECTED] syn_flood | method=signature name=syn_flood severity=HIGH src=10.0.0.10:12345 dst=10.0.0.20:80
[TEST] SYN flood simulation complete

[TEST] Port scan simulation
[DETECTED] port_scan | method=signature name=possible_port_scan severity=MEDIUM src=10.0.0.30:40000 dst=10.0.0.40:24
[DETECTED] port_scan | method=signature name=possible_port_scan severity=MEDIUM src=10.0.0.30:40000 dst=10.0.0.40:25
...
[TEST] Port scan simulation complete
```

### 2. Live capture (Windows 11)

1. Install [Npcap](https://npcap.com/) (check *WinPcap API-compatible mode*).
2. Find your interface: `python list_ifaces_pretty.py`
3. Paste its `\Device\NPF_{...}` name into `config.py` as `IFACE`.
4. From an **Administrator** terminal: `python ids_main.py`
5. The IDS first records a baseline of normal traffic to train the IsolationForest, then starts alerting.
   Alerts go to the console and to `ids_alerts.log`.

---

## Detections and MITRE ATT&CK mapping

| Detection | Method | Severity | MITRE ATT&CK |
|---|---|---|---|
| SYN flood (high SYN rate, no ACKs) | Signature | HIGH | [T1498](https://attack.mitre.org/techniques/T1498/) Network Denial of Service |
| TCP port scan (one source → many ports) | Stateful signature | MEDIUM | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery |
| Unusual flow statistics | IsolationForest anomaly | varies | Catches unknown behavior that has no signature |

## Project files

| File | Role |
|---|---|
| `ids_main.py` | Entry point: baseline collection, then the live detection loop |
| `packet_capture.py` | Scapy sniffer on a background thread that feeds a queue |
| `traffic_analysis.py` | Builds per-flow features (rates, flags, window size) |
| `detection_engine.py` | Signature rules + IsolationForest anomaly model |
| `alert_system.py` | SOC-style alert formatting and log file |
| `test_ids.py` | Synthetic attack traffic for offline testing |
| `list_ifaces*.py`, `sniff_test.py` | Helpers to find and test a capture interface |

## Limitations and next steps

- Rules are tuned for a single host. Thresholds may need tuning on busy networks.
- Ideas: export alerts as JSON for a SIEM (Splunk / Sentinel), add DNS-tunneling and ARP-spoofing rules, replay PCAPs with `rdpcap`.

## Skills demonstrated

Python · Scapy · packet and flow analysis · TCP/IP · scikit-learn (IsolationForest) · detection engineering · multithreading
