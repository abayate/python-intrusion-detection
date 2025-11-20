# test_ids.py
#
# Offline tests for your IDS logic:
# - Simulate a SYN flood
# - Simulate a TCP port scan
#
# No packet capture, no admin, no Npcap needed.
# Just synthetic Scapy packets fed into TrafficAnalyzer + DetectionEngine.

import time
from scapy.layers.inet import IP, TCP

from traffic_analysis import TrafficAnalyzer
from detection_engine import DetectionEngine


def inject_packet(pkt, analyzer, detector, label: str):
    """
    Helper: send one packet through analyzer + detector and print any threats.
    """
    feats = analyzer.analyze_packet(pkt)
    if not feats:
        return

    threats = detector.detect_threats(feats)
    for t in threats:
        print(
            f"[DETECTED] {label} | method={t['method']} name={t['name']} "
            f"severity={t['severity']} "
            f"src={feats['src_ip']}:{feats['src_port']} "
            f"dst={feats['dst_ip']}:{feats['dst_port']}"
        )


def test_syn_flood():
    """
    Simulate a SYN flood from 10.0.0.10:12345 to 10.0.0.20:80.
    We send a lot of SYN packets quickly so the syn_flood rule should fire.
    """
    print("\n[TEST] SYN flood simulation")
    analyzer = TrafficAnalyzer()
    detector = DetectionEngine()

    src_ip = "10.0.0.10"
    dst_ip = "10.0.0.20"
    sport = 12345
    dport = 80

    for i in range(150):  # >100 packets, enough to trigger our rule
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S")
        inject_packet(pkt, analyzer, detector, label="syn_flood")

    print("[TEST] SYN flood simulation complete\n")


def test_port_scan():
    """
    Simulate a TCP SYN port scan from 10.0.0.30 to 10.0.0.40,
    hitting many different destination ports with single SYN probes.

    We temporarily lower detector.port_scan_min_ports so it's easier to trigger.
    """
    print("\n[TEST] Port scan simulation")
    analyzer = TrafficAnalyzer()
    detector = DetectionEngine()

    # Make port-scan rule easier to trigger for the test
    detector.port_scan_min_ports = 5

    src_ip = "10.0.0.30"
    dst_ip = "10.0.0.40"
    sport = 40000

    # Hit a bunch of different destination ports with SYNs
    for dport in range(20, 35):  # 15 ports
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S")
        inject_packet(pkt, analyzer, detector, label="port_scan")
        time.sleep(0.01)  # small delay to give timestamps some spread

    print("[TEST] Port scan simulation complete\n")


if __name__ == "__main__":
    # You can comment out either one if you only want to test a specific rule
    test_syn_flood()
    test_port_scan()
