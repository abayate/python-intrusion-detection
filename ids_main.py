# ids_main.py

import time
import queue

from packet_capture import PacketCapture
from traffic_analysis import TrafficAnalyzer
from detection_engine import DetectionEngine
from alert_system import AlertSystem
from config import IFACE

# How long to collect "normal" traffic for anomaly model training
BASELINE_DURATION_SEC = 30

# Debug flags
DEBUG_BASELINE_FLOWS = False  # print flows during baseline collection
DEBUG_DETECTION_FLOWS = True  # print flows during real-time detection


def collect_baseline(
    packet_capture: PacketCapture,
    analyzer: TrafficAnalyzer,
    detector: DetectionEngine,
    duration: int = BASELINE_DURATION_SEC,
):
    """
    Collect baseline traffic feature vectors for a fixed time window
    to train the anomaly detector.
    """
    print(f"[IDS] Collecting baseline traffic for {duration} seconds...")
    start = time.time()
    samples = []

    while time.time() - start < duration:
        try:
            pkt = packet_capture.packet_queue.get(timeout=1)
        except queue.Empty:
            continue

        feats = analyzer.analyze_packet(pkt)
        if not feats:
            continue

        if DEBUG_BASELINE_FLOWS:
            # Show that packets are being processed during baseline
            print(
                f"[BASELINE] FLOW {feats['src_ip']}:{feats['src_port']} -> "
                f"{feats['dst_ip']}:{feats['dst_port']} | "
                f"pkts={feats['packet_count']} rate={feats['packet_rate']:.2f}pps "
                f"bytes={feats['byte_count']}"
            )

        vec = detector.features_to_vector(feats)
        samples.append(vec)

    print(f"[IDS] Baseline collection complete. Samples: {len(samples)}")
    detector.train_anomaly_detector(samples)


def main():
    print(f"[IDS] Starting on interface: {IFACE}")
    packet_capture = PacketCapture(IFACE)
    analyzer = TrafficAnalyzer()

    # Slightly looser anomaly threshold so you can see some anomaly alerts
    detector = DetectionEngine(anomaly_threshold=0.05)
    alerter = AlertSystem()

    # Start capture thread
    packet_capture.start()

    # 1) Baseline training phase (optional, but recommended for anomaly detection)
    try:
        collect_baseline(packet_capture, analyzer, detector)
    except KeyboardInterrupt:
        print("\n[IDS] Baseline interrupted. Only signature detection will be used.")

    print("[IDS] Entering real-time detection loop. Press Ctrl+C to stop.")

    # 2) Detection phase
    try:
        while True:
            try:
                pkt = packet_capture.packet_queue.get(timeout=1)
            except queue.Empty:
                continue

            feats = analyzer.analyze_packet(pkt)
            if not feats:
                continue

            if DEBUG_DETECTION_FLOWS:
                # Show that packets are being processed in real time
                print(
                    f"[FLOW] {feats['src_ip']}:{feats['src_port']} -> "
                    f"{feats['dst_ip']}:{feats['dst_port']} | "
                    f"pkts={feats['packet_count']} "
                    f"rate={feats['packet_rate']:.2f}pps "
                    f"bytes={feats['byte_count']}"
                )

            # Run detection engine
            threats = detector.detect_threats(feats)
            if not threats:
                continue

            # Generate alerts for each detected threat
            for t in threats:
                alerter.generate_alert(t, feats)

    except KeyboardInterrupt:
        print("\n[IDS] Stopping...")
        packet_capture.stop()


if __name__ == "__main__":
    main()
