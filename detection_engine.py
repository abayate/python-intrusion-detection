# detection_engine.py

from __future__ import annotations

import time
from typing import List, Dict, Any
from sklearn.ensemble import IsolationForest


class DetectionEngine:
    """
    Combines simple signature-based rules with an optional
    anomaly-based detector (Isolation Forest).
    """

    def __init__(
        self,
        contamination: float = 0.02,
        anomaly_threshold: float = -0.2,
    ):
        # Signature rule callbacks
        self.signature_rules = self._build_signature_rules()

        # Stateful tracking for port-scan detection:
        # key: (src_ip, dst_ip) -> {"ports": set(), "first_seen": timestamp}
        self.port_scan_state: Dict[tuple, Dict[str, Any]] = {}
        self.port_scan_window = 60.0  # seconds
        self.port_scan_min_ports = 15  # distinct ports before we scream "scan"

        # Anomaly detection model
        self.iforest: IsolationForest | None = None
        self.contamination = contamination
        self.anomaly_threshold = anomaly_threshold

    # ---------- SIGNATURE-BASED DETECTION ----------

    def _build_signature_rules(self):
        """
        Returns a dict of rule_name -> function(features) -> bool.
        Each rule gets the feature dict from TrafficAnalyzer.
        """

        def syn_flood_rule(f: Dict[str, Any]) -> bool:
            """
            Heuristic for SYN flood:
            - Many SYN packets
            - No ACKs yet on this flow
            - Very high packet rate
            """
            return (
                f["syn_flag"] == 1
                and f["ack_flag"] == 0
                and f["packet_rate"] > 200  # packets per second
                and f["packet_count"] > 100
            )

        def suspicious_scan_rule(f: Dict[str, Any]) -> bool:
            """
            Heuristic for TCP port scanning, using state:
            - Short, low-byte flows that look like probes
            - SYN seen, no ACK yet
            - Source has hit MANY different destination ports
              on this destination within a short window.
            """
            avg_packet_size = f["byte_count"] / max(f["packet_count"], 1)

            distinct_ports = f.get("_distinct_dst_ports", 0)
            window_age = f.get("_port_scan_window", 0.0)

            return (
                # per-flow shape
                f["packet_count"] <= 5
                and f["byte_count"] < 800
                and avg_packet_size < 200
                and f["syn_flag"] == 1
                and f["ack_flag"] == 0
                # behavior across flows (stateful)
                and distinct_ports >= self.port_scan_min_ports
                and window_age <= self.port_scan_window
            )

        return {
            "syn_flood": syn_flood_rule,
            "possible_port_scan": suspicious_scan_rule,
        }

    # ---------- PORT-SCAN STATE UPDATES ----------

    def _update_port_scan_state(self, f: Dict[str, Any]) -> None:
        """
        Track distinct destination ports per (src_ip, dst_ip) over a time window.
        Also injects helper fields into the features dict:
          - _distinct_dst_ports
          - _port_scan_window
        """
        src_ip = f.get("src_ip")
        dst_ip = f.get("dst_ip")
        dst_port = f.get("dst_port")
        if src_ip is None or dst_ip is None or dst_port is None:
            return

        now = time.time()
        key = (src_ip, dst_ip)

        state = self.port_scan_state.get(key)

        # If no state yet, or window is too old, reset
        if state is None or (now - state["first_seen"] > self.port_scan_window * 2):
            state = {"ports": set(), "first_seen": now}

        state["ports"].add(dst_port)
        self.port_scan_state[key] = state

        # annotate features for the rule to read
        f["_distinct_dst_ports"] = len(state["ports"])
        f["_port_scan_window"] = now - state["first_seen"]

    # ---------- ANOMALY-BASED DETECTION (ISOLATION FOREST) ----------

    def features_to_vector(self, f: Dict[str, Any]) -> List[float]:
        """
        Extract a numeric vector used by the anomaly model
        from the full feature dictionary.
        """
        return [
            float(f["packet_size"]),
            float(f["packet_rate"]),
            float(f["byte_rate"]),
            float(f["window_size"]),
        ]

    def train_anomaly_detector(self, samples: List[List[float]]) -> None:
        """
        Train IsolationForest on a list of numeric feature vectors
        representing 'normal' traffic.
        """
        if not samples:
            print("[DetectionEngine] No samples given for anomaly training.")
            return

        self.iforest = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
        )
        self.iforest.fit(samples)
        print(
            f"[DetectionEngine] Trained IsolationForest on "
            f"{len(samples)} baseline samples."
        )

    # ---------- UNIFIED DETECTION ENTRYPOINT ----------

    def detect_threats(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Given a feature dictionary for a single packet/flow update,
        return a list of detected threats (could be 0, 1, or more).
        """
        threats: List[Dict[str, Any]] = []

        # Update state for port-scan detection before running rules
        self._update_port_scan_state(features)

        # 1) Signature-based checks
        for name, rule_fn in self.signature_rules.items():
            try:
                if rule_fn(features):
                    # Tune severity per rule
                    severity = "HIGH" if name == "syn_flood" else "MEDIUM"

                    threats.append(
                        {
                            "method": "signature",
                            "name": name,
                            "severity": severity,
                            "score": None,
                        }
                    )
            except Exception as e:
                print(f"[DetectionEngine] Error in rule '{name}': {e}")

        # 2) Anomaly-based check (if model is trained)
        if self.iforest is not None:
            try:
                vec = [self.features_to_vector(features)]
                score = float(self.iforest.decision_function(vec)[0])
                # Lower scores = more anomalous
                if score < self.anomaly_threshold:
                    threats.append(
                        {
                            "method": "anomaly",
                            "name": "isolation_forest",
                            "severity": "MEDIUM",
                            "score": score,
                        }
                    )
            except Exception as e:
                print(f"[DetectionEngine] Anomaly detection error: {e}")

        return threats
