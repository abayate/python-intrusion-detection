# alert_system.py

import logging
from typing import Dict, Any
from datetime import datetime


class AlertSystem:
    """
    Handles formatting and logging of IDS alerts.
    Currently logs to a file and prints a concise summary to console.
    """

    def __init__(self, log_file: str = "ids_alerts.log"):
        self.logger = logging.getLogger("IDSAlerts")
        self.logger.setLevel(logging.INFO)

        # Avoid duplicate handlers if re-instantiated
        if not self.logger.handlers:
            fh = logging.FileHandler(log_file)
            fmt = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            fh.setFormatter(fmt)
            self.logger.addHandler(fh)

    def generate_alert(self, threat: Dict[str, Any], features: Dict[str, Any]) -> None:
        """
        Log and print a single alert based on the threat dict and features.
        """
        src = f"{features.get('src_ip')}:{features.get('src_port')}"
        dst = f"{features.get('dst_ip')}:{features.get('dst_port')}"
        method = threat.get("method")
        name = threat.get("name")
        severity = threat.get("severity", "MEDIUM")
        score = threat.get("score")

        # Build a structured message
        msg = (
            f"ALERT method={method} name={name} severity={severity} "
            f"src={src} dst={dst} "
            f"pkts={features.get('packet_count')} "
            f"rate={features.get('packet_rate'):.2f}pps "
            f"bytes={features.get('byte_count')}"
        )

        if score is not None:
            msg += f" anomaly_score={score:.4f}"

        # Log to file with appropriate severity
        level = logging.INFO
        if severity == "HIGH":
            level = logging.ERROR
        elif severity == "MEDIUM":
            level = logging.WARNING

        self.logger.log(level, msg)

        # Also print a condensed line to console for visibility
        print(f"[ALERT] {severity}: {name} | {src} -> {dst}")
