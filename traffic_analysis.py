# traffic_analysis.py

import time
from collections import defaultdict
from scapy.layers.inet import IP, TCP


class TrafficAnalyzer:
    """
    Tracks basic flow statistics and extracts per-packet features
    that can be used by signature- and anomaly-based detection.
    """

    def __init__(self):
        # key: (src_ip, dst_ip, src_port, dst_port) -> flow stats
        self.flows: dict[tuple, dict] = {}

    def _get_flow_key(self, pkt):
        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)
        if ip is None or tcp is None:
            return None
        return (ip.src, ip.dst, tcp.sport, tcp.dport)

    def analyze_packet(self, pkt) -> dict | None:
        """
        Update internal flow stats for this packet and return
        a feature dictionary describing the current flow/packet.
        """
        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)
        if ip is None or tcp is None:
            return None

        key = self._get_flow_key(pkt)
        if key is None:
            return None

        now = time.time()
        length = len(pkt)

        flow = self.flows.get(key)
        if flow is None:
            flow = {
                "packet_count": 0,
                "byte_count": 0,
                "start_time": now,
                "last_time": now,
            }

        # update flow stats
        flow["packet_count"] += 1
        flow["byte_count"] += length
        flow["last_time"] = now
        self.flows[key] = flow

        duration = flow["last_time"] - flow["start_time"]
        if duration <= 0:
            duration = 1e-6  # avoid division by zero

        packet_rate = flow["packet_count"] / duration
        byte_rate = flow["byte_count"] / duration

        flags = tcp.flags
        syn_flag = int(flags & 0x02 != 0)  # SYN
        ack_flag = int(flags & 0x10 != 0)  # ACK
        rst_flag = int(flags & 0x04 != 0)  # RST

        features = {
            # identifiers
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            # basic size and counters
            "packet_size": length,
            "packet_count": flow["packet_count"],
            "byte_count": flow["byte_count"],
            # timing / rates
            "duration": duration,
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            # TCP behavior
            "syn_flag": syn_flag,
            "ack_flag": ack_flag,
            "rst_flag": rst_flag,
            "window_size": tcp.window,
        }

        return features


# Simple standalone test using PacketCapture
if __name__ == "__main__":
    from packet_capture import PacketCapture
    import queue

    from config import IFACE

    pc = PacketCapture(IFACE)
    analyzer = TrafficAnalyzer()

    print(f"[TrafficAnalyzer] Capturing on: {IFACE}")
    pc.start()

    try:
        while True:
            try:
                pkt = pc.packet_queue.get(timeout=2)
            except queue.Empty:
                print("[TrafficAnalyzer] No packets in queue...")
                continue

            feats = analyzer.analyze_packet(pkt)
            if feats:
                # Just show a subset so it's readable
                print(
                    f"{feats['src_ip']}:{feats['src_port']} -> "
                    f"{feats['dst_ip']}:{feats['dst_port']} | "
                    f"pkts={feats['packet_count']} rate={feats['packet_rate']:.2f}pps "
                    f"bytes={feats['byte_count']}"
                )
    except KeyboardInterrupt:
        print("\n[TrafficAnalyzer] Stopping capture.")
        pc.stop()
