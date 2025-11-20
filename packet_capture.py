# packet_capture.py

import threading
import queue
from scapy.all import sniff, IP, TCP
from config import IFACE


class PacketCapture:
    """
    Continuously captures IP/TCP packets from a given interface
    and pushes them into a thread-safe queue for processing.
    """

    def __init__(self, iface: str = IFACE):
        self.iface = iface
        self.packet_queue: "queue.Queue" = queue.Queue()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def _packet_handler(self, pkt):
        """Callback called by scapy for every captured packet."""
        if self._stop_event.is_set():
            return

        # Only keep packets that have both IP and TCP layers
        if IP in pkt and TCP in pkt:
            self.packet_queue.put(pkt)

    def _run_sniffer(self):
        """Internal worker that runs in a background thread."""
        sniff(
            iface=self.iface,
            prn=self._packet_handler,  # call for each packet
            store=False,  # don't store packets in memory
            stop_filter=lambda p: self._stop_event.is_set(),
        )

    def start(self):
        """Start packet capture in a background daemon thread."""
        if self._thread and self._thread.is_alive():
            # Already running
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_sniffer, daemon=True)
        self._thread.start()

    def stop(self):
        """Signal the sniffer to stop and wait for the thread to exit."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)


# Small standalone test
if __name__ == "__main__":
    import time

    pc = PacketCapture()

    print(f"[PacketCapture] Starting capture on: {pc.iface}")
    pc.start()

    try:
        while True:
            try:
                pkt = pc.packet_queue.get(timeout=2)
                print(pkt.summary())
            except queue.Empty:
                print("[PacketCapture] No packets yet...")
    except KeyboardInterrupt:
        print("\n[PacketCapture] Stopping capture.")
        pc.stop()
