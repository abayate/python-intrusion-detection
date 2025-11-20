from scapy.all import sniff

IFACE = r"\Device\NPF_{ENTER_YOUR_ID_HERE}"


def handle_packet(pkt):
    print(pkt.summary())


def main():
    print(f"Sniffing on: {IFACE} (press Ctrl+C to stop)")
    sniff(iface=IFACE, filter="udp port 53", prn=handle_packet, store=False)


if __name__ == "__main__":
    main()
