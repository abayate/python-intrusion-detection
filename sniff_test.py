from scapy.all import sniff

IFACE = r"\Device\NPF_{CDE0F71D-A0FF-49CF-91FB-5CD64A4758A9}"


def handle_packet(pkt):
    print(pkt.summary())


def main():
    print(f"Sniffing on: {IFACE} (press Ctrl+C to stop)")
    sniff(iface=IFACE, filter="udp port 53", prn=handle_packet, store=False)


if __name__ == "__main__":
    main()
