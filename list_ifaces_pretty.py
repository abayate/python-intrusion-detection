from scapy.all import get_if_list, conf

for dev_name in get_if_list():
    iface = conf.ifaces.get(dev_name)

    print(f"Scapy device: {dev_name}")
    if iface is not None:
        # iface.name / iface.description come from Scapy's NetworkInterface object
        os_name = getattr(iface, "name", "")
        desc = getattr(iface, "description", "")
        ip = getattr(iface, "ip", None)

        print(f"  OS name     : {os_name}")
        print(f"  Description : {desc}")
        print(f"  IPv4        : {ip}")
    print("-" * 60)
