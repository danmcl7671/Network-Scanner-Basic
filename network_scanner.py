from scapy.all import ARP, Ether, srp
import argparse

def scan_network(ip_range):
    # Create an ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and receive the response
    result = srp(packet, timeout=2, verbose=False)[0]

    # Parse the response
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

def display_results(clients):
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("ip_range", help="IP range to scan (e.g. 192.168.1.0/24)")
    args = parser.parse_args()

    print(f"Scanning network: {args.ip_range}")
    clients = scan_network(args.ip_range)
    display_results(clients)
