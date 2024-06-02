import scapy.all as scapy

class NetAnalyzer:
    def __init__(self, interface, count):
        self.interface = interface
        self.count = count
        self.packets = []

    def sniff_packets(self):
        print(f"[*] Sniffing packets on interface {self.interface}...")
        self.packets = scapy.sniff(iface=self.interface, count=self.count)
        print("[*] Packet Sniffing complete.")

    def analyze_packets(self):
        print("\n[*] Analyzing captured packets:")
        print("=================================")
        for packet in self.packets:
            self.analyze_packet(packet)
            print("=================================")

    def analyze_packet(self, packet):
        if packet.haslayer(scapy.IP):
            source_ip = packet[scapy.IP].src
            destination_ip = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto
            print(f"Source IP: {source_ip} | Destination IP: {destination_ip} | Protocol: {protocol}")

            if packet.haslayer(scapy.TCP):
                payload = packet[scapy.TCP].payload
                print(f"Payload Data: {payload}")
            elif packet.haslayer(scapy.UDP):
                payload = packet[scapy.UDP].payload
                print(f"Payload Data: {payload}")

    def save_packets_to_file(self, filename):
        with open(filename, 'w') as f:
            f.write("Captured Packets:\n")
            for packet in self.packets:
                f.write(str(packet) + "\n")
        print(f"[*] Captured packets saved to {filename}")

if __name__ == "__main__":
    print("=== NetAnalyzer ===")
    interface = input("Enter the interface to sniff packets (e.g., eth0, wlan0): ")
    count = int(input("Enter the number of packets to sniff: "))

    net_analyzer = NetAnalyzer(interface, count)
    net_analyzer.sniff_packets()
    net_analyzer.analyze_packets()

    export_option = input("Do you want to save captured packets to a file? (y/n): ").lower()
    if export_option == 'y':
        filename = input("Enter the filename to save the captured packets: ")
        net_analyzer.save_packets_to_file(filename)
