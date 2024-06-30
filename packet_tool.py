from scapy.all import *
from datetime import datetime

# Initialize packet counter
packet_counter = 0  

# ANSI color codes
CYAN = '\033[96m'
RED = '\033[91m'
GREEN = '\033[92m'
ENDC = '\033[0m'  # Reset to default color

# Protocol mappings
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    20: "FTP",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
}


def get_protocol_name(proto_num):
    return PROTO_MAP.get(proto_num, f"Protocol {proto_num}")


def packet_callback(packet):
    global packet_counter
    if IP in packet:
        packet_counter += 1
        timestamp = datetime.fromtimestamp(packet.time).strftime('%H:%M:%S %Y-%m-%d')
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        proto_name = get_protocol_name(proto_num)
        payload_len = len(packet[Raw]) if Raw in packet else 0
        
        # Format strings with colors
        src_ip_str = f"{CYAN}{src_ip}{ENDC}"
        dst_ip_str = f"{RED}{dst_ip}{ENDC}"
        proto_str = f"Protocol: {proto_name}"
        payload_str = f"{GREEN}Payload Length: {payload_len}{ENDC}" if payload_len > 0 else ""
        
        # Construct the output string, print it, and write the packet to a pcap file
        output = f"[{packet_counter}] [{timestamp}] {src_ip_str} -> {dst_ip_str} {proto_str} {payload_str}"
        print(output)
        wrpcap("output.pcap", packet, append=True)

if __name__ == "__main__":
    # Sniffing packets with a filter for IP traffic
    iface = input("Enter the network interface to sniff (e.g., eth0, wlan0): ")
    sniff(filter="ip", prn=packet_callback, store=0, iface=iface)