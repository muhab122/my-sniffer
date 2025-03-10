from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        protocol_name = "OTHER"
        if packet.haslayer(TCP):
            protocol_name = "TCP"
        elif packet.haslayer(UDP):
            protocol_name = "UDP"
        elif packet.haslayer(ICMP):
            protocol_name = "ICMP"

        print(f"[+] Packet: {src_ip} -> {dst_ip} | Protocol: {protocol_name}")

print("Sniffing started... Press Ctrl + C to stop.")
sniff(prn=packet_callback, store=False)