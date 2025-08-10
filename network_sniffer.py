from scapy.all import sniff, IP, TCP, UDP, ICMP
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        # Map protocol number to name
        protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_name = protocol_map.get(proto, str(proto))
        
        print(f"[+] Source: {src_ip} --> Destination: {dst_ip} | Protocol: {proto_name}")
        
        # Try to extract payload if available
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet.payload)
            if payload:
                print(f"    Payload: {payload[:50]}...")  # Show first 50 bytes

# Capture packets (adjust count or timeout as needed)
print("Starting packet capture... Press CTRL+C to stop.")
sniff(prn=packet_callback, store=False)


