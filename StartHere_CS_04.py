from scapy.all import *

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {proto}")
        
        if TCP in packet:
            payload = packet[TCP].payload
            print("TCP Payload:", payload)
        elif UDP in packet:
            payload = packet[UDP].payload
            print("UDP Payload:", payload)

def main():
    print("Packet Sniffer started. Press Ctrl+C to stop.")
    sniff(prn=packet_handler, store=False)

if __name__ == "__main__":
    main()
