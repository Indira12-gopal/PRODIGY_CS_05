#download scapy library: pip install scapy
# Run the script and wait for 10 seconds. The script will capture packets for 10 seconds and then stop.
# The script will display the source IP, destination IP, protocol, source port, destination port, and payload of each packet.
# If the packet contains a payload, the script will display the payload as well.
# IMPORTANT DOWNLOAD NPCAP FROM OFFICIAL SITE :https://npcap.com/dist/npcap-1.80.exe
import sys
import time
from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.all import conf
conf.l3socket = conf.L3socket
def packet_callback(packet):
    try:
        # Extract IP layer information
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            print(f"\n[+] Packet captured:")
            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dst_ip}")
            print(f"Protocol: {protocol}")

            # Extract TCP/UDP information if present
            if TCP in packet or UDP in packet:
                transport_layer = "TCP" if TCP in packet else "UDP"
                sport = packet[transport_layer].sport
                dport = packet[transport_layer].dport
                print(f"{transport_layer} Source Port: {sport}")
                print(f"{transport_layer} Destination Port: {dport}")

            # Extract payload if available
            if Raw in packet:
                payload = packet[Raw].load
                print(f"Payload: {payload.decode(errors='ignore')}")

    except Exception as e:
        print(f"[!] Error processing packet.")

# Display a startup message
print("Starting packet sniffer. Press Ctrl+C to stop other wise code will terminate after 10 sec.")
print("Capturing packets...\n")

# Start sniffing packets
# Replace 'eth0' with the appropriate network interface name for your system
#You comment out below set of code for further detailed packages info!
def packet_callback(packet):
    print(packet.summary()) # Display a summary of the packet

# Start sniffing in a non-blocking way
start_time = time.time()
try:
    while True:
        # Check elapsed time, if it's more than 10 seconds, stop the script
        if time.time() - start_time > 10:
            print("10 seconds passed, stopping sniffing.")
            print("By Indira Bhattacharjee.")
            sys.exit()  # Stop the script after 10 seconds
        sniff(filter="ip", prn=packet_callback, store=False, timeout=1)  # 1-second timeout for each sniff cycle
except KeyboardInterrupt:
    print("Sniffing interrupted by user")
    sys.exit()
 
