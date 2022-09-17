#! /usr/bin/env python3

from scapy.all import *             # Importing Scapy 

pkts = rdpcap('pktspoofed.pcap')    # Reading Pcap File


for pkt in pkts:                    # Listing all packet separately
    if IP in pkt:                   # Check if data is a network layer packet i.e. IP Packet 
        ip_src=pkt[IP].src
        ip_dst=pkt[IP].dst
        ip_proto=pkt[IP].proto
        if(ip_proto == 6):          # Check whether packet is TCP
            ip_proto = "TCP"
        elif(ip_proto == 1):        # Check whether packet is ICMP
            ip_proto = "ICMP"
        elif(ip_proto == 17):       # Check whether packet is UDP
            ip_proto = "UDP"
        elif(ip_proto == 2):        # Check whether packet is IGMP
            ip_proto = "IGMP"
        print(f"Source : {ip_src:20s} Destination : {ip_dst:20s} Protocol : {ip_proto:10s}".format(str(ip_src), str(ip_dst), str(ip_proto)))
