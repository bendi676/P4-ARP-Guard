#!/usr/bin/env python3
from scapy.all import Ether, ARP, sendp

def send_valid_arp():
    print("Crafting valid ARP Reply")
    
    # 1. Craft the Ethernet Header, target h2
    eth = Ether(src="00:00:0a:00:00:01", dst="00:00:0a:00:00:02")
    
    # 2. Craft the VALID ARP Header
    arp = ARP(op=2, 
              hwsrc="00:00:0a:00:00:01", psrc="10.0.0.1", 
              hwdst="00:00:0a:00:00:02", pdst="10.0.0.2")
    
    # 3. Combine and send
    pkt = eth/arp
    print("Sending packet from h1 (10.0.0.1) to h2 (10.0.0.2)")
    
    sendp(pkt, iface="eth0", verbose=False)
    print("Packet sent successfully!")

if __name__ == "__main__":
    send_valid_arp()