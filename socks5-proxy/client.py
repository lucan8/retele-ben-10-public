import socket
import threading
import sys
from scapy.all import DNS, DNSQR
import base64
import hashlib
import traceback
from typing import Union

class RemoteConn:
    def __init__(self, rem_sock: socket.socket, client_rem_sock_id: int = 0):
        self.rem_sock = rem_sock
        # self.rem_sock.settimeout(10)
        self.client_rem_sock_id = client_rem_sock_id
        self.buffer = ""

    def add_to_buffer(self, message: str):
        self.buffer += message
    
    # Send the data in the buffer and empties it
    def send(self):
        decoded_http_req = myB64Decode(self.buffer)
        # print(decoded_http_req.decode(errors='ignore'))
        self.rem_sock.sendall(decoded_http_req)
        self.buffer = ""
    
    def __del__(self):
        self.rem_sock.close()

# Useful links:
# Built in types: https://docs.python.org/3/library/stdtypes.html
# Base64: https://docs.python.org/3/library/base64.html
# Socket: https://docs.python.org/3/library/socket.html
# Scapy: https://scapy.readthedocs.io/en/latest/api/scapy.html

# TODO:
# Optimization: Strip the padding when sending a message, add it back on the receiving side beofre decoding
# Optimization: Determine the remaining TXT size dynamically
# Good practice: Encode and decode all data
# After each packet sent, wait for a request for md5 and send it
# If they don't match resend the packet
# Also have a timeout of 2-3 sec, if no response comes back resend the packet
# SHOULDN'T THE PACKET GO THROUGH MULTIPLE DNS SERVERS AND GET RID OF BASE_DOMAIN???

SOCKS_VERSION = 5

DNS_SERVER_IP = '34.159.249.73'
# DNS_SERVER_IP = '8.8.8.8' THIS SHOULD BE USED
DNS_SERVER_PORT = 53
BASE_DOMAIN = "vilgax.crabdance.com"
dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_socket.settimeout(100)
DNS_PACKET_ID = 0xAAAA

SOCK_SERVER_PORT = 1080
SOCK_SERVER_IP = '127.0.0.1'

# Operations that will be done by the dns server
CREATE_CONN = 1 # Query: cmd.port.addr
CONSTRUCT_MSG = 2 # Query: cmd.remote_sock_id.encoded_http_req
SEND_MSG = 3 # Query: cmd.remote_sock_id

MAX_HTTP_SIZE = 4096
MAX_UDP_SIZE = 512
CHUNK_SIZE = 200
MAX_LABEL_SIZE = 60 # Make sure it's multiple of 4

# Dummy address to send back to the browser
DUMMY_IP = '0.0.0.1'
DUMMY_PORT = 9999

# rem_sock_id - RemoteConn
conn_dict = {}
rem_sock_id_counter = 1

def myB64Decode(data: str):
    needed_pad = 4 - (len(data) % 4)
    data += '=' * needed_pad
    return base64.b64decode(data)

# Extracts the TXT section of the answer section and decodes if desired
def proc_dns_resp(dns_resp: DNS, decode=False):
    rr = dns_resp.an[0]

    # TXT record is encoded as 16
    if rr.type != 16:
        raise RuntimeError("Not TXT record")

    txt_data = rr.rdata
    if not decode:
        return txt_data
    
    txt_data = b''.join(txt_data).decode()
    txt_data = myB64Decode(txt_data)

    return txt_data

# Tells the DNS server to create a connection to req_addr, req_port
# And to add rem_sock_id_counter to all responses
def create_conn(rem_sock: socket.socket, req_addr: str, req_port: int) -> RemoteConn:
    global rem_sock_id_counter

    send_dns_req(f'{CREATE_CONN}.{rem_sock_id_counter}.{req_port}.{req_addr}')
    conn_dict[rem_sock_id_counter] = RemoteConn(rem_sock)
    rem_sock_id_counter += 1

    return conn_dict[rem_sock_id_counter - 1]

# Adds ".{BASE_DOMAIN}" to domain and sends the request
def send_dns_req(domain: str):
    global dns_socket, DNS_SERVER_IP, DNS_SERVER_PORT, DNS_PACKET_ID

    domain += f".{BASE_DOMAIN}"
    dns_query = bytes(DNS(id=DNS_PACKET_ID, rd=1, qd=DNSQR(qname=domain, qtype="TXT")))
    dns_socket.sendto(dns_query, (DNS_SERVER_IP, DNS_SERVER_PORT))
        
# Encodes http req in base64 and sends it to the DNS server in chunks
def send_http_msg(rem_conn: RemoteConn, http_msg: bytes):
    global CONSTRUCT_MSG, MAX_LABEL_SIZE, MAX_HTTP_SIZE
    
    # Encode http request from browser
    http_msg_b32 = base64.b64encode(http_msg).decode('ascii')
    rem_http_msg = http_msg_b32
    chunk_index = 0
    
    # Send request in chunks, also specifying which socket the server should use
    while len(rem_http_msg):
        chunk = rem_http_msg[:MAX_LABEL_SIZE]
        send_dns_req(f'{CONSTRUCT_MSG}.{rem_conn.client_rem_sock_id}.{chunk}')

        print(f"[+] HTTP chunk {chunk_index} sent")
        rem_http_msg = rem_http_msg[MAX_LABEL_SIZE:]

        chunk_index += 1
    
    if chunk_index != 0:
        # Tell the server to forward the completed message
        print(f"[+] HTTP message completely sent")
        send_dns_req(f'{SEND_MSG}.{rem_conn.client_rem_sock_id}')


def handle_dns_resp(data: bytes):
    global BASE_DOM_NAME_COUNT, conn_dict, rem_sock_id_counter, dns_socket
    dns_packet = DNS(data)

    # Only accept response packets
    if dns_packet.qr == 1:
        query_name = dns_packet[DNSQR].qname.decode().rstrip('.')
        label_parts = query_name.split('.')

        print(f"[+] Query name: {query_name}")

        if len(label_parts) < 3:
            print("[ERROR] Invalid query")
            return

        cmd, rem_sock_id = int(label_parts[0]), int(label_parts[1])
          
        if rem_sock_id not in conn_dict:
            print("[ERROR] Unknown remote socket id")
            return
    
        chosen_rem_sock = conn_dict[rem_sock_id]

        if cmd == CREATE_CONN:
            client_rem_sock_id = int.from_bytes(proc_dns_resp(dns_packet, True))
            chosen_rem_sock.client_rem_sock_id = client_rem_sock_id

            print("[+] Connection to remote succesful")
            forward_to_dns(chosen_rem_sock)
        elif cmd == CONSTRUCT_MSG:
            encoded_msg_l = proc_dns_resp(dns_packet)
            chunk_size = 0
            # print(base64.b64decode(encoded_msg).decode(errors='ignore'))
            # Add partial encoded request to buffer
            for enc_msg in encoded_msg_l:
                msg = enc_msg.decode("ascii")
                # print(msg)
                chosen_rem_sock.add_to_buffer(msg)
                chunk_size += len(enc_msg)

            print(f"[+] Socket {rem_sock_id}: Adding {chunk_size}")
        elif cmd == SEND_MSG:
            # Decode http request and send to the browser
            chosen_rem_sock.send()
            print(f"[+] Socket {rem_sock_id}: Sent HTTP request")
        else:
            print(f"[ERROR] Invalid command: {cmd}")
    else:
        print("[ERROR] Invalid DNS packet")

def forward_to_dns(rem_conn: RemoteConn):
    global dns_socket

    while True:
        data = rem_conn.rem_sock.recv(MAX_HTTP_SIZE)
        if not data:
            break
        send_http_msg(rem_conn, data)

def forward_from_dns():
    global dns_socket

    while True:
        data = dns_socket.recv(MAX_UDP_SIZE)
        if not data:
            break
        handle_dns_resp(data)

def handle_client(sock: socket.socket):
    global rem_sock_id_counter, SOCKS_VERSION, DUMMY_IP, DUMMY_PORT

    vers, nmethods = sock.recv(2)
    assert vers == SOCKS_VERSION

    print(f"nmethods: {nmethods}")

    methods = sock.recv(nmethods)
    print(f"Methods: {methods}")

    # Tell the browser no auth is needed
    sock.sendall(bytes([SOCKS_VERSION, 0]))

    vers, cmd, _, addr_type = sock.recv(4)
    print(f"Command: {cmd}, Addr type: {addr_type}")
    assert vers == SOCKS_VERSION

    if addr_type == 1: # IPV4
        addr = socket.inet_ntoa(sock.recv(4))
    elif addr_type == 3: # Domain name
        domain_length = sock.recv(1)[0]
        addr = sock.recv(domain_length).decode()
        print(f"Solved ip: {addr}")
    else:
        print(f"ERROR: Unsupported address type: {addr_type}")
        sock.close()
        return
    
    port = int.from_bytes(sock.recv(2))

    print(f"Address: {(addr, port)}")
    # Establish connection
    try:
        # Make the browser think we actually connected to something
        sock.sendall(bytes([SOCKS_VERSION, 0, 0, 1]) + 
                     socket.inet_pton(socket.AF_INET, DUMMY_IP) +
                     DUMMY_PORT.to_bytes(2, 'big'))
        
       
        create_conn(sock, addr, port)
    except Exception as e:
        print(f"ERROR: Establishing connection: {traceback.format_exc()}")
        sock.close()

print(f"[+] Listening for DNS responses from {(DNS_SERVER_IP, DNS_SERVER_PORT)}")
threading.Thread(target=forward_from_dns).start()

# Socket for new TCP conncection with browser
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((SOCK_SERVER_IP, SOCK_SERVER_PORT))
sock.listen(5)

print(f"[+] SOCKS5 server listeing on interface: {(SOCK_SERVER_IP, SOCK_SERVER_PORT)}")

# Test DNS server
# dns_socket.sendto(b"hello", (DNS_SERVER_IP, DNS_SERVER_PORT))
# forward_to_dns(None, DNS_SERVER_IP, DNS_SERVER_PORT)

for i in range(3):
    serv_sock, addr = sock.accept()
    print(f"[+] Accepted a new connection: {addr}")
    # threading.Thread(target=handle_client, args=(serv_sock,)).start()
    handle_client(serv_sock)
