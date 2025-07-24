import socket
import threading
from scapy.all import DNS, DNSQR

BASE_DOMAIN = "vilgax.crabdance.com"
BASE_DOM_NAME_COUNT = len(BASE_DOMAIN.split('.'))
DNS_SERVER_PORT = 49152
DNS_SERVER_IP = '0.0.0.0'

TEST_ADDR = ("www.google.com", 443)

# Operations that will be done by the dns server
CREATE_CONN = 1
FORWARD_REQ = 2

# Remote socket variable that changes with each new connection
remote_sock = None

def forward_from_proxy():
    ...
def forward_to_proxy():
    ...
    
def handle_dns_query(data: bytes, client_addr: tuple, dns_socket: socket.socket):
    global BASE_DOM_NAME_COUNT
    dns_packet = DNS(data)

    if dns_packet.qr == 0 and dns_packet.qd:
        query_name = dns_packet[DNSQR].qname.decode().rstrip('.')
        label_parts = query_name.split('.')

        # Expect queries like: addr.port.command
        if len(label_parts) < 3:
            print("Invalid query")
            return
        
        print(f"[+] Received request from {client_addr}: {query_name}")

        cmd, req_port, req_addr = int(label_parts[0]), int(label_parts[1]), '.'.join(label_parts[2:])
        print(f"CMD: {cmd}, PORT: {req_port}, ADDR: {req_addr}")

        if cmd == CREATE_CONN:
            # Connect to the one the client wants to connect
            print(f"[+] Attempting connection to {req_addr}:{req_port}")
            remote_sock = socket.create_connection((req_addr, req_port))
            remote_bind_addr = remote_sock.getsockname()
            print(f"[+] Connection successful {remote_bind_addr}")

dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_socket.bind((DNS_SERVER_IP, DNS_SERVER_PORT))
print(f"Listening for DNS queries on interface ({DNS_SERVER_IP}):{DNS_SERVER_PORT}...")

# Test connection
print(f"[+] Testing connenction to {TEST_ADDR}")
socket.create_connection(TEST_ADDR)
print(f"[+] Connection successful")

while True:
    data, client_address = dns_socket.recvfrom(512)
    try:
        handle_dns_query(data, client_address, dns_socket)
    except Exception as e:
        print(f"[+]ERROR: Handling req from {client_address}, data: {data}: {e}")

dns_socket.close()