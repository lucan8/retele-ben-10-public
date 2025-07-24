import socket
import threading
import sys
from scapy.all import DNS, DNSQR
from base64 import b32encode

# TODO: Use VPS as DNS server instead of local machine to simulate reality better
SOCKS_VERSION = 5

DNS_SERVER_IP = '192.168.100.59'
DNS_SERVER_PORT = 49152
BASE_DOMAIN = "vilgax.crabdance.com"
dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

SOCK_SERVER_PORT = 1080
SOCK_SERVER_IP = '127.0.0.1'

# Operations that will be done by the dns server
CREATE_CONN = 1
FORWARD_REQ = 2

CHUNK_SIZE = 200
def forward_to_dns(client_sock: socket.socket, req_addr: str, req_port: int):
    global BASE_DOMAIN, dns_socket

    # Create initial connection from dns server to (req_addr, req_port)
    domain = f'{CREATE_CONN}.{req_port}.{req_addr}.{BASE_DOMAIN}'
    dns_query = DNS(id=0xAAAA, rd=1, qd=DNSQR(qname=domain, qtype="TXT"))
    dns_socket.sendto(bytes(dns_query), (DNS_SERVER_IP, DNS_SERVER_PORT))

    # Get request from browser and forward it to dns server, encoded
    http_req_b32 = b32encode(client_sock.recv(4096)).decode('ascii').strip('=').lower()
    # chunk_index = 0
    # while True:
    #     domain = f'{FORWARD_REQ}.{http_req_b32[:CHUNK_SIZE]}'
    #     dns_query = DNS(id=0xAAAA, rd=1, qd=DNSQR(qname=domain, qtype="TXT"))
    #     dns_socket.sendto(dns_query, (DNS_SERVER_IP, DNS_SERVER_PORT))
    
    
def handle_client(sock: socket.socket):
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
    # Establish connection0
    try:
        forward_to_dns(sock, addr, port)
        remote_sock = socket.create_connection((addr, port))
        bind_addr = remote_sock.getsockname()
        print(f"Bound address: {bind_addr}")
        if len(bind_addr) == 2: # IPV4
            sock.sendall(bytes([SOCKS_VERSION, 0, 0, 1]) + 
                         socket.inet_pton(socket.AF_INET, bind_addr[0]) +
                         bind_addr[1].to_bytes(2, 'big'))
        elif len(bind_addr) == 4: # IPV6
             sock.sendall(bytes([SOCKS_VERSION, 0, 0, 4]) + 
                          socket.inet_pton(socket.AF_INET6, bind_addr[0]) +
                          bind_addr[1].to_bytes(2, 'big'))
        
        # Keep conversation going with remote
        threading.Thread(target=forward, args=(sock, remote_sock,)).start()
        threading.Thread(target=forward, args=(remote_sock, sock)).start()
    except Exception as e:
        print(f"ERROR: Establishing connection: {e}")
        sock.close()

def forward(src_sock : socket.socket, dest_sock: socket.socket):
    src_sock_addr = src_sock.getsockname()
    dest_sock_addr = dest_sock.getsockname()
    print(f"Forwarding packets from {src_sock_addr} to {dest_sock_addr}")
    try:
        while True:
            data = src_sock.recv(4096)
            print(f"Sending data from {src_sock_addr} to {dest_sock_addr}: {len(data)} bytes")
            if not data:
                break
            dest_sock.sendall(data)
    finally:
        src_sock.close()
        dest_sock.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((SOCK_SERVER_IP, SOCK_SERVER_PORT))
sock.listen(5)

print(f"[+] SOCKS5 server listeing on interface: {(SOCK_SERVER_IP, SOCK_SERVER_PORT)}")

# Test DNS server
# dns_socket.sendto(b"hello", (DNS_SERVER_IP, DNS_SERVER_PORT))
# forward_to_dns(None, DNS_SERVER_IP, DNS_SERVER_PORT)

while True:
    serv_sock, _ = sock.accept()
    print("[+] Accepted a new connection")
    threading.Thread(target=handle_client, args=(serv_sock,)).start()

