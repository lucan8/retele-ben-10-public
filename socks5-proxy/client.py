import socket
import threading
import sys
from scapy.all import DNS, DNSQR
import base64

# Useful links:
# Built in types: https://docs.python.org/3/library/stdtypes.html
# Base64: https://docs.python.org/3/library/base64.html
# Socket: https://docs.python.org/3/library/socket.html

# TODO:
# DO THE NUMBER ENCODING RIGHT ON THE SERVER
# Optimization: Strip the padding when sending a message, add it back on the receiving side beofre decoding
# Good practice: Encode and decode all data
# Construct function that adds BASE_DOMAIN to every DNS request
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
dns_socket.settimeout(10)

SOCK_SERVER_PORT = 1080
SOCK_SERVER_IP = '127.0.0.1'

# Operations that will be done by the dns server
CREATE_CONN = 1 # Query: cmd.port.addr
CONSTRUCT_REQ = 2 # Query: cmd.remote_sock_id.encoded_http_req
SEND_REQ = 3 # Query: cmd.remote_sock_id

CHUNK_SIZE = 200
MAX_LABEL_SIZE = 60 # Make sure it's multiple of 4

# Dummy address to send back to the browser
DUMMY_IP = '0.0.0.1'
DUMMY_PORT = 9999

def proc_dns_resp(dns_resp: DNS) -> bytes:
    rr = dns_resp.an[0]

    # TXT record is encoded as 16
    if rr.type != 16:
        raise RuntimeError("Not TXT record")

    txt_data = rr.rdata
    txt_data = b''.join(txt_data).decode()
    txt_data = base64.b64decode(txt_data)

    return txt_data

def forward_to_dns(client_sock: socket.socket, req_addr: str, req_port: int):
    global BASE_DOMAIN, dns_socket

    # Create initial connection from dns server to (req_addr, req_port)
    domain = f'{CREATE_CONN}.{req_port}.{req_addr}.{BASE_DOMAIN}'
    dns_query = DNS(id=0xAAAA, rd=1, qd=DNSQR(qname=domain, qtype="TXT"))
    dns_socket.sendto(bytes(dns_query), (DNS_SERVER_IP, DNS_SERVER_PORT))

    # Wait for remote_sock id response
    rem_sock_id = int.from_bytes(proc_dns_resp(DNS(dns_socket.recv(512))))
    print(f"[+] Remote socket id: {rem_sock_id}")

    # Get request from browser and forward it to dns server, encoded
    http_req = client_sock.recv(4096)
    print(f"[+] Received http request of size {len(http_req)}")
    # print(http_req.decode(errors='ignore'))

    http_req_b32 = base64.b64encode(http_req).decode('ascii')
    rem_http_req = http_req_b32
    chunk_index = 0
    
    # Send request in chunks, also specifying which socket to use
    while len(rem_http_req):
        chunk = rem_http_req[:MAX_LABEL_SIZE]
        # print(f"[+] Sending chunk {chunk_index} of the http request")
        # print(base64.b64decode(chunk).decode(errors='ignore'))
        domain = f'{CONSTRUCT_REQ}.{rem_sock_id}.{chunk}.{BASE_DOMAIN}'

        dns_query = DNS(id=0xAAAA, rd=1, qd=DNSQR(qname=domain, qtype="TXT"))
        dns_socket.sendto(bytes(dns_query), (DNS_SERVER_IP, DNS_SERVER_PORT))

        chunk_index += 1
        rem_http_req = rem_http_req[MAX_LABEL_SIZE:]
    
    if chunk_index != 0:
        # Tell the server to forward the completed message
        print(f"[+] HTTP request completely sent")
        domain = f'{SEND_REQ}.{rem_sock_id}.{BASE_DOMAIN}'

        dns_query = DNS(id=0xAAAA, rd=1, qd=DNSQR(qname=domain, qtype="TXT"))
        dns_socket.sendto(bytes(dns_query), (DNS_SERVER_IP, DNS_SERVER_PORT))


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
    # Establish connection
    try:
        # Make the browser think we actually connected to something
        sock.sendall(bytes([SOCKS_VERSION, 0, 0, 1]) + 
                     socket.inet_pton(socket.AF_INET, DUMMY_IP) +
                     DUMMY_PORT.to_bytes(2, 'big'))
        forward_to_dns(sock, addr, port)
    except Exception as e:
        print(f"ERROR: Establishing connection: {e}")
        sock.close()


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
    # threading.Thread(target=handle_client, args=(serv_sock,)).start()
    handle_client(serv_sock)
    # break # Only for now

