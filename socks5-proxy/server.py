import socket
import threading
from scapy.all import DNS, DNSQR, DNSRR
import base64
from typing import Union
import traceback

# TODO: Use a new thread for each message receive
class RemoteConn:
    def __init__(self, rem_sock: socket.socket, client_rem_sock_id: int):
        self.rem_sock = rem_sock
        # self.rem_sock.settimeout(5)
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
    
def myB64Decode(data: str):
    needed_pad = 4 - (len(data) % 4)
    data += '=' * needed_pad
    return base64.b64decode(data)

BASE_DOMAIN = "vilgax.crabdance.com"
BASE_DOM_NAME_COUNT = len(BASE_DOMAIN.split('.'))
DNS_SERVER_PORT = 53
DNS_SERVER_IP = '0.0.0.0'
MESSAGE_SIZE = 200
DNS_PACKET_ID = 0xAAAA
DNS_QTYPE = "TXT"
MAX_HTTP_SIZE = 1024
MAX_UDP_SIZE = 512

# remote_sock_id - RemoteConn
conn_dict = {}
rem_sock_id_counter = 1

TEST_ADDR = ("www.google.com", 443)

# Operations that will be done by the dns server

CREATE_CONN = 1 # Query: cmd.port.addr
CONSTRUCT_MSG = 2 # Query: cmd.remote_sock_id.encoded_http_req
SEND_MSG = 3 # Query: cmd.remote_sock_id

def send_dns_resp(dns_req: DNS, client_addr: tuple[bytes, int], msg: bytes):
    global dns_socket
    dns_socket.sendto(bytes(build_dns_resp(dns_req, msg)), client_addr)

def send_fake_dns_resp(domain: str, client_addr: tuple[bytes, int], msg: bytes):
    global dns_socket
    dns_socket.sendto(bytes(build_fake_dns_resp(domain, msg)), client_addr)

# Actually responds to dns_req
# If msg is str, the function assumes it is already encoded in base64, otherwise it encodes it
def build_dns_resp(dns_req: DNS, msg: Union[bytes, str]) -> DNS:
    global DNS_QTYPE
    
    if isinstance(msg, bytes):
        msg = base64.b64encode(msg).decode()

    return DNS(
                id=dns_req.id,
                qr=1,
                aa=1,
                qd=dns_req.qd,
                an=DNSRR(
                    rrname=dns_req.qd.qname,
                    type=DNS_QTYPE,
                    ttl=60,
                    rdata=msg
                )
            )

# Mimics a dns response to the "domain" query
# If msg is str, the function assumes it is already encoded in base64, otherwise it encodes it
def build_fake_dns_resp(domain: str, msg: Union[bytes, str]) -> DNS:
    global DNS_PACKET_ID, DNS_QTYPE

    domain += f".{BASE_DOMAIN}"
    if isinstance(msg, bytes):
        msg = base64.b64encode(msg).decode()

    return DNS(
                id=DNS_PACKET_ID,
                qr=1,
                aa=1,
                qd=DNSQR(qname=domain, qtype=DNS_QTYPE),
                an=DNSRR(
                    rrname=domain,
                    type=DNS_QTYPE,
                    ttl=60,
                    rdata=msg
                )
            ) 
        
def forward_to_dns(rem_conn: RemoteConn, client_addr: tuple[bytes, int]):
    global dns_socket

    while True:
        data = rem_conn.rem_sock.recv(MAX_HTTP_SIZE)
        if not data:
            break
        print("[+] Received HTTP response from remote! Forwarding...")
        send_http_resp(rem_conn, client_addr, data)

def forward_from_dns():
    global dns_socket

    while True:
        data, client_addr = dns_socket.recvfrom(MAX_UDP_SIZE)
        if not data:
            break
        handle_dns_query(data, client_addr)

def send_http_resp(rem_conn: RemoteConn, client_addr: tuple[bytes, int], http_msg: bytes):
    global CONSTRUCT_MSG, MESSAGE_SIZE, MAX_HTTP_SIZE
    
    # Encode http request from browser
    http_msg_b32 = base64.b64encode(http_msg).decode('ascii')
    # print(http_msg.decode('utf-8', errors='ignore'))
    rem_http_msg = http_msg_b32
    chunk_index = 0
    
    # Send request in chunks, also specifying which socket the server should use
    while len(rem_http_msg):
        chunk = rem_http_msg[:MESSAGE_SIZE]
        send_fake_dns_resp(f'{CONSTRUCT_MSG}.{rem_conn.client_rem_sock_id}', client_addr, chunk)

        print(f"[+] HTTP chunk {chunk_index} sent")
        rem_http_msg = rem_http_msg[MESSAGE_SIZE:]

        chunk_index += 1
    
    if chunk_index != 0:
        # Tell the server to forward the completed message
        print(f"[+] HTTP message completely sent")
        send_fake_dns_resp(f'{SEND_MSG}.{rem_conn.client_rem_sock_id}', client_addr, '')

def handle_dns_query(data: bytes, client_addr: tuple[bytes, int]):
    global BASE_DOM_NAME_COUNT, conn_dict, rem_sock_id_counter, dns_socket
    dns_packet = DNS(data)

    if dns_packet.qr == 0 and dns_packet.qd:
        query_name = dns_packet[DNSQR].qname.decode().rstrip('.')
        label_parts = query_name.split('.')

        print(f"[+] Query name: {query_name}")

        if len(label_parts) < 3:
            print("[ERROR] Invalid query")
            return

        cmd = int(label_parts[0])

        if cmd == CREATE_CONN:
            # Quick fix until dns server is set up
            if "vilgax" in query_name:
                client_rem_sock_id, req_port, req_addr = int(label_parts[1]), int(label_parts[2]), '.'.join(label_parts[3:len(label_parts) - 3])
            else:
                client_rem_sock_id, req_port, req_addr = int(label_parts[1]), int(label_parts[2]), '.'.join(label_parts[3:])

            # Connect to the one the client wants to connect
            print(f"[+] Attempting connection to {req_addr}:{req_port}")
            remote_sock = socket.create_connection((req_addr, req_port))

            remote_bind_addr = remote_sock.getsockname()
            print(f"[+] Connection successful {remote_bind_addr}")

            # Add connection to the dictionary
            # TODO: Group this operation in a locked function
            conn_dict[rem_sock_id_counter] = RemoteConn(remote_sock, client_rem_sock_id)
            rem_sock_id_counter += 1

            print(f"[+] Socket {rem_sock_id_counter - 1}: Created")

            # Send the remote sock id back to the client
            send_dns_resp(dns_packet, client_addr, (rem_sock_id_counter - 1).to_bytes(4, 'big'))

            # Keep conversation going between remote and DNS socket
            threading.Thread(target=forward_to_dns, args=(conn_dict[rem_sock_id_counter - 1], client_addr,)).start()
        elif cmd == CONSTRUCT_MSG:
            rem_sock_id, encoded_msg = int(label_parts[1]), label_parts[2]
            
            if rem_sock_id not in conn_dict:
                print("[ERROR] CONSTRUCT_MSG before CREATE_CONN")
                return
            
            # print(base64.b64decode(encoded_msg).decode(errors='ignore'))
            # Add partial encoded request to buffer
            chosen_rem_sock = conn_dict[rem_sock_id]
            chosen_rem_sock.add_to_buffer(encoded_msg)

            print(f"[+] Socket {rem_sock_id}: Adding {len(encoded_msg)}")
        elif cmd == SEND_MSG:
            rem_sock_id = int(label_parts[1])
            
            if rem_sock_id not in conn_dict:
                print("[ERROR] SEND_MSG before CREATE_CONN")
                return
            
            # Decode http request and send to the browser
            chosen_rem_sock = conn_dict[rem_sock_id]
            chosen_rem_sock.send()
            print(f"[+] Socket {rem_sock_id}: Sent HTTP request")
        else:
            print(f"[ERROR] Invalid command: {cmd}")
    else:
        print("[ERROR] Invalid DNS packet")

print(f"Listening for DNS queries on interface ({DNS_SERVER_IP}):{DNS_SERVER_PORT}...")    
dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_socket.bind((DNS_SERVER_IP, DNS_SERVER_PORT))
forward_from_dns()

# Test connection
print(f"[+] Testing connenction to {TEST_ADDR}")
socket.create_connection(TEST_ADDR)
print(f"[+] Connection successful")