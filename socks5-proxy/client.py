import socket
import threading
import sys
from scapy.all import DNS, DNSQR
import base64
import hashlib
import traceback
from typing import Union
import textwrap
import time

# Useful links:
# Built in types: https://docs.python.org/3/library/stdtypes.html
# Base64: https://docs.python.org/3/library/base64.html
# Socket: https://docs.python.org/3/library/socket.html
# Scapy: https://scapy.readthedocs.io/en/latest/api/scapy.html
# Hashlib: https://docs.python.org/3/library/hashlib.html

class Message:
    def __init__(self, data: str, seq_nr: int):
        self.data = data
        self.seq_nr = seq_nr # Number in a sequence of chunks
    

class DNSBuffer:
    def __init__(self, msgs: list[Message]|None, max_size: int = 0):
        if msgs is None:
            self.msgs = []
        else:
            self.msgs = msgs
        if max_size == 0:
            self.max_size = len(self.msgs)
        else:
            self.max_size = max_size
        self.all_sent = True
        self.issorted = False
    
    def append(self, msg: Message):
        if self.isFull():
            raise Exception("Buffer is full")
        
        self.msgs.append(msg)
        self.issorted = False
    
    def isFull(self) -> bool:
        return self.max_size == len(self.msgs)

    def sort(self):
        if not self.issorted:
             self.msgs.sort(key=lambda msg: msg.seq_nr)
             self.issorted = True

    def get_missing_msgs(self) -> list[int]:
        missing_msgs = []
        self.sort()

        for msg_i in range(len(self.msgs) - 1):
            if self.msgs[msg_i + 1].seq_nr - self.msgs[msg_i].seq_nr >= 2:
                missing_msgs.extend([j for j in range(self.msgs[msg_i].seq_nr, self.msgs[msg_i + 1].seq_nr)])
        return missing_msgs
    
    def get_resend_domain(self) -> str:
        global MAX_LABEL_SIZE

        missing_msgs_b64 = base64.b64encode(self.get_resend_str().encode()).decode('ascii')
        return ".".join(textwrap.wrap(missing_msgs_b64, MAX_LABEL_SIZE))
    
    def get_resend_str(self) -> str:
        missing_msgs = self.get_missing_msgs()
        return "_".join([str(res) for res in missing_msgs])
    
    def get_assembled_packets(self) -> str:
        self.sort()
        return "".join([msg.data for msg in self.msgs])
                

class HTTPBuffer:
    def __init__(self, msgs: list[Message]|None, resends: list[int]|None):
        if msgs is None:
            self.msgs = []
        else:
            self.msgs = msgs
        if resends is None:
            self.resends = []
        else:
            self.resends = resends
    
    @classmethod
    def from_bytes(cls, data: bytes, chunk_size: int):
        str_msgs = textwrap.wrap(base64.b64encode(data).decode('ascii'), chunk_size)
        return HTTPBuffer(str_list_to_msgs(str_msgs), None)
    

class RemoteConn:
    def __init__(self, rem_sock_id: int, rem_addr: tuple[str, int],  rem_sock: socket.socket, client_rem_sock_id: int = 0):
        self.rem_sock_id = rem_sock_id
        self.rem_addr = rem_addr
        self.rem_sock = rem_sock
        self.client_rem_sock_id = client_rem_sock_id
        self.http_buffer = HTTPBuffer(None, None) # Used for potential needed re-sends
        self.dns_buffer = DNSBuffer(None) # Used for assembling received dns packets
        self.wait_resp = False # Something like a condition var, waiting for a response or not
    
    # Sends the data in the buffer and empties it
    def send(self):
        # If everything was sent, let the other one know nothing needs to be resent
        if self.dns_buffer.all_sent:
            send_dns_req(f"{RESEND_MSG}.{self.client_rem_sock_id}")
            return

        # No msg missing -> assemble message, decode and forward
        if self.dns_buffer.isFull():
            sorted_msgs = self.dns_buffer.get_assembled_packets()
            decoded_http_req = myB64Decode(sorted_msgs)
            # print(decoded_http_req.decode(errors='ignore'))
            self.rem_sock.sendall(decoded_http_req)
            self.dns_buffer = DNSBuffer(None)

            send_dns_req(f"{RESEND_MSG}.{self.client_rem_sock_id}")
            print(f"[+] Socket {self.rem_sock_id}: Sent HTTP request")
        else: # Otherwise ask for missing packets
            missing_msgs_dom = self.dns_buffer.get_resend_domain()
            send_dns_req(f"{RESEND_MSG}.{self.client_rem_sock_id}.{missing_msgs_dom}")
            print(f"[+] Socket {self.rem_sock_id}: Missing {missing_msgs_dom}")
    
    def __del__(self):
        self.rem_sock.close()

SOCKS_VERSION = 5

DNS_SERVER_IP = '34.159.249.73'
# DNS_SERVER_IP = '8.8.8.8' THIS SHOULD BE USED
DNS_SERVER_PORT = 53
BASE_DOMAIN = "vilgax.crabdance.com"
BASE_DOM_NAME_COUNT = len(BASE_DOMAIN.split('.'))
dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_socket.settimeout(100)
DNS_PACKET_ID = 0xAAAA

SOCK_SERVER_PORT = 1080
SOCK_SERVER_IP = '127.0.0.1'

# Operations that will be done by the dns server
CREATE_CONN = 1 # Query: cmd.port.addr
CONSTRUCT_MSG = 2 # Query: cmd.remote_sock_id.chunk_count.chunk_index.enc_http_req_hash.encoded_http_req
SEND_MSG = 3 # Query: cmd.remote_sock_id
RESEND_MSG = 4 # Query cmd.remote_sock_id.chunk-index0_chunk-index1....

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

# domain should be a str like chunki1_chunki2_..._chunkin
# Returned is a list containg all chunk indexes
def str_to_resend(domain: str) -> list[int]:
   if not domain:
       return []
   return [int(chunk_i) for chunk_i in domain]

def str_list_to_msgs(strs: list[str]) -> list[Message]:
    return [Message(s, i) for i, s in enumerate(strs)]

def myB64Decode(data: str):
    needed_pad = 4 - (len(data) % 4)
    data += '=' * needed_pad
    return base64.b64decode(data)


def hashData(data: bytes) -> bytes:
    md5 = hashlib.md5()
    md5.update(data)
    return md5.digest()

def checkHash(data: bytes, d_hash: bytes) -> bool:
    return hashData(data) == d_hash

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
    conn_dict[rem_sock_id_counter] = RemoteConn(rem_sock_id_counter, (req_addr, req_port), rem_sock)
    rem_sock_id_counter += 1

    return conn_dict[rem_sock_id_counter - 1]

# Adds ".{BASE_DOMAIN}" to domain and sends the request
def send_dns_req(domain: str):
    global dns_socket, DNS_SERVER_IP, DNS_SERVER_PORT, DNS_PACKET_ID

    domain += f".{BASE_DOMAIN}"
    dns_query = bytes(DNS(id=DNS_PACKET_ID, rd=1, qd=DNSQR(qname=domain, qtype="TXT")))
    dns_socket.sendto(dns_query, (DNS_SERVER_IP, DNS_SERVER_PORT))

# Encodes http req in base64 and sends it to the DNS server in chunks
def send_http_msg(rem_conn: RemoteConn):
    global CONSTRUCT_MSG, MAX_LABEL_SIZE, MAX_HTTP_SIZE

    # Nothing to do
    if not len(rem_conn.http_buffer.msgs):
        return
    
    # Send chunks via DNS
    for chunk in rem_conn.http_buffer.msgs:
        chunk_hash = base64.b64encode(hashData(chunk.data.encode('ascii'))).decode('ascii')
        send_dns_req(f"""{CONSTRUCT_MSG}.{rem_conn.client_rem_sock_id}.{len(rem_conn.http_buffer.msgs)}.{chunk.seq_nr}.{chunk_hash}.{chunk.data}""")
        print(f"[+] HTTP chunk {chunk.seq_nr} sent")

    # Tell the server to forward the completed message until it gets a response, or number of retries runs out
    rem_conn.wait_resp = True
    rem_retries = 5
    while rem_conn.wait_resp and rem_retries:
        send_dns_req(f'{SEND_MSG}.{rem_conn.client_rem_sock_id}')
        print(f"[+] HTTP message completely sent(remaining retries {rem_retries})")
        rem_retries -= 1
        time.sleep(1)

    # (might) need to re-send chunks, set http buffer to only contain resends msgs for the next send
    if len(rem_conn.http_buffer.resends):
        resend_msg = [rem_conn.http_buffer.msgs[i] for i in rem_conn.http_buffer.resends]
        rem_conn.http_buffer = HTTPBuffer(resend_msg, None)

        print(f"[+] Resending chunks: {rem_conn.http_buffer.resends}")
        send_http_msg(rem_conn)


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
            threading.Thread(target=forward_to_dns, args=(chosen_rem_sock,)).start()
        elif cmd == CONSTRUCT_MSG:
            chunk_count, chunk_index, encoded_hash = int(label_parts[2]), int(label_parts[3]), label_parts[4]
            encoded_msg = "".join([enc_msg.decode('ascii') for enc_msg in proc_dns_resp(dns_packet)])

            if not checkHash(encoded_msg.encode('ascii'), myB64Decode(encoded_hash)):
                print(f"[WARNING] Socket {rem_sock_id}: Dropping packet {chunk_index}")
                return
            
            # print(base64.b64decode(encoded_msg).decode(errors='ignore'))
            msg = Message(encoded_msg, chunk_index)

            # Set the chunk count if needed, add the message to the buffer
            if chosen_rem_sock.dns_buffer.max_size == 0:
                chosen_rem_sock.dns_buffer.max_size = chunk_count
                chosen_rem_sock.dns_buffer.all_sent = False
            chosen_rem_sock.dns_buffer.append(msg)

            print(f"[+] Socket {rem_sock_id}: Adding {len(encoded_msg)}")
        elif cmd == SEND_MSG:
            # Decode http request and send to the browser
            chosen_rem_sock.send()
            print(f"[+] Socket {rem_sock_id}: Sent HTTP request")
        elif cmd == RESEND_MSG:
            resends = proc_dns_resp(dns_packet, True).decode()
            
            # Set resends and signal to the waiting thread that a response was received
            chosen_rem_sock.http_buffer.resends = str_to_resend(resends)
            chosen_rem_sock.wait_resp = False
        else:
            print(f"[ERROR] Invalid command: {cmd}")
    else:
        print("[ERROR] Invalid DNS packet")

def forward_to_dns(rem_conn: RemoteConn):
    global dns_socket, MAX_LABEL_SIZE

    try:
        while True:
            data = rem_conn.rem_sock.recv(MAX_HTTP_SIZE)
            
            if not data:
                print(f"[+] Socket {rem_conn.rem_sock_id}: No more data")
                break

            # Encode http msg in base64, split it and send it
            rem_conn.http_buffer = HTTPBuffer.from_bytes(data, MAX_LABEL_SIZE)
            send_http_msg(rem_conn)
    except Exception as e:
        print(f"[ERROR] Socket {rem_conn.rem_sock_id}: {traceback.format_exc()}")

    print(f"[+] Socket {rem_conn.rem_sock_id}: Closing connection to remote {rem_conn.rem_sock.getsockname()}")

def forward_from_dns():
    global dns_socket
   
    while True:
        data, server_addr = dns_socket.recvfrom(MAX_UDP_SIZE)
        print(f"[+] Sizeof DNS resp: {len(data)}")

        if server_addr[0] != DNS_SERVER_IP:
            print(f"[WARNING] Received UDP packet from unknown server: {server_addr}")
            continue
        try:
            handle_dns_resp(data)
        except Exception as e:
            print(f"[ERROR] Handling DNS response: {traceback.format_exc()}")

    print("[+] Closing DNS connection")

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

def main():
    global DNS_SERVER_IP, DNS_SERVER_PORT
    
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

    while True:
        serv_sock, addr = sock.accept()
        print(f"[+] Accepted a new connection: {addr}")
        # threading.Thread(target=handle_client, args=(serv_sock,)).start()
        try:
            handle_client(serv_sock)
        except Exception as e:
            print(f"[+] Exception handing client {addr}: {traceback.format_exc()}")
