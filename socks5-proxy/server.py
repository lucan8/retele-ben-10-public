import socket
import threading
from scapy.all import DNS, DNSQR, DNSRR
import base64
from typing import Union
import traceback
import textwrap
import hashlib
import time

# FIRST THING TO CHECK WHEN PACKETS DON'T ARRIVE IS IF THE CLIENT'S IP CHANGED
class Message:
    def __init__(self, data: str, seq_nr: int):
        self.data = data
        self.seq_nr = seq_nr # Number in a sequence of chunks
    
class DNSBuffer:
    def __init__(self, msgs: Union[list[Message], None], max_size: int = 0):
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
    def __init__(self, msgs: Union[list[Message], None], resends: Union[list[int], None]):
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
            send_fake_dns_resp(f"{RESEND_MSG}.{self.client_rem_sock_id}", '')
            return

        # full dns buffer -> assemble messages, decode and forward
        if self.dns_buffer.isFull():
            sorted_msgs = self.dns_buffer.get_assembled_packets()
            # print(f"[+] Socket {self.rem_sock_id}: {sorted_msgs}")
            decoded_http_req = myB64Decode(sorted_msgs)
            # print(decoded_http_req.decode(errors='ignore'))
            self.rem_sock.sendall(decoded_http_req)
            self.dns_buffer = DNSBuffer(None)

            send_fake_dns_resp(f"{RESEND_MSG}.{self.client_rem_sock_id}", '')
            print(f"[+] Socket {self.rem_sock_id}: Sent HTTP request to {self.rem_sock.getsockname()}")
        else: # Otherwise ask for missing messages
            missing_msgs_str = self.dns_buffer.get_resend_str()
            send_fake_dns_resp(f"{RESEND_MSG}.{self.client_rem_sock_id}", missing_msgs_str.encode())
            print(f"[+] Socket {self.rem_sock_id}: Missing {missing_msgs_str}")
    
    def __del__(self):
        self.rem_sock.close()

BASE_DOMAIN = "vilgax.crabdance.com"
BASE_DOM_NAME_COUNT = len(BASE_DOMAIN.split('.'))
DNS_SERVER_PORT = 53
DNS_SERVER_IP = '0.0.0.0'
MESSAGE_SIZE = 200
MAX_LABEL_SIZE = 60 # Make sure it's multiple of 4
DNS_PACKET_ID = 0xAAAA
DNS_QTYPE = "TXT"
MAX_HTTP_SIZE = 4096
MAX_UDP_SIZE = 512
CLIENT_IP = "81.196.154.163"
CLIENT_PORT = None

# remote_sock_id - RemoteConn
conn_dict = {}
rem_sock_id_counter = 1

TEST_ADDR = ("www.google.com", 443)

# Operations that will be done by the dns server

# Operations that will be done by the dns server
CREATE_CONN = 1 # Query: cmd.port.addr
CONSTRUCT_MSG = 2 # Query: cmd.remote_sock_id.chunk_count.chunk_index.encoded_http_req
SEND_MSG = 3 # Query: cmd.remote_sock_id
RESEND_MSG = 4 # Query cmd.remote_sock_id.chunk-index0_chunk-index1....

# domain should be a str like chunki1_chunki2_..._chunkin
# Returned is a list containg all chunk indexes
def str_to_resend(domain: str) -> list[int]:
    if not domain:
        return []
    return [int(chunk_i) for chunk_i in domain.split('_')]

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

def send_dns_resp(dns_req: DNS, msg: Union[bytes, str]):
    global dns_socket
    dns_socket.sendto(bytes(build_dns_resp(dns_req, msg)), (CLIENT_IP, CLIENT_PORT))

def send_fake_dns_resp(domain: str, msg: Union[bytes, str]):
    global dns_socket
    dns_socket.sendto(bytes(build_fake_dns_resp(domain, msg)), (CLIENT_IP, CLIENT_PORT))

# Actually responds to dns_req
# If msg is str, the function assumes it is already encoded in base64, otherwise it encodes it
def build_dns_resp(dns_req: DNS, msg: Union[bytes, str]) -> DNS:
    global DNS_QTYPE
    
    if isinstance(msg, bytes):
        msg = base64.b64encode(msg).decode('ascii')

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
        msg = base64.b64encode(msg).decode('ascii')

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

def create_conn(rem_sock: socket.socket, dns_packet: DNS, rem_addr: tuple[str, int], client_rem_sock_id: int) -> RemoteConn:
    global rem_sock_id_counter

    send_dns_resp(dns_packet, (rem_sock_id_counter).to_bytes(4, 'big'))
    conn_dict[rem_sock_id_counter] = RemoteConn(rem_sock_id_counter, rem_addr, rem_sock, client_rem_sock_id)
    rem_sock_id_counter += 1

    return conn_dict[rem_sock_id_counter - 1]

def forward_to_dns(rem_conn: RemoteConn):
    global dns_socket, MAX_HTTP_SIZE, MESSAGE_SIZE

    try:
        while True:
            data = rem_conn.rem_sock.recv(MAX_HTTP_SIZE)
            
            if not data:
                print(f"[+] Socket {rem_conn.rem_sock_id}: No more data")
                break

            # print(data)
            # Encode http msg in base64, split it and send it
            rem_conn.http_buffer = HTTPBuffer.from_bytes(data, MESSAGE_SIZE)
            send_http_msg(rem_conn)
    except Exception as e:
        print(f"[ERROR] Socket {rem_conn.rem_sock_id}: {traceback.format_exc()}")

    print(f"[+] Socket {rem_conn.rem_sock_id}: Closing connection to remote {rem_conn.rem_sock.getsockname()}")

def forward_from_dns():
    global dns_socket, CLIENT_IP, CLIENT_PORT
   
    while True:
        data, client_addr = dns_socket.recvfrom(MAX_UDP_SIZE)
        print(f"[+] Sizeof DNS query: {len(data)}")

        if client_addr[0] != CLIENT_IP:
            print(f"[WARNING] Received UDP packet from unknown client: {client_addr}")
            continue

        CLIENT_PORT = client_addr[1]
        try:
            handle_dns_query(data)
        except Exception as e:
            print(f"[ERROR] Handling DNS query: {traceback.format_exc()}")

    print("[+] Closing DNS connection")

# Encodes http req in base64 and sends it to the DNS server in chunks
def send_http_msg(rem_conn: RemoteConn):
    global CONSTRUCT_MSG, MESSAGE_SIZE, CLIENT_IP, CLIENT_PORT

    # Nothing to do
    if not len(rem_conn.http_buffer.msgs):
        return
    
    # Send chunks via DNS
    for chunk in rem_conn.http_buffer.msgs:
        chunk_hash =  base64.b64encode(hashData(chunk.data.encode('ascii'))).decode('ascii')
        send_fake_dns_resp(f"""{CONSTRUCT_MSG}.{rem_conn.client_rem_sock_id}.{len(rem_conn.http_buffer.msgs)}.{chunk.seq_nr}.{chunk_hash}""", chunk.data)
        print(f"[+] HTTP chunk {chunk.seq_nr} sent")

    # Tell the server to forward the completed message until it gets a response
    rem_conn.wait_resp = True
    rem_retries = 5
    while rem_conn.wait_resp and rem_retries:
        send_fake_dns_resp(f'{SEND_MSG}.{rem_conn.client_rem_sock_id}', "")
        print(f"[+] HTTP message completely sent(remaining retries {rem_retries})")
        rem_retries -= 1
        time.sleep(1)

    # (might) need to re-send chunks, set http buffer to only contain resends msgs for the next send
    if len(rem_conn.http_buffer.resends):
        resend_msg = [rem_conn.http_buffer.msgs[i] for i in rem_conn.http_buffer.resends]
        rem_conn.http_buffer = HTTPBuffer(resend_msg, None)

        print(f"[+] Resending chunks: {rem_conn.http_buffer.resends}")
        send_http_msg(rem_conn)

def handle_dns_query(data: bytes):
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
                client_rem_sock_id, req_port, req_addr = int(label_parts[1]), int(label_parts[2]), '.'.join(label_parts[3:len(label_parts) - BASE_DOM_NAME_COUNT])
            else:
                client_rem_sock_id, req_port, req_addr = int(label_parts[1]), int(label_parts[2]), '.'.join(label_parts[3:])

            # Connect to the one the client wants to connect
            print(f"[+] Attempting connection to {req_addr}:{req_port}")
            remote_sock = socket.create_connection((req_addr, req_port))

            remote_bind_addr = remote_sock.getsockname()
            print(f"[+] Connection successful {remote_bind_addr}")

            # Finalize connection to client by sending our remote socket id
            create_conn(remote_sock, dns_packet, (req_addr, req_port), client_rem_sock_id)
            print(f"[+] Socket {rem_sock_id_counter - 1}: Created")

            # Keep conversation going between remote and DNS socket
            threading.Thread(target=forward_to_dns, args=(conn_dict[rem_sock_id_counter - 1],)).start()
        elif cmd == CONSTRUCT_MSG:
            rem_sock_id, chunk_count, chunk_index = int(label_parts[1]), int(label_parts[2]), int(label_parts[3])
            encoded_hash, encoded_msg = label_parts[4], label_parts[5]
            
            if rem_sock_id not in conn_dict:
                print(f"[ERROR] Socket {rem_sock_id}: CONSTRUCT_MSG before CREATE_CONN")
                return
            
            if not checkHash(encoded_msg.encode('ascii'), myB64Decode(encoded_hash)):
                print(f"[WARNING] Socket {rem_sock_id}: Dropping packet {chunk_index}")
                return
            
            # print(base64.b64decode(encoded_msg).decode(errors='ignore'))
            # Add partial encoded request to buffer
            chosen_rem_sock = conn_dict[rem_sock_id]
            msg = Message(encoded_msg, chunk_index)

            # Set the chunk count if needed add the message to the buffer
            if chosen_rem_sock.dns_buffer.max_size == 0:
                chosen_rem_sock.dns_buffer.max_size = chunk_count
                chosen_rem_sock.dns_buffer.all_sent = False
            chosen_rem_sock.dns_buffer.append(msg)

            print(f"[+] Socket {rem_sock_id}: Adding {len(encoded_msg)}")
        elif cmd == SEND_MSG:
            rem_sock_id = int(label_parts[1])
            
            if rem_sock_id not in conn_dict:
                print(f"[ERROR] Socket {rem_sock_id}: SEND_MSG before CREATE_CONN")
                return
            
            # Decode http request and send to the browser
            chosen_rem_sock = conn_dict[rem_sock_id]
            chosen_rem_sock.send()
        elif cmd == RESEND_MSG:
            rem_sock_id = int(label_parts[1])

            if rem_sock_id not in conn_dict:
                print(f"[ERROR] Socket {rem_sock_id}: RESEND_MSG before CREATE_CONN")
                return
            chosen_rem_sock = conn_dict[rem_sock_id]

            # Quick fix until dns server is set up
            if "vilgax" in query_name:
                resend_chunks = ''.join(label_parts[2:len(label_parts) - BASE_DOM_NAME_COUNT])
            else:
                resend_chunks = ''.join(label_parts[2:])

            # Set resends and signal to the waiting thread that a response was received
            chosen_rem_sock.http_buffer.resends = str_to_resend(myB64Decode(resend_chunks).decode())
            chosen_rem_sock.wait_resp = False
        else:
            print(f"[ERROR] Invalid command: {cmd}")
    else:
        print("[ERROR] Invalid DNS packet")

def main():
    global DNS_SERVER_IP, DNS_SERVER_PORT, TEST_ADDR
    print(f"Listening for DNS queries on interface ({DNS_SERVER_IP}):{DNS_SERVER_PORT}...")    
    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.bind((DNS_SERVER_IP, DNS_SERVER_PORT))
    forward_from_dns()

    # Test connection
    # print(f"[+] Testing connenction to {TEST_ADDR}")
    # socket.create_connection(TEST_ADDR)
    # print(f"[+] Connection successful")

main()