import socket
import threading
from scapy.all import DNS, DNSQR, DNSRR
import base64

class RemoteSock:
    def __init__(self, rem_sock: socket.socket):
        self.rem_sock = rem_sock
        self.buffer = []

    def add_to_buffer(self, message: bytes):
        self.buffer.extend(message)
    
# TODO: Use a new thread for each message receive
    
BASE_DOMAIN = "vilgax.crabdance.com"
BASE_DOM_NAME_COUNT = len(BASE_DOMAIN.split('.'))
DNS_SERVER_PORT = 53
DNS_SERVER_IP = '0.0.0.0'
MESSAGE_SIZE = 200

# id - socket
rem_sock_dict = {}
rem_sock_id_counter = 1

TEST_ADDR = ("www.google.com", 443)

# Operations that will be done by the dns server

CREATE_CONN = 1 # Query: cmd.port.addr
CONSTRUCT_REQ = 2 # Query: cmd.remote_sock_id.encoded_http_req
SEND_REQ = 3 # Query: cmd.remote_sock_id

def forward_from_proxy():
    ...
def forward_to_proxy():
    ...

def build_dns_resp(dns_req: DNS, msg: str) -> DNS:
    return DNS(
                id=dns_req.id,
                qr=1,
                aa=1,
                qd=dns_req.qd,
                an=DNSRR(
                    rrname=dns_req.qd.qname,
                    type="TXT",
                    ttl=60,
                    rdata= base64.b64encode(msg.encode()).decode()
                )
            )

def handle_dns_query(data: bytes, client_addr: tuple[bytes, int]):
    global BASE_DOM_NAME_COUNT, rem_sock_dict, rem_sock_id_counter, dns_socket
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
                req_port, req_addr = int(label_parts[1]), '.'.join(label_parts[2:len(label_parts) - 3])
            else:
                req_port, req_addr = int(label_parts[1]), '.'.join(label_parts[2:])

            # Connect to the one the client wants to connect
            print(f"[+] Attempting connection to {req_addr}:{req_port}")
            remote_sock = socket.create_connection((req_addr, req_port))

            remote_bind_addr = remote_sock.getsockname()
            print(f"[+] Connection successful {remote_bind_addr}")

            # Add connection to the dictionary
            # TODO: Group this operation in a locked function
            rem_sock_dict[rem_sock_id_counter] = RemoteSock(remote_sock)
            rem_sock_id_counter += 1

            print(f"[+] Socket {rem_sock_id_counter}: Created")

            # Send the remote sock id back to the client
            dns_socket.sendto(bytes(build_dns_resp(dns_packet, str(rem_sock_id_counter - 1))), client_addr)
        elif cmd == CONSTRUCT_REQ:
            # Quick fix until dns server is set up
            if "vilgax" in query_name:
                rem_sock_id, encoded_msg = int(label_parts[1]), label_parts[2:len(label_parts) - 3]
            else:
                rem_sock_id, encoded_msg = int(label_parts[1]), label_parts[2:]
            
            if rem_sock_id not in rem_sock_dict:
                print("[ERROR] FORWARD before CREATE_CONN")
                return
            
            # Add partial encoded request to buffer
            chosen_rem_sock = rem_sock_dict[rem_sock_id]
            chosem_rem_sock.add_to_buffer(encoded_msg)

            print(f"[+] Socket {rem_sock_id}: Adding {len(encoded_msg)}")
    elif cmd == SEND_REQ:
        rem_sock_id = int(label_parts[1])
        
        if rem_sock_id not in rem_sock_dict:
            print("[ERROR] SEND_REQ before CREATE_CONN")
            return
        
        # Decode http request and send to the browser
        chosen_rem_sock = rem_sock_dict[rem_sock_id]
        decoded_http_req = base64.b64decode(chosen_rem_sock.buffer)
        chosen_rem_sock.sendall(decoded_http_req)

        print(f"[+] Socket {rem_sock_id}: Sent HTTP request")
        
dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_socket.bind((DNS_SERVER_IP, DNS_SERVER_PORT))
print(f"Listening for DNS queries on interface ({DNS_SERVER_IP}):{DNS_SERVER_PORT}...")

# Test connection
print(f"[+] Testing connenction to {TEST_ADDR}")
socket.create_connection(TEST_ADDR)
print(f"[+] Connection successful")

while True:
    data, client_addr = dns_socket.recvfrom(MESSAGE_SIZE)
    try:
        print(f"[+] Received request from {client_addr}")
        handle_dns_query(data, client_addr)
    except Exception as e:
        print(f"[+]ERROR: Handling req from {client_addr}, data: {data}: {e}")

dns_socket.close()