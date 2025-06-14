import socket
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, Raw, conf, sr1, Packet

# Code inspired by the DNS resolver from the course

UPSTREAM_DNS_SERVER = "8.8.8.8"
BLOCKED_LOG_FILE = "blocked_dns_requests.log"

def init_blacklist():
    """
    Loads a list of known ad domains from provided files
    """

    blacklist_files  = ["facebook.txt", "adservers.txt"]
    blocked = []
    for path in blacklist_files: 
        with open(path, "r") as file:
            for line in file:
                if line[0] == '#':
                    continue

                line = line.strip()
                args = line.split(" ")
                blocked.append(args[1].lower())
        print(f"Loaded data from {path}...")

    return blocked

blacklist = init_blacklist()

def is_domain_blocked(domain):
    domain = domain.lower()
    if domain in blacklist:
        return True

    # We are also going to check if perhaps
    # the blocked domain is a subdomain of the whole domain
    parts = domain.split('.')
    for i in range(len(parts)):
        sub_domain = ".".join(parts[i:])
        if sub_domain in blacklist:
            return True
    return False

def handle_dns_query(data, client_address, udp_socket):
        dns_packet = DNS(data)

        # .qr specifies what kind of packet this is
        # 1 means it is a response packet 0 means it is a query packet
        # Question domain also needs to be present otherwise there
        # is nothing to block
        if dns_packet.qr == 0 and dns_packet.qd:
            query_name = dns_packet.qd.qname.decode('utf-8').rstrip('.')
            print(f"Received DNS query for: {query_name}")

            if is_domain_blocked(query_name):
                print(f"Blocking DNS query for: {query_name}")
                with open(BLOCKED_LOG_FILE, "a") as file:
                    file.write(f"BLOCKED: {query_name}\n")

                response = DNS(
                    id=dns_packet.id,
                    qr=1,      # This is a response
                    aa=1,      # Authoritative Answer (we are acting as one for blocked domains)
                    rd=dns_packet.rd, # Recursion Desired (match original)
                    ra=1,      # Recursion Available (we can recurse or provide definitive answer)
                    qd=dns_packet.qd, # Original Question Section
                    an=DNSRR(rrname=dns_packet.qd.qname, type='A', rdata='0.0.0.0', ttl=3600)
                )
                udp_socket.sendto(bytes(response), client_address)
                print(f"Sent blocked response for {query_name}")
            else:
                print(f"Forwarding DNS query for: {query_name}")

                # send and receive 1 packet
                upstream_response_packet = sr1(
                    IP(dst=UPSTREAM_DNS_SERVER) /
                    UDP(dport=53, sport=client_address[1]) /
                    dns_packet,
                    timeout=2, verbose=0
                )

                if upstream_response_packet and upstream_response_packet.haslayer(DNS):
                    response_data = bytes(upstream_response_packet[DNS])
                    udp_socket.sendto(response_data, client_address)
                    print(f"Forwarded legitimate response for {query_name} to {client_address[0]}")
                else:
                    print(f"No valid DNS response from upstream for {query_name}")

def main():
    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    dns_socket.bind(('0.0.0.0', 53))
    print(f"Listening for DNS queries on UDP port 53 (0.0.0.0)...")

    while True:
        data, client_address = dns_socket.recvfrom(512)
        handle_dns_query(data, client_address, dns_socket)

    dns_socket.close()

if __name__ == "__main__":
    main()
