import socket
import base64
import hashlib
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR

def file_md5(path):
    md5 = hashlib.md5()

    with open(path, "rb") as file:
        chunk = file.read(4096)
        while chunk:
            md5.update(chunk)
            chunk = file.read(4096)

    return md5.hexdigest()

# According to google a record of type text
# can hold up to 255 bytes, 200 should be safe
CHUNK_SIZE = 200

def handle_dns_query(data, client_address, udp_socket):
    dns_packet = DNS(data)

    # .qr specifies what kind of packet this is
    # 1 means it is a response packet 0 means it is a query packet
    # Question domain also needs to be present otherwise there
    # is nothing to block
    if dns_packet.qr == 0 and dns_packet.qd:
        query_name = dns_packet[DNSQR].qname.decode().rstrip('.')
        label_parts = query_name.split('.')

        # Expect queries like: chunk0.file.txt.vilgax.crabdance.com
        if len(label_parts) < 2:
            print(f"Invalid query: {query_name}")
            return

        # e.g. chunk0
        # sometimes instead of the chunk
        # we could get md5 which means that
        # the user requests the md5 of the file
        chunk_label = label_parts[0]

        # e.g. file.txt
        filename = label_parts[1]

        response_txt = None
        if chunk_label == "md5":
            print(f"[+] Received request for md5 hash of file {filename}")
            response_txt = file_md5(filename)
            print(f"MD5 of file {filename} is = {response_txt}")
        elif chunk_label.startswith("chunk"):
            chunk_index = int(chunk_label[5:])
            print(f"[+] Received request for chunk {chunk_index} of file {filename}")

            with open(filename, "rb") as f:
                f.seek(chunk_index * CHUNK_SIZE)
                chunk_data = f.read(CHUNK_SIZE)

            if chunk_data:
                b64_chunk = base64.b64encode(chunk_data).decode()
                response_txt = b64_chunk
            else:
                # Send EOF if no more data or file not found
                b64_chunk = base64.b64encode(b"EOF").decode()
                response_txt = b64_chunk
        else:
            print(f"Unsupported query label: {chunk_label}")
            return


        response = DNS(
            id=dns_packet.id,
            qr=1,
            aa=1,
            qd=dns_packet.qd,
            an=DNSRR(
                rrname=dns_packet.qd.qname,
                type="TXT",
                ttl=60,
                rdata=response_txt
            )
        )

        udp_socket.sendto(bytes(response), client_address)
        print(f"Sent chunk response")

def main():
    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.bind(('0.0.0.0', 53))
    print("Listening for DNS queries on UDP port 53 (0.0.0.0)...")

    while True:
        data, client_address = dns_socket.recvfrom(512)
        handle_dns_query(data, client_address, dns_socket)

    dns_socket.close()

if __name__ == "__main__":
    main()
