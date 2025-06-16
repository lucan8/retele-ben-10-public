import socket
import base64
import hashlib
from scapy.all import DNS, DNSQR

SERVER_IP = "164.92.244.69"
PORT = 53
BASE_DOMAIN = "vilgax.crabdance.com"

def file_md5(path):
    md5 = hashlib.md5()

    with open(path, "rb") as file:
        chunk = file.read(4096)
        while chunk:
            md5.update(chunk)
            chunk = file.read(4096)

    return md5.hexdigest()


def get_md5(sock, file_name):
    domain = f"md5.{file_name}.{BASE_DOMAIN}"
    dns_query = DNS(id=0xAAAA, rd=1, qd=DNSQR(qname=domain, qtype="TXT"))

    sock.sendto(bytes(dns_query), (SERVER_IP, PORT))

    data, _ = sock.recvfrom(512)
    response = DNS(data)

    rr = response.an[0]

    # TXT record is encoded as 16
    md5_hash = ""
    if rr.type == 16:
        md5_hash = rr.rdata
        md5_hash = b''.join(md5_hash).decode()

    return md5_hash



def get_whole_file(sock, file_name):
    """
    based on the socket connection this will try to ask for all the chunks
    of the file and if it manages to retrieve all files it will return 'true'
    else 'false'.
    """
    chunks = []
    chunk_index = 0

    while True:
        domain = f"chunk{chunk_index}.{file_name}.{BASE_DOMAIN}"
        dns_query = DNS(id=0xAAAA, rd=1, qd=DNSQR(qname=domain, qtype="TXT"))

        sock.sendto(bytes(dns_query), (SERVER_IP, PORT))

        try:
            data, _ = sock.recvfrom(512)
            response = DNS(data)

            rr = response.an[0]

            # TXT record is encoded as 16
            if rr.type != 16:
                continue

            txt_data = rr.rdata
            txt_data = b''.join(txt_data).decode()
            txt_data = base64.b64decode(txt_data)

            print(f"Received chunk {chunk_index}")

            if txt_data.decode() == "EOF":
                print("EOF")
                break

            chunks.append(txt_data)
            chunk_index += 1

        except socket.timeout:
            print(f"Request timed out on chunk {chunk_index}.")
            break

    if not chunks:
        return False

    # Save the file
    print()
    print("Saving the file...")

    file_bytes = b"".join(chunks)

    with open(file_name, "wb") as file:
        file.write(file_bytes)
    print(f"File '{file_name}' saved!")

    return True


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    file_name = "ben10"
    get_whole_file(sock, file_name)
    print()

    # check if md5 hash match
    server_md5 = get_md5(sock, file_name)
    print("Received MD5 from the server:", server_md5)

    local_md5 = file_md5(file_name)

    if server_md5 != local_md5:
        print("MD5 hashes don't match, your local file is corrputed")
        print(f"Expected '{server_md5}' but got '{local_md5}")
    else:
        print(f"MD5 hashes match they are {server_md5}")


if __name__ == "__main__":
    main()
