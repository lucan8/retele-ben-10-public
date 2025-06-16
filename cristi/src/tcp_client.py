# TCP client
import socket
import logging
import time
import sys
import random

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname) -8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

def set_conn():
    port = 10000
    name = 'server'
    address = '198.7.0.2'
    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

    # Make the address be reused instantly
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    logging.info('Handshake with %s', str(server_address))
    sock.connect(server_address)

    return sock

sock = set_conn()
while True:
    message = f"The secret number is: {random.randint(0, 25)}"
    try:
        sock.send(message.encode('utf-8'))
        data = sock.recv(1024)
        logging.info('Content received: "%s"', data)
    except ConnectionResetError:
        logging.info("Connection forcefully closed")
        logging.info("Reestablishing connection...")
        sock.close()
        sock = set_conn()
    except KeyboardInterrupt:
        sock.close()
        logging.info("Closing connection")
        break

    time.sleep(3)
