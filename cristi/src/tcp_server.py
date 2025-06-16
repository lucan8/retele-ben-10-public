# TCP Server
import socket
import logging
import time

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname) -8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

def set_conn():
    port = 10000
    name = "server"
    address = '198.7.0.2'
    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind(server_address)
    logging.info("Server started on %s, port %d", address, port)

    sock.listen(5)
    logging.info('Waiting for connections...')

    conn, address = sock.accept()
    logging.info("Handshake with %s", address)

    return conn, sock

conn, sock = set_conn()

while True:
    try:
        data = conn.recv(1024)
        logging.info('Content rerceived: "%s"', data)
        conn.send(b"Server received message: " + data)
    except ConnectionResetError:
        logging.info("Connection forcefully closed")
        logging.info("Reestablishing connection...")
        sock.close()
        conn, sock = set_conn()
    except KeyboardInterrupt:
        sock.close()
        logging.info("Server is closing")
        break
