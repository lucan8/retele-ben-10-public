# TCP client
import socket
import logging
import time
import sys
import random

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
name = 'server'
adresa = '198.7.0.2'
server_address = (adresa, port)

logging.info('Handshake cu %s', str(server_address))
sock.connect(server_address)

while True:
    mesaj = f"The secret number is: {random.randint(0, 25)}"
    try:
        sock.send(mesaj.encode('utf-8'))
        data = sock.recv(1024)
        logging.info('Content primit: "%s"', data)
    except:
        logging.info('Closing socket')
        sock.close()
        break
    time.sleep(3)
