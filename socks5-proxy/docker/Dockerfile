FROM python:3.9-slim

# Install any dependencies (like scapy)
RUN apt-get update && apt-get install -y \
    tcpdump dnsutils vim procps psmisc htop procps iproute2 net-tools

RUN pip install scapy
RUN  apt-get clean

WORKDIR /elocal

COPY server.py /elocal/server.py

EXPOSE 49152/udp

CMD ["python3", "-u", "server.py"]
