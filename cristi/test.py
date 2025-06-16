import socket
import requests
region_sites_ips = {
    "Asia": [
        ("www.iisc.ac.in", "14.139.196.22"),
        ("www.ntu.edu.tw", "140.112.1.1"),
        ("www.kaist.ac.kr", "143.248.1.140"),
        ("www.chula.ac.th", "161.246.70.53"),
        ("www.vnu.edu.vn", "119.17.215.11")
    ],
    "Africa": [
        ("www.uct.ac.za", "137.158.154.1"),
        ("www.kenet.or.ke", "196.200.219.1"),
        ("www.cu.edu.eg", "163.121.128.11"),
        ("www.unilag.edu.ng", "41.203.64.1"),
        ("www.um5.ac.ma", "195.221.1.1")
    ],
    "Australia": [
        ("homer.unimelb.edu.au", "128.250.21.21"),
        ("rsise.anu.edu.au", "150.203.179.10"),
        ("www.uq.edu.au", "130.102.6.1"),
        ("ftp.griffith.edu.au", "131.181.2.10"),
        ("www.service.tas.gov.au", "103.26.158.22")
    ],
    "Europe": [
        ("www.dfn.de", "188.1.144.1"),
        ("www.cern.ch", "188.184.116.1"),
        ("www.ras.ru", "84.237.1.1"),
        ("www.uv.es", "158.42.1.1"),
        ("www.uj.edu.pl", "149.156.1.1")
    ]
    }

for reg, sites in region_sites_ips.items():
    print(f"REGION: {reg}")
    for domain, ip in sites:
        try:
            print(f"ADDRESSES FROM DNS: {socket.gethostbyname_ex(domain)}")
            print(f"IP FROM DEEPSEEK: {ip}")
        except:
            print("Could not solve domain")
