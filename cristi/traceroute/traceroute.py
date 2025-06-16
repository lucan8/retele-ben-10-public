import socket
import requests
import folium
from pathlib import Path
import random
from typing import Dict, List, Tuple

# IT SEEMS THAT OFTEN TRACEROUTE DOES NOT REACH THE DESTINATION
# HARDCODING IPS FOR SITES THOUGH RESOLVING THEM WITH DNS WOULD BE MORE INTERESTING
# TODO(EXTRA): Put unrelated packets in a special queue and print
# TODO(EXTRA): Send multiple packets for the same TTL 
# TODO(EXTRA): Get all ip addresses of a site and test them(use ipv6 as well)

def getLocalIp():
    dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dummy_sock.connect(('8.8.8.8', 0))

    ip = dummy_sock.getsockname()[0]
    dummy_sock.close()

    return ip

class IPLocation:
    MY_LOCAL_IP = getLocalIp()
    def __init__(self, json):
        self.ip = json.get('query')
        self.country = json.get('country', 'N/A')
        self.region = json.get('regionName', 'N/A')
        self.city = json.get('city', 'N/A')
        self.lat = json.get('lat')
        self.lon = json.get('lon')

    def getLocationStr(self):
        return f"{self.country} - {self.region} - {self.city}"


def _traceroute(ip, port, TTL, udp_send_sock, icmp_recv_sock):
    print("Current TTL: ", TTL)
    # setam TTL in headerul de IP pentru socketul de UDP
    udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, TTL)

    # trimite un mesaj UDP catre un tuplu (IP, port)
    udp_send_sock.sendto(b'salut', (ip, port))

    addr = None
    try:
        while True:
            data, addr = icmp_recv_sock.recvfrom(63535)

            # First 4 bits give the size of the IP header in 32-bit words
            ip_header_length = (data[0] & 0x0f) * 4

            # Extract source and destination of the icmp packet for unexpected behaviour
            src_ip = socket.inet_ntoa(data[12:16])
            dest_ip = socket.inet_ntoa(data[16:20])

            print(f"SOURCE: {src_ip}, DESTINATION: {dest_ip}")
            print(f"ICMP RESP TYPE: {data[ip_header_length]}, CODE: {data[ip_header_length + 1]}")

            # TTL exceeded
            if data[ip_header_length] == 11 and data[ip_header_length + 1] == 0:
                break
            
            # Port unreachable (we reached destination)
            if data[ip_header_length] == 3 and data[ip_header_length + 1] == 3:
                break
            
            if data[ip_header_length] == 3 and data[ip_header_length + 1] == 1:
                print("Host unreachable!")

            # Other types and codes are garbage
            addr = None
        
    except socket.timeout as e:
        print('    *   ' * 3)
    return addr


def traceroute(ip, port):
    # Set ttl range
    ttl = 1
    MAX_TTL = 30

    print("Running for: ", ip, port)

    # Will containt collected addresses
    addresses = []

    # Create udp socket for sending data
    udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    
    # Create raw icmp socket for responses
    icmp_recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_recv_sock.settimeout(5)
    
    # Get all addresses from traceroute until either MAX_TTL or destination is reached
    while not addresses or (addresses[-1] != ip and ttl < MAX_TTL):
        addr = _traceroute(ip, port, ttl, udp_send_sock, icmp_recv_sock)
        if addr is not None:
            addresses.append(addr[0])
            print(addresses[-1])
        ttl += 1

    udp_send_sock.close()
    icmp_recv_sock.close()

    return addresses


'''
 Exercitiu hackney carriage (optional)!
    e posibil ca ipinfo sa raspunda cu status code 429 Too Many Requests
    cititi despre campul X-Forwarded-For din antetul HTTP
        https://www.nginx.com/resources/wiki/start/topics/examples/forwarded/
    si setati-l o valoare in asa fel incat
    sa puteti trece peste sistemul care limiteaza numarul de cereri/zi

    Alternativ, puteti folosi ip-api (documentatie: https://ip-api.com/docs/api:json).
    Acesta permite trimiterea a 45 de query-uri de geolocare pe minut.
'''

# Returns the location of each machine the packet passed through to reach arg ip
def getRouteLocations(ip: str) -> list[IPLocation]:
    fake_HTTP_header = {
        'referer': 'https://ip-api.com/',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36'
    }
    
    ip_api_url = 'http://ip-api.com/json/'

    # Set probably unused port
    test_port = 33434

    # Get all address trceroute passed through
    addresses = traceroute(ip, test_port)
    
    # Get location information for the retrieved ip addressses
    locations = []
    for addr in addresses:
        resp = requests.get(ip_api_url + addr, headers=fake_HTTP_header).json()
        if resp['status'] == 'success':
            locations.append(IPLocation(resp))
        else:
            print(f"FAILED RESPONSE: {resp}")
    return locations

def printRouteLocations(out_file, locations: list[IPLocation]):
    for i in range(len(locations) - 1):
        out_file.write(locations[i].getLocationStr() + " -> ")
        print(locations[i].getLocationStr() + " -> ", end="")

    # No arrow for last one
    out_file.write(locations[-1].getLocationStr() + '\n\n')
    print(locations[-1].getLocationStr())

def plot_route_on_map(locations: list[IPLocation], output_html_file: str):
    map_center = [locations[0].lat, locations[0].lon]
    route_map = folium.Map(location=map_center, zoom_start=2)

    # For the PolyLine, using coordinates with random small offsets
    points_for_line = []

    loc_count = len(locations)

    for i, loc in enumerate(locations):
        map_loc = [loc.lat, loc.lon]

        # Add a small random offset for points that already exist
        jitter_scale = 0.05
        if map_loc in points_for_line:
            map_loc[0] += random.uniform(-jitter_scale, jitter_scale)
            map_loc[1] += random.uniform(-jitter_scale, jitter_scale) 

        points_for_line.append(map_loc)
        
        # Different text and color for start, intermediate and end hops
        popup_text = f"<b>Hop {i+1}:</b> {loc.ip}<br>{loc.city}, {loc.region}, {loc.country}"
        marker_color = "blue" 

        if i == 0: # First valid hop
            popup_text = f"<b>Start (Hop {i+1}):</b> {loc.ip}<br>{loc.city}, {loc.region}, {loc.country}"
            marker_color = "green" 
        elif i == loc_count - 1: # Last valid hop
            popup_text = f"<b>End (Hop {i+1}):</b> {loc.ip}<br>{loc.city}, {loc.region}, {loc.country}"
            marker_color = "red"   

        folium.Marker(
            location=points_for_line[-1],
            popup=folium.Popup(popup_text, max_width=300),
            tooltip=f"{loc.ip} ({loc.city})",
            icon=folium.Icon(color=marker_color)
        ).add_to(route_map)
    print(points_for_line)
    # Connect points using the original, non-jittered coordinates
    if len(points_for_line) > 1:
        folium.PolyLine(points_for_line, color="purple", weight=2.5, opacity=0.8).add_to(route_map)

    try:
        route_map.save(output_html_file)
        print(f"Map saved to {output_html_file}")
    except Exception as e:
        print(f"Error saving map: {e}")

# Creates the files and directories neccessary to represent
# The path traversed by packets to reach the ips of the given sites of the given regions as a string and as a map
# The hardcoded flag specifies whether to use the ips given or to solve them using dns
def solve(region_sites_ips: Dict[str, List[Tuple[str, str]]], hardcoded_ips: bool = True):
    # Chooses start directory based on flag
    start_dir = ""
    if hardcoded_ips:
        start_dir = "traceroute/docs/hardcoded_ips"
    else:
        start_dir = "traceroute/docs/dns_solved_ips"

    # Create start directory
    Path(start_dir).mkdir(parents=True, exist_ok=True)

    print(f"MY LOCAL IP: {IPLocation.MY_LOCAL_IP}")
    out_file = open(f'{start_dir}/traceroute.md', 'w')
    out_file.write(f'# Traceroute paths starting from {IPLocation.MY_LOCAL_IP}\n\n')
    out_file.write('Note: The map does not perfectly represent the geolocation of the machines\n\n')

    # Create directory which will hold the visual representation of the paths per region
    maps_dir = 'maps'
    Path(f'{start_dir}/{maps_dir}').mkdir(exist_ok=True)

    for reg, domains in region_sites_ips.items():
        out_file.write("## " + reg + '\n\n')
        Path(f'{start_dir}/{maps_dir}/{reg}').mkdir(exist_ok=True)

        # For each domain get associated ip, traceoute path and it's corresponding map
        for i, site in enumerate(domains):
            ip = site[1]
            # Using dns to get ip if not hardcoded
            if not hardcoded_ips:
                # If using dns does not work, fallback on hardcoded ip
                try:
                    ip = socket.gethostbyname(site[0])
                except:
                    print(f"WARNING: Could not get ip for {site[0]}")

            out_file.write(f"{i + 1}. Site: {site[0]}({ip})\n\n")
            out_file.write(f"   - Path: \n")
            locations = getRouteLocations(ip)

            printRouteLocations(out_file, locations)
            plot_route_on_map(locations, f"{start_dir}/{maps_dir}/{reg}/out_map_{i + 1}.html")
            out_file.write(f"   - [Visual map representations](/{start_dir}/{maps_dir}/{reg}/out_map_{i + 1}.html)\n\n")

def main():
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

    solve(region_sites_ips, False)
    solve(region_sites_ips)

main()