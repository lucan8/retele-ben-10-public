import socket
import requests
import folium
from pathlib import Path
import random

# IT SEEMS THAT OFTEN TRACEROUTE DOES NOT REACH THE DESTINATION
# TODO: Eliminate unrelated packets(put them in a special queue and print)
# TODO: CHOOSE BETTER SITES

# Check for the existence of region and also use regionName instead of region
class IPLocation:
    def __init__(self, json):
        self.ip = json.get('query')
        self.country = json.get('country', 'N/A')
        self.region = json.get('regionName', 'N/A')
        self.city = json.get('city', 'N/A')
        self.lat = json.get('lat')
        self.lon = json.get('lon')
    def getLocationStr(self):
        return f"{self.country} - {self.region} - {self.city}"
    
# socket de UDP
udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
# socket RAW de citire a răspunsurilor ICMP
icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
# setam timout in cazul in care socketul ICMP la apelul recvfrom nu primeste nimic in buffer
icmp_recv_socket.settimeout(5)

# Get machine ip
MY_LOCAL_IP = socket.gethostbyname(socket.gethostname())
def _traceroute(ip, port, TTL):
    print("Current TTL: ", TTL)
    # setam TTL in headerul de IP pentru socketul de UDP
    udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, TTL)

    # trimite un mesaj UDP catre un tuplu (IP, port)
    udp_send_sock.sendto(b'salut', (ip, port))

    addr = None
    try:
        data, addr = icmp_recv_socket.recvfrom(63535)

        # First 4 bits give the size of the IP header in 32-bit words
        ip_header_length = (data[0] & 0x0f) * 4

        # Extract source and destination of the icmp packet for unexpected behaviour
        src_ip = socket.inet_ntoa(data[12:16])
        dest_ip = socket.inet_ntoa(data[16:20])

        print(f"SOURCE: {src_ip}, DESTINATION: {dest_ip}")
        print(f"ICMP RESP TYPE: {data[ip_header_length]}, CODE: {data[ip_header_length + 1]}")
        
        # data[ip_header_length] = Type, data[ip_header_length + 1] = Code
        if data[ip_header_length] != 11:
            if data[ip_header_length + 1] != 3:
                addr = None
                print(f"Destination host unreachable!")
        elif data[ip_header_length + 1] != 0:
            addr = None
            print("Fragment reassembly time exceeded!")
        
    except socket.timeout as e:
        print('    *   ' * 3)
    return addr


def traceroute(ip, port):
    ttl = 1
    MAX_TTL = 30

    print("Running for: ", ip, port)
    addresses = []

    # Get all addresses from traceroute until either MAX_TTL or destination is reached
    while not addresses or (addresses[-1] != ip and ttl < MAX_TTL):
        addr = _traceroute(ip, port, ttl)
        if addr is not None:
            addresses.append(addr[0])
            print(addresses[-1])
        ttl += 1

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

def main():
    region_sites = {
        "Africa": [
            ("www.uct.ac.za", "137.158.154.230"),
            ("www.unilag.edu.ng", "196.45.48.5"),
            ("www.au.int", "196.1.95.34"),
            ("www.kemri.go.ke", "41.204.161.195"),
            ("www.moroccoworldnews.com", "172.67.72.169")
        ],
        "Asia": [
            ("www.tokyo-u.ac.jp", "133.11.0.23"),
            ("www.iitm.ac.in", "14.139.160.3"),
            ("www.ntu.edu.sg", "155.69.7.49"),
            ("www.korea.ac.kr", "163.152.6.10"),
            ("www.cuhk.edu.hk", "137.189.97.31")
        ],
        "Australia": [
            ("www.abc.net.au", "203.2.218.214"),
            ("www.anu.edu.au", "150.203.2.53"),
            ("www.sydney.edu.au", "129.78.5.8"),
            ("www.csiro.au", "138.194.190.20"),
            ("www.australia.gov.au", "152.91.62.30")
        ]
    }

    print(f"MY LOCAL IP: {MY_LOCAL_IP}")
    out_file = open('traceroute.md', 'w')
    out_file.write(f'# Traceroute paths starting from {MY_LOCAL_IP}\n\n')
    out_file.write('Note: The map does not perfectly represent the geolocation of the machines\n\n')
    
    maps_dir = 'maps'
    Path(maps_dir).mkdir(exist_ok=True)

    for reg, sites in region_sites.items():
        out_file.write("## " + reg + '\n\n')
        Path(f'{maps_dir}/{reg}').mkdir(exist_ok=True)

        for i, site in enumerate(sites):
            out_file.write(f"{i + 1}. Site: {site[0]}({site[1]})\n\n")
            out_file.write(f"   - Path: \n")
            locations = getRouteLocations(site[1])

            printRouteLocations(out_file, locations)
            plot_route_on_map(locations, f"{maps_dir}/{reg}/out_map_{i + 1}.html")
            out_file.write(f"   - [Visual map representations]({maps_dir}/{reg}/out_map_{i + 1}.html)\n\n")

main()
