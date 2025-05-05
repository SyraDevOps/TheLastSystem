import sys
import subprocess
import importlib
import os
import struct
import binascii
import random
import re
import threading
import logging
from tqdm import tqdm
from colorama import Fore

# --- Novos imports para recursos avançados ---
import asyncio
from multiprocessing import Pool
import glob
import importlib.util
import numpy as np
from typing import List, Dict, Optional, Union, Tuple, Any, Callable
import json
from datetime import datetime
import pytest
import matplotlib.pyplot as plt
from io import BytesIO
import base64

# --- Auto-installer para required libraries ---
REQUIRED_LIBS = [
    'socket', 'psutil', 'platform', 'netifaces', 'concurrent.futures',
    'scapy.all', 'pyshark', 'requests', 'fpdf', 'whois', 'cryptography', 'colorama'
]

# Instale estas dependências adicionais
REQUIRED_LIBS.extend([
    'numpy', 'scikit-learn', 'python-nmap', 'matplotlib', 'pytest'
])

def check_and_install():
    print("[*] Verificando dependências...")
    for lib in REQUIRED_LIBS:
        pkg = lib.split('.')[0]
        try:
            importlib.import_module(pkg)
        except ImportError:
            print(f"[!] Instalando {pkg}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

check_and_install()

# --- Imports (garantidos) ---
import socket
import psutil
import platform
import netifaces
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, TCP, UDP
import pyshark
import requests
from fpdf import FPDF
import time
import whois
from cryptography.hazmat.primitives import hashes
import queue

# --- Configuração de logging estruturado ---
logging.basicConfig(
    filename="SYRA_TLS_REPORTS/syra_tls.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# --- Parâmetros globais de timeout ---
DEFAULT_TCP_TIMEOUT = 0.5
DEFAULT_UDP_TIMEOUT = 0.5
DEFAULT_SNMP_TIMEOUT = 2
DEFAULT_SMB_TIMEOUT = 2
DEFAULT_ICMP_TIMEOUT = 1

# --- Banner ---
def print_banner():
    banner = r"""
██╗  ██╗ █████╗ ██╗   ██╗███████╗███╗   ██╗
██║  ██║██╔══██╗██║   ██║██╔════╝████╗  ██║
███████║███████║██║   ██║█████╗  ██╔██╗ ██║
██╔══██║██╔══██║╚██╗ ██╔╝██╔══╝  ██║╚██╗██║
██║  ██║██║  ██║ ╚████╔╝ ███████╗██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝
    """
    print("\033[1;36m" + banner + "\033[0m")
    print("        HAVEN - Next-Gen Network Scanner & Forensics Suite\n")
    print("        SYRADEVOPS - TLS\n")

# --- Diretório do projeto ---
def ensure_project_dir():
    project_dir = os.path.join(os.getcwd(), "SYRA_TLS_REPORTS")
    if not os.path.exists(project_dir):
        os.makedirs(project_dir)
    return project_dir

# --- Coleta de informações do sistema ---
def get_system_info():
    info = []
    info.append(f"Sistema operacional: {platform.system()} {platform.release()}")
    info.append(f"Hostname: {socket.gethostname()}")
    info.append(f"Usuário: {os.getlogin()}")
    info.append(f"Tempo ligado: {time.ctime(psutil.boot_time())}")
    info.append(f"CPU: {platform.processor()}")
    info.append(f"Núcleos: {psutil.cpu_count(logical=True)}")
    info.append(f"Memória total: {round(psutil.virtual_memory().total/1024**3,2)} GB")
    info.append(f"Discos: {[d.device for d in psutil.disk_partitions()]}")
    info.append(f"Processos ativos: {len(psutil.pids())}")
    info.append(f"Conexões de rede ativas: {len(psutil.net_connections())}")
    info.append(f"Rotas: {psutil.net_if_stats()}")
    return info

def list_interfaces():
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        iface_info = [f"Interface: {iface}"]
        for addr in addrs:
            if addr.family == socket.AF_INET:
                iface_info.append(f"  IP: {addr.address} / Máscara: {addr.netmask}")
            elif addr.family == psutil.AF_LINK:
                iface_info.append(f"  MAC: {addr.address}")
        interfaces.append('\n'.join(iface_info))
    return interfaces

def get_all_networks():
    networks = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                mask = addr.netmask
                if ip and mask:
                    networks.append((iface, ip, mask))
    return networks

# --- ARP Scan ---
def arp_scan(ip_range, interface, timeout=3):
    devices = []
    try:
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        ans, _ = srp(packet, timeout=timeout, iface=interface, verbose=False)
        for _, received in ans:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        logging.info(f"ARP scan {ip_range} via {interface}: {len(devices)} dispositivos encontrados")
    except Exception as e:
        devices.append({'error': str(e)})
        logging.error(f"Erro no ARP scan {ip_range} via {interface}: {e}")
    return devices

# --- ICMP Ping Sweep ---
def icmp_ping(ip, timeout=DEFAULT_ICMP_TIMEOUT):
    try:
        pkt = IP(dst=ip)/ICMP()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        return ip if resp else None
    except Exception as e:
        logging.warning(f"ICMP ping falhou para {ip}: {e}")
        return None

def icmp_ping_sweep(ip_base, timeout=DEFAULT_ICMP_TIMEOUT):
    ips = [f"{ip_base}.{i}" for i in range(1, 255)]
    active = []
    with ThreadPoolExecutor(max_workers=100) as executor, tqdm(total=len(ips), desc="ICMP Sweep", ncols=80) as pbar:
        futures = {executor.submit(icmp_ping, ip, timeout): ip for ip in ips}
        for future in futures:
            try:
                result = future.result()
                if result:
                    active.append(result)
            except Exception as e:
                logging.warning(f"Erro durante ICMP sweep para {futures[future]}: {e}")
            finally:
                pbar.update(1)
    logging.info(f"ICMP sweep {ip_base}.0/24: {len(active)} ativos")
    return active

# --- TCP/UDP Port Scan (com banner grabbing e UDP detection) ---
def port_scan(ip, ports=None, tcp_timeout=DEFAULT_TCP_TIMEOUT, udp_timeout=DEFAULT_UDP_TIMEOUT):
    if ports is None:
        ports = (
            list(range(1, 1025)) +
            [3306, 5432, 8000, 8080, 8443, 8888, 27017, 6379, 11211, 5900, 25565]
        )
    open_ports = []
    banners = {}
    for port in tqdm(ports, desc=f"Port scan {ip}", ncols=80):
        # TCP Scan
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(tcp_timeout)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                    try:
                        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = s.recv(1024).decode(errors='ignore').strip()
                        banners[port] = banner[:100]
                    except Exception:
                        banners[port] = "No banner"
        except Exception as e:
            logging.debug(f"TCP scan erro {ip}:{port}: {e}")
        # UDP Scan (básico)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(udp_timeout)
                s.sendto(b'', (ip, port))
                s.recvfrom(1024)
                open_ports.append(f"UDP/{port}")
        except Exception:
            pass
    logging.info(f"Port scan {ip}: {open_ports}")
    return open_ports, banners

# --- DNS Scan ---
def dns_scan(domain):
    try:
        result = socket.gethostbyname_ex(domain)
        return f"DNS: {result}"
    except Exception as e:
        return f"DNS Scan Error: {e}"

# --- WHOIS ---
def whois_lookup(domain):
    try:
        # Tenta usar o pacote whois (python-whois)
        import whois
        if hasattr(whois, "whois"):
            w = whois.whois(domain)
            return str(w)
        else:
            raise ImportError("Pacote whois não tem método whois")
    except Exception:
        # Fallback: consulta WHOIS via socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(("whois.verisign-grs.com", 43))
            s.send((domain + "\r\n").encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            return response.decode(errors="replace")
        except Exception as e:
            return f"WHOIS Error: {e}"

# --- Vendor MAC ---
def get_vendor(mac):
    try:
        return requests.get(f"https://api.macvendors.com/{mac}").text
    except Exception:
        return "Desconhecido"

# --- Hostname ---
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Desconhecido"

# --- Network Points ---
def show_network_points():
    gws = netifaces.gateways()
    dns = []
    try:
        for iface in psutil.net_if_addrs():
            for addr in psutil.net_if_addrs()[iface]:
                if hasattr(addr, 'address') and addr.family == socket.AF_INET:
                    dns.append(addr.address)
    except Exception:
        pass
    return f"Gateways: {gws}\nDNS: {dns}"

# --- PyShark Sniffer com suporte para múltiplas interfaces ---
def get_active_interfaces():
    """Retorna lista de interfaces ativas"""
    active = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                active.append(iface)
                break
    return active

def pyshark_sniffer(interface=None, packet_count=100, save_pcap=None):
    """Sniff de pacotes com PyShark em uma ou todas as interfaces"""
    if not interface:
        # Se nenhuma interface fornecida, use todas as ativas
        interfaces = get_active_interfaces()
        print(f"\n[+] Nenhuma interface especificada. Analisando todas: {interfaces}")
        all_packets = []
        for iface in interfaces:
            try:
                print(f"\n[+] Capturando {packet_count} pacotes na interface {iface}...")
                pcap_path = save_pcap
                if save_pcap and len(interfaces) > 1:
                    # Cria um arquivo separado para cada interface
                    base, ext = os.path.splitext(save_pcap)
                    pcap_path = f"{base}_{iface}{ext}"
                
                cap = pyshark.LiveCapture(interface=iface, output_file=pcap_path)
                cap.sniff(packet_count=packet_count)
                
                packets_info = []
                for pkt in cap:
                    try:
                        info = f"[{iface}] {pkt.sniff_time} {pkt.highest_layer} {pkt.ip.src} -> {pkt.ip.dst} {pkt.transport_layer} {getattr(pkt[pkt.transport_layer],'srcport', '')}"
                    except Exception:
                        info = f"[{iface}] {str(pkt)}"
                    packets_info.append(info)
                
                all_packets.extend(packets_info)
                print(f"[+] {len(packets_info)} pacotes capturados na interface {iface}")
                
            except Exception as e:
                all_packets.append(f"[!] Erro na interface {iface}: {e}")
        
        return all_packets
    else:
        # Comportamento original para uma única interface
        print(f"\n[+] Capturando {packet_count} pacotes na interface {interface}...")
        try:
            cap = pyshark.LiveCapture(interface=interface, output_file=save_pcap)
            cap.sniff(packet_count=packet_count)
            packets_info = []
            for pkt in cap:
                try:
                    info = f"{pkt.sniff_time} {pkt.highest_layer} {pkt.ip.src} -> {pkt.ip.dst} {pkt.transport_layer} {getattr(pkt[pkt.transport_layer],'srcport', '')}"
                except Exception:
                    info = str(pkt)
                packets_info.append(info)
            return packets_info
        except Exception as e:
            return [f"[!] Erro: {e}"]

# --- Deep Packet Inspection com suporte para múltiplas interfaces ---
def deep_packet_inspection(interface=None, packet_count=100):
    """
    Realiza Deep Packet Inspection (DPI) em uma ou todas as interfaces de rede.
    Mostra barra de progresso, detalhes dos pacotes e permite fácil expansão.
    """
    print(f"\n[INFO] Iniciando DPI para {packet_count} pacotes...")
    interfaces = [interface] if interface else get_active_interfaces()
    all_analysis = []
    for iface in interfaces:
        try:
            print(f"[INFO] Capturando {packet_count} pacotes na interface: {iface}")
            cap = pyshark.LiveCapture(interface=iface)
            cap.sniff(packet_count=packet_count)
            analysis = []
            for pkt in tqdm(cap, total=packet_count, desc=f"DPI {iface}", ncols=80):
                try:
                    layers = [layer.layer_name for layer in pkt.layers]
                    summary = f"[{iface}] {pkt.sniff_time} Layers: {layers} "
                    if 'ip' in layers:
                        summary += f"{pkt.ip.src} -> {pkt.ip.dst} "
                    if 'http' in layers:
                        summary += f"HTTP Host: {getattr(pkt.http, 'host', '')} URI: {getattr(pkt.http, 'request_uri', '')} "
                    if 'tls' in layers:
                        summary += f"TLS Version: {getattr(pkt.tls, 'handshake_version', '')} "
                    if 'dns' in layers:
                        summary += f"DNS Query: {getattr(pkt.dns, 'qry_name', '')} "
                    analysis.append(summary)
                    # Exibição em tempo real
                    print(f"[PKT] {summary}")
                except Exception as e:
                    analysis.append(f"[{iface}] Erro ao analisar pacote: {e}")
            all_analysis.extend(analysis)
            print(f"[INFO] {len(analysis)} pacotes analisados na interface {iface}")
        except Exception as e:
            all_analysis.append(f"[!] Erro na interface {iface}: {e}")
    return all_analysis

# --- Hash de arquivos suspeitos (exemplo de integração forense) ---
def hash_file(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
            digest = hashes.Hash(hashes.SHA256())
            digest.update(data)
            return digest.finalize().hex()
    except Exception as e:
        return f"Erro ao calcular hash: {e}"

# --- Implementação de fingerprinting de SO ---
def os_fingerprint(ip: str) -> dict:
    """
    Realiza fingerprinting do sistema operacional usando nmap.
    
    Args:
        ip: Endereço IP alvo
        
    Returns:
        Dicionário com resultado do fingerprinting
    """
    try:
        import nmap
        
        print(Fore.CYAN + f"[INFO] Realizando OS fingerprinting em {ip}")
        
        nm = nmap.PortScanner()
        # -O ativa detecção de SO
        # -T4 define timing agressivo
        # --osscan-limit limita scan a hosts promissores
        result = nm.scan(ip, arguments='-O -T4 --osscan-limit')
        
        if ip not in result['scan'] or 'osmatch' not in result['scan'][ip]:
            return {"error": "Não foi possível identificar o SO"}
        
        # Extrai informações do SO
        os_matches = result['scan'][ip]['osmatch']
        os_info = {
            "os_name": os_matches[0]['name'],
            "accuracy": os_matches[0]['accuracy'],
            "all_matches": [match['name'] for match in os_matches]
        }
        
        if 'osclass' in os_matches[0]:
            os_info["type"] = os_matches[0]['osclass'][0].get('type', 'unknown')
            os_info["vendor"] = os_matches[0]['osclass'][0].get('vendor', 'unknown')
            os_info["os_family"] = os_matches[0]['osclass'][0].get('osfamily', 'unknown')
        
        print(Fore.GREEN + f"[OK] SO identificado: {os_info['os_name']} (precisão: {os_info['accuracy']}%)")
        
        return os_info
        
    except ImportError:
        print(Fore.RED + "[ERRO] python-nmap não está instalado. Use pip install python-nmap")
        return {"error": "python-nmap não está instalado"}
    except Exception as e:
        print(Fore.RED + f"[ERRO] Falha no fingerprinting de SO: {e}")
        return {"error": str(e)}

def tcp_fingerprinting(ip: str) -> dict:
    """
    Realiza fingerprinting básico baseado em comportamento de TCP/IP.
    Usa Scapy para enviar sondas TCP/IP e analisar respostas específicas do SO.
    
    Args:
        ip: Endereço IP alvo
        
    Returns:
        Dicionário com resultado do fingerprinting
    """
    from scapy.all import IP, TCP, sr1
    
    print(Fore.CYAN + f"[INFO] Realizando TCP fingerprinting em {ip}")
    
    results = {}
    
    try:
        # Test 1: SYN to open port
        resp = sr1(IP(dst=ip)/TCP(dport=80, flags="S"), timeout=2, verbose=0)
        if resp:
            if resp.haslayer(TCP) and resp.getlayer(TCP).flags & 0x12:  # SYN+ACK
                ttl = resp.ttl
                window_size = resp.getlayer(TCP).window
                
                results["ttl"] = ttl
                results["window"] = window_size
                
                # Windows typically has TTL=128, window size varies
                if ttl >= 123 and ttl <= 130:
                    results["os_guess"] = "Windows"
                # Linux typically has TTL=64
                elif ttl >= 60 and ttl <= 68:
                    results["os_guess"] = "Linux"
                # MacOS/BSD typically has TTL=64 but different window sizes
                elif ttl >= 60 and ttl <= 68 and window_size == 65535:
                    results["os_guess"] = "MacOS/BSD"
                else:
                    results["os_guess"] = "Unknown"
        
        print(Fore.GREEN + f"[OK] TCP fingerprinting: {results.get('os_guess', 'Desconhecido')}")
        return results
        
    except Exception as e:
        print(Fore.RED + f"[ERRO] Falha no TCP fingerprinting: {e}")
        return {"error": str(e)}

# --- Implementação de análise por multiprocessamento ---
def analyze_packet(packet_data: dict) -> dict:
    """
    Função para análise profunda de um único pacote.
    Usa CPU intensivamente, por isso é adequada para multiprocessing.
    
    Args:
        packet_data: Dicionário com dados do pacote
        
    Returns:
        Dicionário com dados analisados
    """
    result = {"original": packet_data}
    
    try:
        # Exemplo: extração de features para análise
        if "ip" in packet_data:
            # Análise do endereço IP
            ip_parts = packet_data["ip"].get("src", "").split(".")
            result["is_private"] = (
                ip_parts[0] == "10" or
                (ip_parts[0] == "172" and 16 <= int(ip_parts[1]) <= 31) or
                (ip_parts[0] == "192" and ip_parts[1] == "168")
            )
        
        # Análise de protocolo 
        if "protocol" in packet_data:
            proto = packet_data["protocol"]
            result["security_risk"] = proto in ["telnet", "ftp"]
            
        # Análise de payload para detectar padrões
        if "payload" in packet_data:
            payload = packet_data["payload"]
            # Exemplo: Detecta comandos comuns de shell
            commands = ["cat ", "ls ", "cd ", "pwd", "whoami", "wget ", "curl "]
            result["has_shell_commands"] = any(cmd in payload for cmd in commands)
            
            # Exemplo: Detecta potenciais sqli
            sqli = ["SELECT ", "UNION ", "DROP ", "OR 1=1", "--", "' OR '", "admin'--"]
            result["potential_sqli"] = any(inj in payload for inj in sqli)
    
    except Exception as e:
        result["error"] = str(e)
    
    return result

def multiprocess_packet_analysis(packets: List[dict], max_workers: int = None) -> List[dict]:
    """
    Analisa pacotes usando multiprocessamento.
    
    Args:
        packets: Lista de dicionários com dados dos pacotes
        max_workers: Número máximo de processos (None = auto)
        
    Returns:
        Lista de resultados
    """
    start_time = time.time()
    print(Fore.CYAN + f"[INFO] Iniciando análise paralela de {len(packets)} pacotes")
    
    with Pool(processes=max_workers) as pool:
        results = list(tqdm(
            pool.imap(analyze_packet, packets),
            total=len(packets),
            desc="Análise de Pacotes",
            ncols=80
        ))
    
    elapsed = time.time() - start_time
    print(Fore.GREEN + f"[OK] Análise concluída em {elapsed:.2f}s")
    return results

def extract_packet_features(packets: List[dict]) -> np.ndarray:
    """
    Extrai features de pacotes para uso em modelos de ML.
    
    Args:
        packets: Lista de dicionários com dados dos pacotes
        
    Returns:
        Array NumPy com features
    """
    features = []
    
    for pkt in packets:
        # Cria um vetor de características para cada pacote
        pkt_features = []
        
        # Feature 1: Tamanho do pacote
        pkt_features.append(pkt.get("length", 0))
        
        # Feature 2: Protocolo (codificado como número)
        proto_map = {"tcp": 1, "udp": 2, "icmp": 3, "http": 4, "dns": 5, "unknown": 0}
        protocol = pkt.get("protocol", "unknown").lower()
        pkt_features.append(proto_map.get(protocol, 0))
        
        # Feature 3: É porta comum? (1 = sim)
        common_ports = {80, 443, 22, 21, 25, 53, 3389}
        is_common = 1 if pkt.get("port", 0) in common_ports else 0
        pkt_features.append(is_common)
        
        # Feature 4: Tempo desde o pacote anterior (ou 0 se for o primeiro)
        pkt_features.append(pkt.get("delta", 0))
        
        # Feature 5: Quantidade de flags TCP (se for TCP)
        tcp_flags = len(pkt.get("tcp_flags", ""))
        pkt_features.append(tcp_flags)
        
        features.append(pkt_features)
    
    return np.array(features)

# --- Implementação de detecção de anomalias ---
def detect_traffic_anomalies(packets: List[dict], contamination: float = 0.05) -> List[int]:
    """
    Detecta anomalias no tráfego de rede usando IsolationForest.
    
    Args:
        packets: Lista de dicionários com dados dos pacotes
        contamination: Proporção esperada de anomalias (0.05 = 5%)
        
    Returns:
        Lista de índices dos pacotes anômalos
    """
    try:
        from sklearn.ensemble import IsolationForest
        
        print(Fore.CYAN + "[INFO] Extraindo características dos pacotes para análise de anomalias")
        
        # Extrai características dos pacotes
        features = extract_packet_features(packets)
        
        # Verifica se há dados suficientes
        if len(features) < 10:
            print(Fore.YELLOW + "[AVISO] Poucos pacotes para análise de anomalias (mín. 10)")
            return []
            
        print(Fore.CYAN + f"[INFO] Treinando modelo com {len(features)} pacotes")
        
        # Treina o modelo
        model = IsolationForest(contamination=contamination, random_state=42)
        preds = model.fit_predict(features)
        
        # -1 indica anomalia, 1 indica normal
        anomaly_indices = [i for i, pred in enumerate(preds) if pred == -1]
        
        print(Fore.GREEN + f"[OK] {len(anomaly_indices)} anomalias detectadas")
        
        return anomaly_indices
        
    except ImportError:
        print(Fore.RED + "[ERRO] scikit-learn não está instalado. Use pip install scikit-learn")
        return []
    except Exception as e:
        print(Fore.RED + f"[ERRO] Falha na detecção de anomalias: {e}")
        return []

def analyze_anomalous_packets(packets: List[dict], anomaly_indices: List[int]) -> List[dict]:
    """
    Analisa pacotes anômalos e gera relatório.
    
    Args:
        packets: Lista de todos os pacotes
        anomaly_indices: Índices dos pacotes anômalos
        
    Returns:
        Lista de dicionários com detalhes das anomalias
    """
    anomaly_report = []
    
    for idx in anomaly_indices:
        if 0 <= idx < len(packets):
            packet = packets[idx]
            
            # Análise básica da anomalia
            analysis = {
                "packet_index": idx,
                "packet_data": packet,
                "possible_reasons": []
            }
            
            # Análises específicas
            if packet.get("length", 0) > 1500:
                analysis["possible_reasons"].append("Pacote excepcionalmente grande")
                
            if packet.get("protocol") == "unknown":
                analysis["possible_reasons"].append("Protocolo desconhecido")
                
            # Verifica portas não padrão para protocolos conhecidos
            port = packet.get("port", 0)
            protocol = packet.get("protocol", "").lower()
            
            if protocol == "http" and port not in [80, 8080, 8000]:
                analysis["possible_reasons"].append(f"HTTP em porta não padrão ({port})")
                
            if protocol == "https" and port not in [443, 8443]:
                analysis["possible_reasons"].append(f"HTTPS em porta não padrão ({port})")
            
            # Se nenhuma razão específica foi encontrada
            if not analysis["possible_reasons"]:
                analysis["possible_reasons"].append("Padrão de tráfego estatisticamente anômalo")
                
            anomaly_report.append(analysis)
            
    return anomaly_report

# --- NetBIOS Scanner ---
def netbios_scan(ip):
    """Scan para descobrir nomes NetBIOS"""
    try:
        # Formatação do pacote NetBIOS Name Service Query
        header = struct.pack(">HHHHHH", 
            random.randint(0, 65535),  # Transaction ID
            0x0010,                    # Flags (query)
            1,                         # Questions count
            0,                         # Answers count
             0,                         # Authority count
            0                          # Additional count
        )
        
        question = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
        packet = header + question
        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(packet, (ip, 137))
        response = s.recv(1024)
        s.close()
        
        # Análise da resposta
        if len(response) > 60:
            names_count = struct.unpack(">B", response[56:57])[0]
            result = []
            for i in range(names_count):
                name_offset = 57 + (i * 18)
                name = response[name_offset:name_offset+15].strip(b"\x00").decode('ascii', errors='replace')
                flag = struct.unpack(">H", response[name_offset+16:name_offset+18])[0]
                result.append(f"{name} [0x{flag:04x}]")
            return result
        return []
    except Exception:
        return []

# --- SMB Scanner ---
def smb_scan(ip, timeout=DEFAULT_SMB_TIMEOUT):
    """Scan para detectar compartilhamentos SMB e informações do servidor"""
    try:
        # Negociação SMB
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, 445))
            
            # SMB Negotiate Protocol Request
            negotiate = (
                b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18"
                b"\x43\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43"
                b"\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52"
                b"\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e"
                b"\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66"
                b"\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20"
                b"\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30"
                b"\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02"
                b"\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
            )
            
            s.send(negotiate)
            response = s.recv(1024)
        
        # Análise da resposta
        if len(response) > 36:
            dialect_index = response[36]
            os_info = "Windows" if dialect_index > 0 else "Samba/Unix"
            logging.info(f"SMB {ip}: {os_info}")
            return [f"SMB Server: {os_info}"]
        return []
    except Exception as e:
        logging.warning(f"SMB scan falhou para {ip}: {e}")
        return []

# --- SNMP Scanner ---
def snmp_scan(ip, community='public', timeout=DEFAULT_SNMP_TIMEOUT):
    """Scan para dispositivos SNMP com community string 'public'"""
    try:
        # SNMP GET request para obter sysDescr.0 (1.3.6.1.2.1.1.1.0)
        community_bytes = community.encode() if isinstance(community, str) else community
        # Fix the byte string concatenation syntax
        payload = (
            b"\x30\x26"               # SEQUENCE 38 bytes
            + b"\x02\x01\x00"           # INTEGER: version 0 (v1)
            + b"\x04" + bytes([len(community_bytes)]) + community_bytes  # STRING: community
            + b"\xa0\x19"               # GET-REQUEST
            + b"\x02\x01\x00"           # INTEGER: request ID 0
            + b"\x02\x01\x00"           # INTEGER: error 0
            + b"\x02\x01\x00"           # INTEGER: error index 0
            + b"\x30\x0e"               # SEQUENCE
            + b"\x30\x0c"               # SEQUENCE
            + b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"  # OID: 1.3.6.1.2.1.1.1.0
            + b"\x05\x00"               # NULL
        )          
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (ip, 161))
            response, _ = s.recvfrom(4096)
        
        # Procura por string no response
        desc_pattern = re.compile(br'\x04[\x01-\xff](.+?)[\x00-\x1f]', re.DOTALL)
        match = desc_pattern.search(response)
        
        if match:
            desc = match.group(1).decode('ascii', errors='replace')
            logging.info(f"SNMP {ip}: {desc}")
            return [f"SNMP Device: {desc}"]
        return ["SNMP: Responde com community 'public'"]
    except Exception as e:
        logging.warning(f"SNMP scan falhou para {ip}: {e}")
        return []

# --- SSDP/UPnP Scanner ---
def ssdp_scan(ip):
    """Scan para dispositivos UPnP usando SSDP"""
    try:
        ssdp_request = (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b"MAN: \"ssdp:discover\"\r\n"
            b"MX: 2\r\n"
            b"ST: ssdp:all\r\n\r\n"
        )
        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(ssdp_request, (ip, 1900))
        response, _ = s.recvfrom(4096)
        s.close()
        
        # Parse response
        lines = response.decode('utf-8', errors='replace').splitlines()
        result = []
        for line in lines:
            if line.startswith('SERVER:') or line.startswith('Location:'):
                result.append(line)
        return result if result else ["UPnP: Dispositivo responde"]
    except Exception:
        return []

# --- NFS Scanner ---
def nfs_scan(ip):
    """Scan para serviços NFS"""
    try:
        # Chama rpcinfo para NFS
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex((ip, 2049)) == 0:
            s.close()
            return ["NFS: Porta 2049 aberta"]
        s.close()
        return []
    except Exception:
        return []

# --- FTP Banner ---
def ftp_banner(ip):
    """Coleta banner FTP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, 21))
        banner = s.recv(1024).decode('utf-8', errors='replace').strip()
        s.close()
        return [f"FTP Banner: {banner}"]
    except Exception:
        return []

# --- SSH Banner ---
def ssh_banner(ip):
    """Coleta banner SSH"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, 22))
        banner = s.recv(1024).decode('utf-8', errors='replace').strip()
        s.close()
        return [f"SSH Banner: {banner}"]
    except Exception:
        return []

# --- MySQL Banner ---
def mysql_banner(ip):
    """Coleta informações de servidor MySQL"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, 3306))
        banner = s.recv(1024)
        s.close()
        if len(banner) > 5:
            version = banner[5:].split(b'\x00')[0].decode('utf-8', errors='replace')
            return [f"MySQL Version: {version}"]
        return ["MySQL: Porta aberta"]
    except Exception:
        return []

# --- Extended Info Scan ---
def extended_scan(ip):
    """Executar todos os scanners avançados em uma thread"""
    results = {}
    
    # Threads para cada serviço
    def scan_smb():
        results['smb'] = smb_scan(ip)
    
    def scan_netbios():
        results['netbios'] = netbios_scan(ip)
    
    def scan_snmp():
        results['snmp'] = snmp_scan(ip)
    
    def scan_ssdp():
        results['ssdp'] = ssdp_scan(ip)
    
    def scan_nfs():
        results['nfs'] = nfs_scan(ip)
    
    def scan_ftp():
        results['ftp'] = ftp_banner(ip)
    
    def scan_ssh():
        results['ssh'] = ssh_banner(ip)
    
    def scan_mysql():
        results['mysql'] = mysql_banner(ip)
    
    # Inicia threads
    threads = []
    for fn in [scan_smb, scan_netbios, scan_snmp, scan_ssdp, scan_nfs, scan_ftp, scan_ssh, scan_mysql]:
        t = threading.Thread(target=fn)
        threads.append(t)
        t.start()
    
    # Aguarda todas completarem
    for t in threads:
        t.join()
    
    # Consolida resultados
    all_results = []
    for scanner, res in results.items():
        if res:
            all_results.append(f"--- {scanner.upper()} ---")
            all_results.extend(res)
    
    return all_results

# --- Full Network Scan (Enhanced) ---
def full_network_scan():
    report = []
    report.append("=== INFORMAÇÕES DO SISTEMA ===")
    report.extend(get_system_info())
    report.append("\n=== INTERFACES DE REDE ===")
    report.extend(list_interfaces())
    report.append("\n=== PONTOS DE REDE ===")
    report.append(show_network_points())
    redes = get_all_networks()
    for iface, ip, mask in redes:
        report.append(f"\n[+] Escaneando rede {ip}/{mask} na interface {iface}")
        ip_base = '.'.join(ip.split('.')[:3])
        devices = arp_scan(f"{ip_base}.1/24", iface)
        active_ips = icmp_ping_sweep(ip_base)
        all_devices = {(d['ip'], d['mac']) for d in devices if 'ip' in d}
        all_devices.update({(ip, "???") for ip in active_ips if not any(ip == d[0] for d in all_devices)})
        report.append("\nIP\t\tMAC\t\t\tHOSTNAME\tPORTAS\tSERVIÇOS")
        report.append("-"*80)
        # Barra de progresso para dispositivos
        for ip, mac in tqdm(sorted(all_devices), desc=f"Dispositivos {iface}", ncols=80):
            hostname = get_hostname(ip)
            ports, banners = port_scan(ip)
            vendor = get_vendor(mac) if mac != "???" else "Desconhecido"
            report.append(f"{ip}\t{mac}\t{hostname}\t{ports}\t{vendor}")
            logging.info(f"Dispositivo {ip} ({mac}) - {hostname} - {ports}")
            print(f"[+] Executando scan avançado em {ip}...")
            extended_info = extended_scan(ip)
            if extended_info:
                for line in extended_info:
                    report.append(f"    {line}")
            if banners:
                banner_str = "; ".join([f"{p}:{banners[p]}" for p in banners])
                report.append(f"    Banners: {banner_str}")
            report.append("-"*80)
    return report

# --- NOVO SCANNER DINÂMICO E AVANÇADO ---
def advanced_network_scan(targets, ports=None, mode="full", threads=200, timeout=0.5):
    """
    targets: string (CIDR, IP, range) ou lista de IPs
    ports: lista de portas ou None (usa padrão)
    mode: 'full', 'fast', 'custom'
    threads: número de threads
    timeout: timeout de conexão
    """
    from ipaddress import ip_network, ip_address
    import queue

    # Definição de portas padrão
    if not ports:
        if mode == "fast":
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080]
        elif mode == "custom":
            ports = [80, 443, 8080, 8443]
        else:  # full
            ports = list(range(1, 1025)) + [3306, 5432, 8000, 8080, 8443, 8888, 27017, 6379, 11211, 5900, 25565]

    # Descobre IPs alvo
    ip_list = []
    try:
        if isinstance(targets, str):
            if "/" in targets:
                ip_list = [str(ip) for ip in ip_network(targets, strict=False).hosts()]
            elif "-" in targets:
                start, end = targets.split("-")
                start_ip = ip_address(start.strip())
                end_ip = ip_address(end.strip())
                ip_list = [str(ip_address(i)) for i in range(int(start_ip), int(end_ip) + 1)]
            else:
                ip_list = [targets]
        elif isinstance(targets, list):
            ip_list = targets
    except Exception as e:
        return [f"[!] Erro ao processar alvos: {e}"]

    results = []
    q = queue.Queue()
    for ip in ip_list:
        for port in ports:
            q.put((ip, port))

    scan_results = {}
    lock = threading.Lock()

    def worker():
        while not q.empty():
            try:
                ip, port = q.get_nowait()
            except queue.Empty:
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        banner = ""
                        try:
                            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                            banner = s.recv(1024).decode(errors='ignore').strip()
                        except Exception:
                            pass
                        with lock:
                            if ip not in scan_results:
                                scan_results[ip] = []
                            scan_results[ip].append((port, banner[:100] if banner else ""))
            except Exception:
                pass
            finally:
                q.task_done()

    threads_list = []
    for _ in range(min(threads, q.qsize())):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads_list.append(t)

    q.join()

    # Resultados organizados
    for ip in ip_list:
        if ip in scan_results:
            results.append(f"\nHost: {ip}")
            for port, banner in sorted(scan_results[ip]):
                results.append(f"  Porta {port}/tcp aberta | Banner: {banner}")
        else:
            results.append(f"\nHost: {ip} - Nenhuma porta aberta detectada.")

    return results

# --- Implementação de scanners assíncronos ---
async def async_tcp_connect(ip: str, port: int, timeout: float = 0.5) -> Tuple[str, int, bool]:
    """
    Tenta conectar em uma porta TCP de forma assíncrona.
    
    Args:
        ip: Endereço IP alvo
        port: Porta a ser testada
        timeout: Tempo limite em segundos
        
    Returns:
        Tupla (ip, porta, status_conexao)
    """
    try:
        # Cria uma corrotina de conexão
        conn = asyncio.open_connection(ip, port)
        # Aguarda com timeout
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        # Fecha a conexão
        writer.close()
        await writer.wait_closed()
        return (ip, port, True)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return (ip, port, False)

async def async_tcp_scan(ip: str, ports: List[int], timeout: float = 0.5) -> List[int]:
    """
    Realiza varredura de portas TCP usando asyncio.
    
    Args:
        ip: Endereço IP alvo
        ports: Lista de portas a verificar
        timeout: Tempo limite para cada conexão
    
    Returns:
        Lista de portas abertas
    """
    print(Fore.CYAN + f"[INFO] Iniciando scan TCP assíncrono no host {ip} ({len(ports)} portas)")
    
    # Cria tarefas para cada porta
    tasks = [async_tcp_connect(ip, port, timeout) for port in ports]
    
    # Barra de progresso
    with tqdm(total=len(tasks), desc=f"TCP Async {ip}", ncols=80) as pbar:
        open_ports = []
        for i, task_batch in enumerate(np.array_split(tasks, max(1, len(tasks) // 100))):
            # Executa em lotes para atualizar a barra de progresso
            results = await asyncio.gather(*task_batch)
            for ip, port, is_open in results:
                if is_open:
                    open_ports.append(port)
            pbar.update(len(task_batch))
    
    print(Fore.GREEN + f"[OK] {len(open_ports)} portas abertas em {ip}")
    return open_ports

async def async_icmp_ping(ip: str, timeout: float = 1.0) -> Optional[str]:
    """
    ICMP ping assíncrono usando asyncio e subprocess.
    
    Args:
        ip: Endereço IP a verificar
        timeout: Tempo limite em segundos
    
    Returns:
        IP se estiver ativo, None caso contrário
    """
    try:
        # No Windows, usamos o comando ping com -n, em Linux seria -c
        ping_cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        
        proc = await asyncio.create_subprocess_exec(
            *ping_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        
        _, _ = await proc.communicate()
        return ip if proc.returncode == 0 else None
    except Exception as e:
        logging.error(f"Erro no async_icmp_ping para {ip}: {e}")
        return None

async def async_icmp_sweep(ip_base: str, timeout: float = 1.0) -> List[str]:
    """
    Varredura ICMP assíncrona em toda a sub-rede /24.
    
    Args:
        ip_base: Base do endereço IP (ex: "192.168.1")
        timeout: Tempo limite para cada ping
    
    Returns:
        Lista de IPs ativos
    """
    print(Fore.CYAN + f"[INFO] Iniciando ICMP sweep assíncrono na rede {ip_base}.0/24")
    
    # Gera IPs de 1 a 254
    ips = [f"{ip_base}.{i}" for i in range(1, 255)]
    
    # Cria tarefas para cada IP
    tasks = [async_icmp_ping(ip, timeout) for ip in ips]
    
    # Barra de progresso
    with tqdm(total=len(tasks), desc="ICMP Async Sweep", ncols=80) as pbar:
        results = []
        for i, task_batch in enumerate(np.array_split(tasks, max(1, len(tasks) // 50))):
            batch_results = await asyncio.gather(*task_batch)
            results.extend(batch_results)
            pbar.update(len(task_batch))
    
    # Filtra None e retorna IPs ativos
    active_ips = [ip for ip in results if ip]
    print(Fore.GREEN + f"[OK] {len(active_ips)} hosts ativos encontrados")
    
    return active_ips

# Versão assíncrona do network scan
async def async_network_scan(targets: str, ports: Optional[List[int]] = None, mode: str = "full") -> List[Dict]:
    """
    Realiza scan de rede assíncrono em múltiplos alvos e portas.
    
    Args:
        targets: String CIDR, range de IP ou único IP
        ports: Lista de portas ou None para usar modo padrão
        mode: "full", "fast" ou "custom"
        
    Returns:
        Lista de resultados por host
    """
    from ipaddress import ip_network, ip_address
    
    # Configuração de portas conforme o modo
    if ports is None:
        if mode == "fast":
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080]
        elif mode == "custom":
            ports = [80, 443, 8080, 8443]
        else:  # full
            ports = list(range(1, 1025)) + [3306, 5432, 8000, 8080, 8443, 8888, 27017, 6379]
    
    # Descoberta de IPs alvo
    ip_list = []
    try:
        if "/" in targets:
            ip_list = [str(ip) for ip in ip_network(targets, strict=False).hosts()]
        elif "-" in targets:
            start, end = targets.split("-")
            start_ip = ip_address(start.strip())
            end_ip = ip_address(end.strip())
            ip_list = [str(ip_address(i)) for i in range(int(start_ip), int(end_ip) + 1)]
        else:
            ip_list = [targets]
    except Exception as e:
        return [{"error": f"Erro ao processar alvos: {e}"}]
    
    print(Fore.CYAN + f"[INFO] Iniciando scan assíncrono em {len(ip_list)} hosts e {len(ports)} portas")
    
    # Primeiro realiza ICMP para descobrir hosts ativos (opcional)
    if len(ip_list) > 5:  # Se tiver muitos hosts, vale a pena fazer ICMP primeiro
        # Extrair base de IP para sweep (só funciona para IPs na mesma subnet)
        ip_bases = set()
        for ip in ip_list:
            base = ".".join(ip.split(".")[:3])
            ip_bases.add(base)
        
        active_ips = []
        for base in ip_bases:
            active_ips.extend(await async_icmp_sweep(base))
        
        # Filtra para manter apenas IPs que estavam na lista original
        ip_list = [ip for ip in ip_list if ip in active_ips]
    
    # Realiza scan TCP em cada host ativo
    results = []
    for ip in tqdm(ip_list, desc="Hosts", ncols=80):
        open_ports = await async_tcp_scan(ip, ports)
        if open_ports:
            result = {"ip": ip, "ports": open_ports, "banners": {}}
            # Coleta banners para cada porta aberta
            for port in open_ports:
                try:
                    # Banner grabbing simples
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), 
                        timeout=1.0
                    )
                    writer.write(b'HEAD / HTTP/1.0\r\n\r\n')
                    await writer.drain()
                    banner = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                    writer.close()
                    await writer.wait_closed()
                    result["banners"][port] = banner.decode(errors="ignore")[:100]
                except:
                    result["banners"][port] = ""
            results.append(result)
        else:
            results.append({"ip": ip, "ports": [], "message": "Nenhuma porta aberta"})
    
    return results

# --- Salvar resultados em PDF (pode ser chamado a qualquer momento) ---
def save_results_pdf(results, filename):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    for line in results:
        pdf.multi_cell(0, 8, line)
    pdf.output(filename)
    print(f"[+] Resultado salvo em: {filename}")

def save_report_pdf(report_lines, filename):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    for line in report_lines:
        pdf.multi_cell(0, 8, line)
    pdf.output(filename)
    print(f"[+] Relatório salvo em: {filename}")

# --- Monitoramento de tráfego em tempo real ---
def live_traffic_monitor(interface=None):
    """
    Monitora o tráfego de rede em tempo real, exibindo pacotes capturados com destaque de cores.
    Pressione Ctrl+C para parar.
    """
    print(Fore.CYAN + "[INFO] Monitoramento de tráfego iniciado. Pressione Ctrl+C para parar.")
    interfaces = [interface] if interface else get_active_interfaces()
    try:
        for iface in interfaces:
            print(Fore.YELLOW + f"[INFO] Interface: {iface}")
            cap = pyshark.LiveCapture(interface=iface)
            for pkt in cap.sniff_continuously():
                try:
                    layers = [layer.layer_name for layer in pkt.layers]
                    src = pkt.ip.src if 'ip' in layers else "?"
                    dst = pkt.ip.dst if 'ip' in layers else "?"
                    proto = pkt.highest_layer
                    info = f"{Fore.GREEN}[{iface}] {Fore.MAGENTA}{proto} {Fore.BLUE}{src} -> {dst}"
                    print(info)
                except Exception as e:
                    print(Fore.RED + f"[ERRO] {e}")
    except KeyboardInterrupt:
        print(Fore.CYAN + "\n[INFO] Monitoramento interrompido pelo usuário.")

# --- Parse Packet String ---
def parse_packet_string(pkt_str):
    """
    Converte uma string de pacote do pyshark_sniffer em um dicionário mínimo.
    Ajuste conforme o formato real das strings.
    """
    pkt = {}
    try:
        # Exemplo: "[iface] 2024-05-05 12:34:56 TCP 192.168.1.2 -> 192.168.1.1"
        # Ajuste o parsing conforme necessário!
        parts = pkt_str.split()
        if "->" in pkt_str:
            src_idx = parts.index("->") - 1
            dst_idx = parts.index("->") + 1
            pkt["protocol"] = parts[2] if len(parts) > 2 else "unknown"
            pkt["ip.src"] = parts[src_idx]
            pkt["ip.dst"] = parts[dst_idx]
        pkt["length"] = len(pkt_str)
        pkt["port"] = 0  # Não há porta na string, defina 0 ou tente extrair se possível
        pkt["delta"] = 0
        pkt["tcp_flags"] = ""
    except Exception:
        pkt["protocol"] = "unknown"
        pkt["length"] = len(pkt_str)
        pkt["port"] = 0
        pkt["delta"] = 0
        pkt["tcp_flags"] = ""
    return pkt

# --- Menu atualizado ---
def menu():
    print(Fore.CYAN + """
[1] Scan avançado de rede (Syra & TLS)
[2] Scan rápido (hosts e portas comuns)
[3] Scan customizado (escolha IPs/portas)
[4] Listar pontos de rede (gateway, DNS)
[5] Sniffer de pacotes (PyShark/Wireshark-like)
[6] Deep Packet Inspection (DPI)
[7] Gerar relatório PDF do último resultado
[8] WHOIS/DNS de domínio
[9] Calcular hash SHA256 de arquivo
[10] Monitorar tráfego de rede em tempo real
[11] Detectar anomalias no tráfego de rede
[12] Fingerprinting de SO (OS e TCP)
[0] Sair
""")
    return input(Fore.YELLOW + "Escolha uma opção: ")

if __name__ == "__main__":
    print_banner()
    project_dir = ensure_project_dir()
    last_results = []
    while True:
        op = menu()
        if op == "1":
            alvo = input("Alvo (IP, range, CIDR ex: 192.168.1.0/24): ")
            last_results = advanced_network_scan(alvo, mode="full")
            print('\n'.join(last_results))
        elif op == "2":
            alvo = input("Alvo (IP, range, CIDR): ")
            last_results = advanced_network_scan(alvo, mode="fast")
            print('\n'.join(last_results))
        elif op == "3":
            alvo = input("Alvo (IP, range, CIDR): ")
            portas = input("Portas (ex: 22,80,443): ")
            portas = [int(p) for p in portas.split(",") if p.strip().isdigit()]
            last_results = advanced_network_scan(alvo, ports=portas, mode="custom")
            print('\n'.join(last_results))
        elif op == "4":
            print(show_network_points())
        elif op == "5":
            iface = input("Interface para sniffer (deixe em branco para todas): ")
            count = int(input("Quantos pacotes capturar? [100]: ") or "100")
            pcap_path = os.path.join(project_dir, f"trafego_{int(time.time())}.pcap")
            packets = pyshark_sniffer(iface, count, save_pcap=pcap_path)
            print('\n'.join(packets))
            print(f"[+] Pacotes salvos em: {pcap_path}")
        elif op == "6":
            iface = input("Interface para DPI (deixe em branco para todas): ")
            count = int(input("Quantos pacotes analisar? [100]: ") or "100")
            dpi = deep_packet_inspection(iface, count)
            print('\n'.join(dpi))
        elif op == "7":
            if not last_results:
                print("Nenhum resultado para salvar!")
            else:
                pdf_path = os.path.join(project_dir, f"SYRA_TLS_SCAN_{int(time.time())}.pdf")
                save_results_pdf(last_results, pdf_path)
        elif op == "8":
            domain = input("Domínio para WHOIS/DNS: ")
            print(whois_lookup(domain))
            print(dns_scan(domain))
        elif op == "9":
            filepath = input("Caminho do arquivo para hash SHA256: ")
            print(hash_file(filepath))
        elif op == "10":
            iface = input("Interface para monitoramento (deixe em branco para todas): ")
            live_traffic_monitor(iface if iface else None)
        elif op == "11":
            iface = input("Interface para análise de anomalias (deixe em branco para todas): ")
            count = int(input("Quantos pacotes capturar? [100]: ") or "100")
            packets = pyshark_sniffer(iface, count)
            # Converte as strings em dicionários
            parsed_packets = [parse_packet_string(pkt) for pkt in packets]
            anomaly_indices = detect_traffic_anomalies(parsed_packets)
            if anomaly_indices:
                anomaly_report = analyze_anomalous_packets(parsed_packets, anomaly_indices)
                for anomaly in anomaly_report:
                    print(f"Anomalia detectada no pacote {anomaly['packet_index']}:")
                    print(f"  Dados do pacote: {anomaly['packet_data']}")
                    print(f"  Possíveis razões: {', '.join(anomaly['possible_reasons'])}")
        elif op == "12":
            ip = input("Digite o IP para fingerprinting: ")
            os_result = os_fingerprint(ip)
            print(f"Resultado OS Fingerprinting: {os_result}")
            tcp_result = tcp_fingerprinting(ip)
            print(f"Resultado TCP Fingerprinting: {tcp_result}")
        elif op == "0":
            print("Saindo...")
            break
        else:
            print("Opção inválida.")