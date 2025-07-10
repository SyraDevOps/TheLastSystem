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
import time
import pickle
import queue
from tqdm import tqdm
from colorama import Fore, Style

# --- Novos imports para recursos avançados ---
import asyncio
from multiprocessing import Pool
import glob
import importlib.util
import numpy as np
from typing import List, Dict, Optional, Union, Tuple, Any, Callable
import json
from datetime import datetime
#pytest é para testes, não é necessário para a execução do script principal
#import pytest
import matplotlib.pyplot as plt
from io import BytesIO
import base64

# --- Auto-installer para required libraries ---
# Lista de dependências principais e avançadas
REQUIRED_LIBS = [
    'socket', 'psutil', 'platform', 'netifaces', 'concurrent.futures',
    'scapy', 'pyshark', 'requests', 'fpdf', 'whois', 'cryptography', 'colorama',
    'numpy', 'scikit-learn', 'python-nmap', 'matplotlib', 'ipaddress'
]

def check_and_install():
    """Verifica e instala as dependências necessárias."""
    print(Fore.YELLOW + "[*] Verificando dependências..." + Style.RESET_ALL)
    installed = True
    for lib in REQUIRED_LIBS:
        # Pacotes como scapy.all são importados do pacote 'scapy'
        pkg_name = lib.split('.')[0]
        try:
            # Para scapy, o nome do pacote pip é diferente
            if pkg_name == 'scapy':
                importlib.import_module('scapy.all')
            else:
                importlib.import_module(pkg_name)
        except ImportError:
            installed = False
            print(Fore.RED + f"[!] Dependência '{pkg_name}' não encontrada. Instalando..." + Style.RESET_ALL)
            try:
                # Trata casos especiais de nome de pacote pip
                pip_name = 'python-nmap' if pkg_name == 'nmap' else pkg_name
                pip_name = 'pyshark' if pkg_name == 'pyshark' else pip_name # pyshark-legacy pode ser necessário
                subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])
                print(Fore.GREEN + f"[+] '{pip_name}' instalado com sucesso." + Style.RESET_ALL)
            except subprocess.CalledProcessError as e:
                print(Fore.RED + f"[ERRO] Falha ao instalar '{pip_name}': {e}" + Style.RESET_ALL)
                sys.exit(1)
    if installed:
        print(Fore.GREEN + "[+] Todas as dependências estão satisfeitas." + Style.RESET_ALL)


check_and_install()

# --- Imports (garantidos após a verificação) ---
import socket
import psutil
import platform
import netifaces
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, TCP, UDP
import pyshark
import requests
from fpdf import FPDF
import whois
from cryptography.hazmat.primitives import hashes
from ipaddress import ip_network, ip_address

# --- Configuração de logging estruturado ---
LOG_DIR = "SYRA_TLS_REPORTS"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "syra_tls.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# --- Parâmetros globais de timeout ---
DEFAULT_TCP_TIMEOUT = 0.5
DEFAULT_UDP_TIMEOUT = 1.0 # UDP precisa de mais tempo
DEFAULT_SNMP_TIMEOUT = 2
DEFAULT_SMB_TIMEOUT = 2
DEFAULT_ICMP_TIMEOUT = 1

# --- Banner ---
def print_banner():
    """Exibe o banner do programa."""
    banner = r"""
███████╗██╗   ██╗██████╗ █████╗     ██╗  ██╗██╗      ███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔══██╗    ██║  ██║██║      ██╔════╝
███████╗ ╚████╔╝ ██████╔╝███████║    ███████║██║      ███████╗
╚════██║  ╚██╔╝  ██╔══██╗██╔══██║    ██╔══██║██║      ╚════██║
███████║   ██║   ██║  ██║██║  ██║    ██║  ██║███████╗███████║
╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝╚══════╝
    """
    print(Fore.CYAN + banner + Style.RESET_ALL)
    print("        HAVEN - Next-Gen Network Scanner & Forensics Suite\n")
    print("                 Developed by SYRADEVOPS - TLS\n")


# --- Diretório do projeto ---
def ensure_project_dir():
    """Garante que o diretório de relatórios exista."""
    project_dir = os.path.join(os.getcwd(), LOG_DIR)
    if not os.path.exists(project_dir):
        os.makedirs(project_dir)
    return project_dir


# --- Funções de Monitoramento de Dispositivos (Novas) ---

def monitorar_trafego_dispositivo(ip=None, mac=None, interface=None, packet_count=100):
    """
    Monitora o tráfego de rede de um IP ou MAC específico.
    """
    if not ip and not mac:
        print(Fore.RED + "[ERRO] É necessário fornecer um IP ou MAC." + Style.RESET_ALL)
        return

    target_str = ip or mac
    print(Fore.CYAN + f"[INFO] Monitorando tráfego de '{target_str}' na interface '{interface or 'todas'}'...")
    
    cap = pyshark.LiveCapture(interface=interface)
    count = 0
    try:
        for pkt in cap.sniff_continuously():
            try:
                if ip and hasattr(pkt, 'ip') and (pkt.ip.src == ip or pkt.ip.dst == ip):
                    print(pkt)
                    count += 1
                elif mac and hasattr(pkt, 'eth') and (pkt.eth.src.lower() == mac.lower() or pkt.eth.dst.lower() == mac.lower()):
                    print(pkt)
                    count += 1
                
                if count >= packet_count:
                    break
            except AttributeError:
                # Pacote não tem o atributo esperado (ex: ARP não tem 'ip')
                continue
            except Exception as e:
                logging.warning(f"Erro ao processar pacote no monitoramento: {e}")
                continue
    except KeyboardInterrupt:
        print(Fore.CYAN + "\n[INFO] Monitoramento interrompido pelo usuário." + Style.RESET_ALL)


def consultar_mac_info():
    """
    Consulta informações detalhadas de um endereço MAC detectado na rede.
    """
    known_file = os.path.join(ensure_project_dir(), "dispositivos_conhecidos.pkl")
    relatorio_file = os.path.join(ensure_project_dir(), "relatorio_dispositivos.txt")
    
    mac = input("Digite o endereço MAC (ex: 10:27:f5:5f:a8:09): ").strip().lower()
    
    # Busca no relatório detalhado, se existir
    if os.path.exists(relatorio_file):
        with open(relatorio_file, "r", encoding="utf-8") as f:
            relatorio = f.read()
        if mac in relatorio:
            print(Fore.CYAN + f"\n[INFO] Dados detalhados do MAC {mac} encontrados no relatório:\n" + Style.RESET_ALL)
            # Mostra o bloco do dispositivo
            blocos = relatorio.split("-" * 60)
            for bloco in blocos:
                if mac in bloco:
                    print(bloco.strip())
                    return
    
    # Se não achar no relatório, busca no arquivo de dispositivos conhecidos
    if not os.path.exists(known_file):
        print(Fore.YELLOW + "[AVISO] Nenhum dispositivo conhecido salvo. Rode o monitoramento [13] primeiro." + Style.RESET_ALL)
        return

    try:
        with open(known_file, "rb") as f:
            known_devices = pickle.load(f)
    except Exception:
        print(Fore.RED + "[ERRO] Não foi possível carregar os dispositivos conhecidos." + Style.RESET_ALL)
        return
        
    for ip, mac_addr in known_devices:
        if mac_addr.lower() == mac:
            print(Fore.GREEN + f"\n[INFO] Dispositivo encontrado: IP={ip} MAC={mac_addr}" + Style.RESET_ALL)
            print(f"  Hostname: {get_hostname(ip)}")
            print(f"  Fabricante: {get_vendor(mac_addr)}")
            ports, banners = port_scan(ip, [21,22,23,25,80,443,445,3389,8080])
            print(f"  Portas abertas comuns: {ports}")
            if banners:
                for p, b in banners.items():
                    print(f"    Banner porta {p}: {b}")
            # Pode adicionar extended_scan(ip) se quiser mais detalhes
            return
            
    print(Fore.YELLOW + "[AVISO] MAC não encontrado entre os dispositivos conhecidos." + Style.RESET_ALL)


def monitorar_dispositivos_rede(interface=None, intervalo=30):
    """
    Monitora continuamente a rede local e alerta sobre novos dispositivos conectados ou desconectados.
    """
    print(Fore.CYAN + f"\n[INFO] Monitoramento contínuo iniciado (intervalo: {intervalo}s). Pressione Ctrl+C para parar." + Style.RESET_ALL)
    known_file = os.path.join(ensure_project_dir(), "dispositivos_conhecidos.pkl")
    
    # Carrega dispositivos conhecidos de execuções anteriores
    if os.path.exists(known_file):
        try:
            with open(known_file, "rb") as f:
                known_devices = pickle.load(f)
            print(Fore.CYAN + f"[INFO] {len(known_devices)} dispositivos conhecidos carregados." + Style.RESET_ALL)
        except Exception:
            known_devices = set()
    else:
        known_devices = set()

    try:
        while True:
            print(Fore.CYAN + f"[{datetime.now().strftime('%H:%M:%S')}] Verificando a rede..." + Style.RESET_ALL)
            redes = get_all_networks()
            current_devices = set()
            for iface, ip, mask in redes:
                if interface and iface != interface:
                    continue
                
                cidr = str(ip_network(f"{ip}/{mask}", strict=False))
                print(f"  -> Escaneando {cidr} via {iface}")
                devices = arp_scan(cidr, iface)
                for d in devices:
                    if 'ip' in d and 'mac' in d:
                        current_devices.add((d['ip'], d['mac']))
            
            # Novos dispositivos
            novos = current_devices - known_devices
            for ip, mac in novos:
                vendor = get_vendor(mac)
                print(Fore.GREEN + f"[ALERTA] Novo dispositivo detectado: IP={ip} MAC={mac} ({vendor})" + Style.RESET_ALL)
            
            # Dispositivos que saíram
            removidos = known_devices - current_devices
            for ip, mac in removidos:
                print(Fore.YELLOW + f"[ALERTA] Dispositivo saiu da rede: IP={ip} MAC={mac}" + Style.RESET_ALL)
            
            if novos or removidos:
                known_devices = current_devices
                # Salva estado
                with open(known_file, "wb") as f:
                    pickle.dump(known_devices, f)
                    
            time.sleep(intervalo)
    except KeyboardInterrupt:
        print(Fore.CYAN + "\n[INFO] Monitoramento interrompido pelo usuário." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"\n[ERRO] Ocorreu um erro durante o monitoramento: {e}" + Style.RESET_ALL)


# --- Coleta de informações do sistema ---
def get_system_info():
    info = []
    try:
        info.append(f"Sistema operacional: {platform.system()} {platform.release()}")
        info.append(f"Hostname: {socket.gethostname()}")
        info.append(f"Usuário: {os.getlogin()}")
        info.append(f"Tempo ligado: {datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')}")
        info.append(f"CPU: {platform.processor()}")
        info.append(f"Núcleos: {psutil.cpu_count(logical=True)}")
        info.append(f"Memória total: {round(psutil.virtual_memory().total/1024**3, 2)} GB")
    except Exception as e:
        info.append(f"Erro ao obter informações do sistema: {e}")
    return info

def list_interfaces():
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        iface_info = [f"Interface: {iface}"]
        for addr in addrs:
            if addr.family == socket.AF_INET:
                iface_info.append(f"  IP: {addr.address} / Máscara: {addr.netmask}")
            elif addr.family == psutil.AF_LINK: # psutil.AF_LINK para MAC
                iface_info.append(f"  MAC: {addr.address}")
        interfaces.append('\n'.join(iface_info))
    return interfaces

def get_all_networks():
    networks = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            # Pega apenas endereços IPv4 válidos que não sejam de loopback
            if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                ip = addr.address
                mask = addr.netmask
                if ip and mask:
                    networks.append((iface, ip, mask))
    return networks

# --- ARP Scan ---
def arp_scan(ip_range, interface, timeout=3):
    devices = []
    print(f"  -> Realizando ARP scan em {ip_range} via {interface}...")
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
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(icmp_ping, ip, timeout): ip for ip in ips}
        for future in tqdm(futures, total=len(ips), desc="ICMP Sweep", ncols=80, unit="host"):
            try:
                result = future.result()
                if result:
                    active.append(result)
            except Exception as e:
                logging.warning(f"Erro durante ICMP sweep para {futures[future]}: {e}")
    logging.info(f"ICMP sweep {ip_base}.0/24: {len(active)} ativos")
    return active

# --- TCP/UDP Port Scan ---
def port_scan(ip, ports=None, tcp_timeout=DEFAULT_TCP_TIMEOUT, udp_timeout=DEFAULT_UDP_TIMEOUT):
    if ports is None:
        ports = list(range(1, 1025))

    open_ports = []
    banners = {}
    for port in ports:
        # TCP Scan
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(tcp_timeout)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                    try:
                        # Banner grabbing simples
                        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = s.recv(1024).decode(errors='ignore').strip()
                        banners[port] = banner[:100]
                    except Exception:
                        banners[port] = "No banner"
        except Exception as e:
            logging.debug(f"TCP scan erro {ip}:{port}: {e}")

    logging.info(f"Port scan {ip}: {open_ports}")
    return open_ports, banners


# --- Funções de Informação Externa ---
def dns_scan(domain):
    try:
        result = socket.gethostbyname_ex(domain)
        return f"DNS: {result}"
    except Exception as e:
        return f"DNS Scan Error: {e}"

def whois_lookup(domain):
    try:
        import whois
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return f"WHOIS Error: {e}"

def get_vendor(mac):
    try:
        # Usar uma API online para obter o fabricante do MAC
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if response.status_code == 200:
            return response.text
        return "Desconhecido"
    except Exception:
        return "Desconhecido (API falhou)"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Desconhecido"


def show_network_points():
    gws = netifaces.gateways()
    # Extrai o gateway padrão (normalmente 'default' e AF_INET)
    default_gw = gws.get('default', {}).get(socket.AF_INET, ('N/A', 'N/A'))
    
    return f"Gateway Padrão: {default_gw[0]} (Interface: {default_gw[1]})"


# --- Funções de Sniffer e DPI ---
def get_active_interfaces():
    """Retorna lista de interfaces de rede ativas (com IP não-loopback)."""
    active = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                if iface not in active:
                    active.append(iface)
    return active

def pyshark_sniffer(interface=None, packet_count=100, save_pcap=None):
    """Sniff de pacotes com PyShark em uma ou todas as interfaces ativas."""
    interfaces = [interface] if interface else get_active_interfaces()
    if not interfaces:
        return ["[!] Nenhuma interface de rede ativa encontrada."]

    all_packets_info = []
    
    for iface in interfaces:
        print(f"\n[+] Capturando {packet_count} pacotes na interface {iface}...")
        pcap_path = None
        if save_pcap:
            # Adiciona o nome da interface ao arquivo se houver mais de uma
            if len(interfaces) > 1:
                base, ext = os.path.splitext(save_pcap)
                pcap_path = f"{base}_{iface}{ext}"
            else:
                pcap_path = save_pcap

        try:
            # Usamos um LiveCapture com um limite de pacotes
            cap = pyshark.LiveCapture(interface=iface, output_file=pcap_path)
            packets_captured = []
            
            for pkt in cap.sniff_iterator(packet_count=packet_count):
                packets_captured.append(pkt)
                try:
                    info = f"[{iface}] {pkt.sniff_time.strftime('%H:%M:%S')} {pkt.highest_layer} {pkt.ip.src} -> {pkt.ip.dst} {pkt.transport_layer} Port: {getattr(pkt[pkt.transport_layer],'dstport', '')}"
                except AttributeError:
                    info = f"[{iface}] {str(pkt)}"
                all_packets_info.append(info)

            print(f"[+] {len(packets_captured)} pacotes capturados na interface {iface}.")
            if pcap_path:
                print(f"[+] Captura salva em: {pcap_path}")

        except Exception as e:
            msg = f"[!] Erro na interface {iface}: {e}"
            print(Fore.RED + msg + Style.RESET_ALL)
            all_packets_info.append(msg)
            
    return all_packets_info


def deep_packet_inspection(interface=None, packet_count=50):
    """Realiza Deep Packet Inspection (DPI) em pacotes capturados."""
    print(f"\n[INFO] Iniciando DPI para {packet_count} pacotes...")
    interfaces = [interface] if interface else get_active_interfaces()
    all_analysis = []

    for iface in interfaces:
        try:
            print(f"[INFO] Capturando e analisando pacotes na interface: {iface}")
            cap = pyshark.LiveCapture(interface=iface)
            
            analysis_results = []
            with tqdm(total=packet_count, desc=f"DPI {iface}", ncols=80) as pbar:
                for pkt in cap.sniff_iterator(packet_count=packet_count):
                    try:
                        layers = [layer.layer_name for layer in pkt.layers]
                        summary = f"[{iface}] {pkt.sniff_time.strftime('%H:%M:%S')} Layers: {', '.join(layers)} | "
                        
                        if 'ip' in layers:
                            summary += f"{pkt.ip.src} -> {pkt.ip.dst} | "
                        if 'http' in layers and hasattr(pkt.http, 'host'):
                            summary += f"HTTP Host: {pkt.http.host}, URI: {getattr(pkt.http, 'request_uri', '')} | "
                        if 'tls' in layers and hasattr(pkt.tls, 'handshake_version'):
                            summary += f"TLS v: {pkt.tls.handshake_version} | "
                        if 'dns' in layers and hasattr(pkt.dns, 'qry_name'):
                            summary += f"DNS Query: {pkt.dns.qry_name} | "
                        
                        analysis_results.append(summary.strip(' |'))
                    except Exception as e:
                        analysis_results.append(f"[{iface}] Erro ao analisar pacote: {e}")
                    pbar.update(1)

            all_analysis.extend(analysis_results)
            print(f"[INFO] {len(analysis_results)} pacotes analisados na interface {iface}")

        except Exception as e:
            msg = f"[!] Erro de DPI na interface {iface}: {e}"
            print(Fore.RED + msg + Style.RESET_ALL)
            all_analysis.append(msg)
            
    return all_analysis

# --- Análise Forense e IA ---

def hash_file(filepath):
    """Calcula o hash SHA256 de um arquivo."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
            digest = hashes.Hash(hashes.SHA256())
            digest.update(data)
            return digest.finalize().hex()
    except FileNotFoundError:
        return "Erro: Arquivo não encontrado."
    except Exception as e:
        return f"Erro ao calcular hash: {e}"


def parse_packet_from_pyshark(pkt) -> dict:
    """Converte um objeto de pacote pyshark em um dicionário de features."""
    pkt_dict = {}
    try:
        pkt_dict['length'] = int(pkt.length)
        pkt_dict['protocol'] = pkt.highest_layer.lower()
        
        if 'tcp' in pkt.layers:
            pkt_dict['port'] = int(pkt.tcp.dstport)
        elif 'udp' in pkt.layers:
            pkt_dict['port'] = int(pkt.udp.dstport)
        else:
            pkt_dict['port'] = 0
            
    except (AttributeError, ValueError):
        # Fallback para pacotes não-IP ou malformados
        pkt_dict['length'] = pkt_dict.get('length', 0)
        pkt_dict['protocol'] = pkt_dict.get('protocol', 'unknown')
        pkt_dict['port'] = pkt_dict.get('port', 0)
        
    return pkt_dict


def extract_packet_features(packets: List[dict]) -> np.ndarray:
    """Extrai features de pacotes para uso em modelos de ML."""
    features = []
    
    proto_map = {"tcp": 1, "udp": 2, "icmp": 3, "http": 4, "dns": 5, "tls": 6, "arp": 7, "unknown": 0}
    common_ports = {80, 443, 22, 21, 25, 53, 3389}

    for pkt in packets:
        pkt_features = [
            pkt.get("length", 0),
            proto_map.get(pkt.get("protocol", "unknown"), 0),
            1 if pkt.get("port", 0) in common_ports else 0
        ]
        features.append(pkt_features)
    
    return np.array(features)

def detect_traffic_anomalies(packets: List[dict], contamination: float = 0.05) -> List[int]:
    """Detecta anomalias no tráfego de rede usando IsolationForest."""
    try:
        from sklearn.ensemble import IsolationForest
        
        print(Fore.CYAN + "[INFO] Extraindo características para análise de anomalias..." + Style.RESET_ALL)
        features = extract_packet_features(packets)
        
        if len(features) < 10:
            print(Fore.YELLOW + "[AVISO] Poucos pacotes para uma análise de anomalias confiável (mín. 10)." + Style.RESET_ALL)
            return []
            
        print(Fore.CYAN + f"[INFO] Treinando modelo de detecção de anomalias com {len(features)} pacotes..." + Style.RESET_ALL)
        
        model = IsolationForest(contamination=contamination, random_state=42)
        preds = model.fit_predict(features)
        
        anomaly_indices = [i for i, pred in enumerate(preds) if pred == -1]
        
        print(Fore.GREEN + f"[OK] {len(anomaly_indices)} anomalias em potencial detectadas." + Style.RESET_ALL)
        return anomaly_indices
        
    except ImportError:
        print(Fore.RED + "[ERRO] scikit-learn não está instalado. Use 'pip install scikit-learn'." + Style.RESET_ALL)
        return []
    except Exception as e:
        print(Fore.RED + f"[ERRO] Falha na detecção de anomalias: {e}" + Style.RESET_ALL)
        return []

# --- Fingerprinting de SO ---

def os_fingerprint(ip: str) -> dict:
    """Realiza fingerprinting do sistema operacional usando nmap."""
    try:
        import nmap
        
        print(Fore.CYAN + f"[INFO] Realizando OS fingerprinting em {ip} (requer privilégios de root)..." + Style.RESET_ALL)
        nm = nmap.PortScanner()
        # -O para detecção de SO, -T4 para velocidade, --osscan-limit para focar em hosts promissores
        # Adicionar sudo se necessário para nmap
        result = nm.scan(ip, arguments='-O -T4 --osscan-limit', sudo=True)
        
        if ip not in result['scan'] or 'osmatch' not in result['scan'][ip] or not result['scan'][ip]['osmatch']:
            return {"error": "Não foi possível identificar o SO. Tente rodar o script com sudo."}
        
        os_matches = result['scan'][ip]['osmatch']
        top_match = os_matches[0]
        os_info = {
            "os_name": top_match.get('name', 'N/A'),
            "accuracy": top_match.get('accuracy', 'N/A'),
            "type": "N/A", "vendor": "N/A", "os_family": "N/A"
        }
        
        if 'osclass' in top_match and top_match['osclass']:
            os_class = top_match['osclass'][0]
            os_info.update({
                "type": os_class.get('type', 'N/A'),
                "vendor": os_class.get('vendor', 'N/A'),
                "os_family": os_class.get('osfamily', 'N/A')
            })
        
        print(Fore.GREEN + f"[OK] SO provável: {os_info['os_name']} (precisão: {os_info['accuracy']}%)" + Style.RESET_ALL)
        return os_info
        
    except ImportError:
        print(Fore.RED + "[ERRO] 'python-nmap' não está instalado. Use 'pip install python-nmap'." + Style.RESET_ALL)
        return {"error": "python-nmap não está instalado"}
    except Exception as e:
        print(Fore.RED + f"[ERRO] Falha no fingerprinting de SO: {e}" + Style.RESET_ALL)
        return {"error": str(e)}


def tcp_fingerprinting(ip: str) -> dict:
    """Realiza fingerprinting básico baseado em TTL e Window Size do TCP/IP."""
    print(Fore.CYAN + f"[INFO] Realizando TCP fingerprinting passivo em {ip}..." + Style.RESET_ALL)
    results = {}
    try:
        # Sonda TCP para uma porta comum (80)
        resp = sr1(IP(dst=ip)/TCP(dport=80, flags="S"), timeout=2, verbose=0)
        if resp and resp.haslayer(TCP) and (resp.getlayer(TCP).flags & 0x12):  # SYN+ACK
            ttl = resp.ttl
            window_size = resp.getlayer(TCP).window
            
            results["ttl"] = ttl
            results["window"] = window_size
            
            if 100 < ttl <= 128:
                results["os_guess"] = "Windows"
            elif 60 < ttl <= 64:
                results["os_guess"] = "Linux/Unix/MacOS"
            else:
                results["os_guess"] = "Desconhecido"
            
            print(Fore.GREEN + f"[OK] Suposição baseada em TCP: {results['os_guess']} (TTL={ttl})" + Style.RESET_ALL)
            return results
        else:
            return {"error": "Não foi possível obter uma resposta TCP SYN/ACK."}
        
    except Exception as e:
        print(Fore.RED + f"[ERRO] Falha no TCP fingerprinting: {e}" + Style.RESET_ALL)
        return {"error": str(e)}


# --- Scanner de Rede Avançado e Modular ---

def advanced_network_scan(targets, ports=None, mode="full", threads=100, timeout=0.5):
    """Scanner de rede modular e com threads."""
    
    # Definição de portas padrão
    if not ports:
        if mode == "fast":
            ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080]
        else:  # full or custom
            ports = list(range(1, 1025)) + [3306, 5432, 8000, 8080, 8443]

    # Descobre IPs alvo
    ip_list = []
    try:
        if isinstance(targets, str):
            if "/" in targets:
                net = ip_network(targets, strict=False)
                ip_list = [str(ip) for ip in net.hosts()]
            elif "-" in targets:
                start, end = targets.split("-")
                start_ip, end_ip = ip_address(start.strip()), ip_address(end.strip())
                ip_list = [str(ip_address(i)) for i in range(int(start_ip), int(end_ip) + 1)]
            else:
                ip_list = [targets]
        elif isinstance(targets, list):
            ip_list = targets
    except ValueError as e:
        return [f"[!] Erro ao processar alvos: {e}"]

    results = []
    q_tasks = queue.Queue()
    for ip in ip_list:
        for port in ports:
            q_tasks.put((ip, port))

    scan_results = {}
    lock = threading.Lock()

    def worker():
        while not q_tasks.empty():
            try:
                ip, port = q_tasks.get_nowait()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        banner = ""
                        try:
                            # Tenta obter um banner
                            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                            banner_raw = s.recv(1024)
                            banner = banner_raw.decode(errors='ignore').strip().split('\n')[0]
                        except Exception:
                            pass
                        with lock:
                            if ip not in scan_results:
                                scan_results[ip] = []
                            scan_results[ip].append((port, banner[:60] if banner else "N/A"))
            except queue.Empty:
                break
            except Exception:
                pass
            finally:
                q_tasks.task_done()

    threads_list = []
    print(Fore.CYAN + f"[INFO] Escaneando {len(ip_list)} hosts e {len(ports)} portas com {threads} threads..." + Style.RESET_ALL)
    for _ in range(min(threads, q_tasks.qsize())):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads_list.append(t)

    # Adiciona uma barra de progresso
    pbar = tqdm(total=q_tasks.qsize(), desc="Scanning", unit="port")
    initial_size = q_tasks.qsize()
    while not q_tasks.empty():
        pbar.update(initial_size - q_tasks.qsize())
        initial_size = q_tasks.qsize()
        time.sleep(0.1)
    pbar.close()

    q_tasks.join()

    # Resultados organizados
    for ip in sorted(ip_list):
        if ip in scan_results:
            hostname = get_hostname(ip)
            results.append(f"\n--- Host: {ip} ({hostname}) ---")
            for port, banner in sorted(scan_results[ip]):
                results.append(f"  [+] Porta {port}/tcp ABERTA | Banner: {banner}")
        else:
            # Opção para não poluir o relatório com hosts inativos
            # results.append(f"\nHost: {ip} - Nenhuma porta aberta detectada.")
            pass
            
    return results


# --- Relatórios ---
def save_report_pdf(report_lines, filename):
    """Salva uma lista de strings em um arquivo PDF."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Courier", size=8) # Fonte monoespaçada para alinhamento
    for line in report_lines:
        try:
            pdf.multi_cell(0, 5, line)
        except UnicodeEncodeError:
            # Remove caracteres que não são compatíveis com a fonte padrão
            pdf.multi_cell(0, 5, line.encode('latin-1', 'replace').decode('latin-1'))
    
    full_path = os.path.join(ensure_project_dir(), filename)
    pdf.output(full_path)
    print(Fore.GREEN + f"[+] Relatório salvo em: {full_path}" + Style.RESET_ALL)


# --- Menu e Execução Principal ---
def menu():
    """Exibe o menu de opções."""
    print(Fore.CYAN + "\n" + "="*25 + " MENU " + "="*25)
    print("[1] Scan Rápido de Rede        (Hosts ativos e portas comuns)")
    print("[2] Scan Completo de Rede      (Alvo específico, portas 1-1024)")
    print("[3] Scan Customizado           (Escolha IPs e portas)")
    print("[4] Informações de Rede Local  (Gateway, Interfaces)")
    print("-" * 56)
    print("[5] Sniffer de Pacotes         (Captura tráfego para análise)")
    print("[6] Deep Packet Inspection     (Análise detalhada de protocolos)")
    print("[7] Monitor de Tráfego em Tempo Real")
    print("-" * 56)
    print("[8] Fingerprinting de SO       (Identifica Sistema Operacional)")
    print("[9] Monitorar Dispositivos     (Alerta sobre novos/desconectados)")
    print("[10] Consultar Info de MAC      (Busca por um MAC conhecido)")
    print("[11] Monitorar Tráfego de IP/MAC")
    print("-" * 56)
    print("[12] Detectar Anomalias (IA)    (Usa IA para achar tráfego suspeito)")
    print("[13] Utilitários Forenses     (WHOIS, DNS, Hash de arquivo)")
    print("-" * 56)
    print("[14] Gerar Relatório PDF do Último Resultado")
    print("[0] Sair")
    print("=" * 56)
    return input(Fore.YELLOW + "Escolha uma opção: " + Style.RESET_ALL)


if __name__ == "__main__":
    print_banner()
    project_dir = ensure_project_dir()
    last_results = []
    
    while True:
        op = menu()
        
        if op == "1":
            alvo = input("Alvo (CIDR da sua rede, ex: 192.168.1.0/24): ")
            last_results = advanced_network_scan(alvo, mode="fast")
            print('\n'.join(last_results))
            
        elif op == "2":
            alvo = input("Alvo (IP, range ex: 192.168.1.1-100, CIDR): ")
            last_results = advanced_network_scan(alvo, mode="full")
            print('\n'.join(last_results))

        elif op == "3":
            alvo = input("Alvo (IP, range, CIDR): ")
            portas_str = input("Portas (ex: 22,80,443, ou deixe em branco para 1-1024): ")
            portas = [int(p.strip()) for p in portas_str.split(',')] if portas_str else None
            last_results = advanced_network_scan(alvo, ports=portas)
            print('\n'.join(last_results))

        elif op == "4":
            print("\n" + Fore.GREEN + "--- INFORMAÇÕES DO SISTEMA ---" + Style.RESET_ALL)
            print('\n'.join(get_system_info()))
            print("\n" + Fore.GREEN + "--- INTERFACES DE REDE ---" + Style.RESET_ALL)
            print('\n'.join(list_interfaces()))
            print("\n" + Fore.GREEN + "--- PONTOS DE REDE ---" + Style.RESET_ALL)
            print(show_network_points())
            
        elif op == "5":
            iface = input("Interface para sniffer (deixe em branco para todas as ativas): ")
            count = int(input("Quantos pacotes capturar? [100]: ") or "100")
            pcap_file = f"captura_{int(time.time())}.pcap"
            packets_info = pyshark_sniffer(iface or None, count, save_pcap=os.path.join(project_dir, pcap_file))
            last_results = packets_info
            print('\n'.join(packets_info))

        elif op == "6":
            iface = input("Interface para DPI (deixe em branco para todas): ")
            count = int(input("Quantos pacotes analisar? [50]: ") or "50")
            dpi_results = deep_packet_inspection(iface or None, count)
            last_results = dpi_results
            print('\n'.join(dpi_results))
            
        elif op == "7":
            iface = input("Interface para monitoramento (deixe em branco para todas): ")
            # A função live_traffic_monitor já foi integrada ao DPI e sniffer
            # Esta chamada inicia um monitoramento contínuo
            deep_packet_inspection(iface or None, packet_count=999999)

        elif op == "8":
            ip = input("Digite o IP para fingerprinting: ")
            os_res = os_fingerprint(ip)
            tcp_res = tcp_fingerprinting(ip)
            last_results = [f"OS Fingerprint: {os_res}", f"TCP Fingerprint: {tcp_res}"]
            print(f"Resultado Nmap: {os_res}")
            print(f"Resultado Scapy: {tcp_res}")
            
        elif op == "9":
            iface = input("Interface para monitoramento (deixe em branco para padrão): ")
            intervalo = int(input("Intervalo entre verificações (segundos) [30]: ") or "30")
            monitorar_dispositivos_rede(iface if iface else None, intervalo)

        elif op == "10":
            consultar_mac_info()

        elif op == "11":
            alvo = input("Digite o IP ou MAC para monitorar: ").strip()
            iface = input("Interface para monitoramento (deixe em branco para padrão): ")
            count = int(input("Quantos pacotes capturar? [100]: ") or "100")
            if ":" in alvo:
                monitorar_trafego_dispositivo(mac=alvo, interface=iface or None, packet_count=count)
            else:
                monitorar_trafego_dispositivo(ip=alvo, interface=iface or None, packet_count=count)

        elif op == "12":
            iface = input("Interface para análise (deixe em branco para padrão): ")
            count = int(input("Quantos pacotes capturar para análise? [200]: ") or "200")
            
            print(Fore.CYAN + f"Capturando {count} pacotes para análise..." + Style.RESET_ALL)
            cap = pyshark.LiveCapture(interface=iface or None)
            packets_raw = [pkt for _, pkt in zip(range(count), cap.sniff_iterator())]

            parsed_packets = [parse_packet_from_pyshark(pkt) for pkt in packets_raw]
            anomaly_indices = detect_traffic_anomalies(parsed_packets)
            
            if anomaly_indices:
                print(Fore.YELLOW + "\n--- ANOMALIAS DETECTADAS ---" + Style.RESET_ALL)
                for idx in anomaly_indices:
                    print(f"Pacote anômalo #{idx}: {packets_raw[idx]}")
                    print(f"  > Features: {parsed_packets[idx]}")
                last_results = [f"Anomalia no pacote {idx}: {packets_raw[idx]}" for idx in anomaly_indices]
            else:
                print(Fore.GREEN + "Nenhuma anomalia significativa foi detectada." + Style.RESET_ALL)

        elif op == "13":
            sub_op = input("Utilitário: [1] WHOIS/DNS, [2] Hash de Arquivo: ")
            if sub_op == "1":
                domain = input("Domínio para WHOIS/DNS: ")
                print(Fore.GREEN + "--- WHOIS ---" + Style.RESET_ALL)
                print(whois_lookup(domain))
                print(Fore.GREEN + "\n--- DNS ---" + Style.RESET_ALL)
                print(dns_scan(domain))
            elif sub_op == "2":
                filepath = input("Caminho do arquivo para hash SHA256: ")
                print(f"Hash SHA256: {hash_file(filepath)}")

        elif op == "14":
            if not last_results:
                print(Fore.RED + "Nenhum resultado recente para salvar!" + Style.RESET_ALL)
            else:
                pdf_filename = f"SYRA_TLS_SCAN_{int(time.time())}.pdf"
                save_report_pdf(last_results, pdf_filename)
                
        elif op == "0":
            print(Fore.CYAN + "Saindo... Obrigado por usar o HAVEN!" + Style.RESET_ALL)
            break
            
        else:
            print(Fore.RED + "Opção inválida. Por favor, tente novamente." + Style.RESET_ALL)
