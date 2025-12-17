"""
Module de collecte réseau passif
Écoute UDP pour découvrir les machines du réseau
"""

import socket
import struct
import time
from typing import List, Dict


class PassiveNetworkScanner:
    """
    Scanner réseau passif utilisant UDP
    Capture les requêtes réseau pour découvrir les machines
    """
    
    def __init__(self, timeout: int = 30):
        """
        Initialiser le scanner passif
        
        Args:
            timeout: Durée d'écoute en secondes
        """
        self.timeout = timeout
        self.discovered_hosts = {}
        self.udp_socket = None
        
    def start_capture(self):
        """
        Démarrer la capture UDP
        """
        try:
            # Créer un socket UDP
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.settimeout(self.timeout)
            
            # Se connecter à un port aléatoire
            self.udp_socket.bind(('0.0.0.0', 0))
            
            print(f"[INFO] Démarrage de la capture UDP sur {self.udp_socket.getsockname()}")
            
            # Temps de début
            start_time = time.time()
            
            while time.time() - start_time < self.timeout:
                try:
                    # Recevoir un paquet
                    data, addr = self.udp_socket.recvfrom(8192)
                    
                    # Extraire l'adresse IP source
                    ip_address = addr[0]
                    
                    # Stocker les informations
                    if ip_address not in self.discovered_hosts:
                        self.discovered_hosts[ip_address] = {
                            'ip': ip_address,
                            'first_seen': time.time(),
                            'last_seen': time.time(),
                            'packets': 1,
                            'ports': set()
                        }
                    else:
                        self.discovered_hosts[ip_address]['packets'] += 1
                        self.discovered_hosts[ip_address]['last_seen'] = time.time()
                        self.discovered_hosts[ip_address]['ports'].add(addr[1])
                    
                except socket.timeout:
                    break
                except Exception as e:
                    print(f"[ERROR] Erreur lors de la réception: {e}")
                    break
            
            print(f"[INFO] Capture UDP terminée. {len(self.discovered_hosts)} hôtes découverts.")
            
        except Exception as e:
            print(f"[ERROR] Erreur lors de la capture UDP: {e}")
        
        finally:
            if self.udp_socket:
                self.udp_socket.close()
    
    def get_discovered_hosts(self) -> List[Dict]:
        """
        Récupérer la liste des hôtes découverts
        
        Returns:
            Liste de dictionnaires contenant les informations des hôtes
        """
        hosts = []
        for host_info in self.discovered_hosts.values():
            host_info['ports'] = list(host_info['ports'])
            hosts.append(host_info)
        return hosts


class ActivePortScanner:
    """
    Scanner de ports actif léger
    Vérifie l'ouverture des ports critiques
    """
    
    def __init__(self, timeout: float = 2.0):
        """
        Initialiser le scanner de ports
        
        Args:
            timeout: Timeout pour chaque connexion
        """
        self.timeout = timeout
        self.critical_ports = {
            445: 'SMB',   # Server Message Block
            389: 'LDAP',  # Lightweight Directory Access Protocol
            88: 'Kerberos',  # Kerberos authentication
            53: 'DNS'    # Domain Name System
        }
    
    def scan_host(self, host: str, port: int) -> Dict:
        """
        Scanner un port spécifique sur un hôte
        
        Args:
            host: Adresse IP ou hostname
            port: Numéro de port
        
        Returns:
            Dictionnaire avec les résultats du scan
        """
        try:
            # Créer un socket TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Tenter de se connecter
            result = sock.connect_ex((host, port))
            
            is_open = result == 0
            service_name = self.critical_ports.get(port, 'Unknown')
            
            sock.close()
            
            return {
                'host': host,
                'port': port,
                'service_name': service_name,
                'is_open': is_open,
                'status': 'open' if is_open else 'closed'
            }
            
        except Exception as e:
            return {
                'host': host,
                'port': port,
                'service_name': self.critical_ports.get(port, 'Unknown'),
                'is_open': False,
                'status': 'error',
                'error': str(e)
            }
    
    def scan_hosts(self, hosts: List[str]) -> List[Dict]:
        """
        Scanner plusieurs hôtes pour les ports critiques
        
        Args:
            hosts: Liste des adresses IP ou hostnames
        
        Returns:
            Liste des résultats de scan
        """
        results = []
        
        for host in hosts:
            for port in self.critical_ports.keys():
                result = self.scan_host(host, port)
                results.append(result)
                
                if result['is_open']:
                    print(f"[INFO] Port {port}/{result['service_name']} ouvert sur {host}")
        
        return results
    
    def scan_subnet(self, ip_address: str, subnet_mask: int = 24) -> List[Dict]:
        """
        Scanner une plage de sous-réseau (ex: 10.0.3.0/24)
        
        Args:
            ip_address: Une adresse IP du sous-réseau (ex: 10.0.3.15)
            subnet_mask: CIDR notation (par défaut 24)
        
        Returns:
            Liste des résultats de scan
        """
        import ipaddress
        
        try:
            # Créer l'objet réseau à partir de l'IP et du subnet
            ip_obj = ipaddress.ip_address(ip_address)
            network = ipaddress.ip_network(f"{ip_obj}/{subnet_mask}", strict=False)
            
            results = []
            host_count = 0
            
            print(f"[INFO] Scan du sous-réseau {network}")
            
            # Parcourir les hôtes du réseau
            for host in network.hosts():  # Exclut le réseau et broadcast
                host_str = str(host)
                for port in self.critical_ports.keys():
                    result = self.scan_host(host_str, port)
                    results.append(result)
                    
                    if result['is_open']:
                        print(f"[INFO] Port {port}/{result['service_name']} ouvert sur {host_str}")
                        host_count += 1
            
            print(f"[INFO] Scan du sous-réseau terminé. {host_count} services trouvés.")
            return results
            
        except Exception as e:
            print(f"[ERROR] Erreur lors du scan du sous-réseau: {e}")
            return []


# Fonction utilitaire pour obtenir l'adresse IP locale

def get_local_ip() -> str:
    """
    Obtenir l'adresse IP locale de la machine
    
    Returns:
        Adresse IP locale
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"[ERROR] Impossible d'obtenir l'adresse IP locale: {e}")
        return "127.0.0.1"


def get_all_network_interfaces() -> List[Dict]:
    """
    Obtenir toutes les interfaces réseau actives et leurs informations
    (important pour les machines avec plusieurs NICs)
    
    Returns:
        Liste de dictionnaires avec 'ip', 'subnet', 'gateway'
    """
    import subprocess
    import ipaddress
    
    interfaces = []
    
    try:
        # Sur Windows, utiliser ipconfig /all pour parser les interfaces
        result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=10)
        
        current_interface = None
        for line in result.stdout.split('\n'):
            line_stripped = line.strip()
            
            # Détection d'une nouvelle interface (commence sans espace)
            if line and not line.startswith(' ') and ':' in line:
                if current_interface and 'ip' in current_interface and current_interface['ip']:
                    interfaces.append(current_interface)
                # Extraire le nom (avant le ':')
                name = line.split(':')[0].strip()
                current_interface = {'name': name, 'ip': None, 'subnet': None, 'subnet_mask': None}
            
            # Extraction IP (ligne indentée)
            if current_interface and line.startswith(' '):
                if 'Adresse IPv4' in line or 'IPv4 Address' in line:
                    ip_str = line.split(':')[1].strip() if ':' in line else ''
                    if ip_str and ip_str != '' and ip_str != '127.0.0.1':
                        current_interface['ip'] = ip_str
                
                # Extraction masque
                if 'Masque de sous-réseau' in line or 'Subnet Mask' in line:
                    mask_str = line.split(':')[1].strip() if ':' in line else ''
                    if mask_str and mask_str != '':
                        current_interface['subnet_mask'] = mask_str
                        # Calculer le subnet à partir de l'IP et du masque
                        try:
                            if current_interface.get('ip'):
                                net = ipaddress.ip_network(f"{current_interface['ip']}/{mask_str}", strict=False)
                                current_interface['subnet'] = str(net)
                        except Exception:
                            pass
        
        # Ajouter la dernière interface
        if current_interface and 'ip' in current_interface and current_interface['ip']:
            interfaces.append(current_interface)
        
        # Filtrer les interfaces sans IP valide et sans 127.0.0.1
        valid_interfaces = [i for i in interfaces if i.get('ip') and i['ip'] != '127.0.0.1']
        
        if valid_interfaces:
            print(f"[INFO] {len(valid_interfaces)} interface(s) réseau détectée(s):")
            for iface in valid_interfaces:
                print(f"  - {iface['name']}: {iface['ip']} ({iface.get('subnet', 'N/A')})")
        
        return valid_interfaces
        
    except Exception as e:
        print(f"[ERROR] Erreur lors de la détection des interfaces: {e}")
        return []


# Fonction utilitaire pour obtenir l'adresse MAC

def get_mac_address() -> str:
    """
    Obtenir l'adresse MAC de la machine
    
    Returns:
        Adresse MAC
    """
    try:
        import uuid
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                       for elements in range(0, 8*8, 8)][::-1])
        return mac.upper()
    except Exception as e:
        print(f"[ERROR] Impossible d'obtenir l'adresse MAC: {e}")
        return "UNKNOWN"
