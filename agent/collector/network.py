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
