"""
Module de collecte des informations locales
Récupère les informations système de la machine
"""

import platform
import socket
import subprocess
import re
from typing import Dict


def get_local_machine_info() -> Dict:
    """
    Récupérer les informations locales de la machine
    
    Returns:
        Dictionnaire avec les informations de la machine
    """
    # Récupérer toutes les IPs disponibles
    from .network import get_all_network_interfaces
    all_ips = []
    try:
        interfaces = get_all_network_interfaces()
        all_ips = [iface.get('ip') for iface in interfaces if iface.get('ip')]
    except:
        all_ips = [get_ip_address()]
    
    # Trier: 70.70.70.x (domaine) en premier, puis les autres
    domain_ips = [ip for ip in all_ips if ip.startswith('70.70.70.')]
    other_ips = [ip for ip in all_ips if not ip.startswith('70.70.70.')]
    sorted_ips = domain_ips + other_ips
    
    info = {
        'hostname': get_hostname(),
        'os_name': get_os_name(),
        'os_version': get_os_version(),
        'os_platform': get_os_platform(),
        'architecture': get_architecture(),
        'ip_address': sorted_ips[0] if sorted_ips else get_ip_address(),
        'all_ip_addresses': sorted_ips,
        'mac_address': get_mac_address(),
        'domain_name': get_domain_name(),
        'workgroup': get_workgroup()
    }
    
    print(f"[INFO] Informations locales récupérées:")
    print(f"  - Nom d'hôte: {info['hostname']}")
    print(f"  - OS: {info['os_name']} {info['os_version']}")
    print(f"  - Domaine: {info['domain_name']}")
    print(f"  - IP Primaire: {info['ip_address']}")
    if len(sorted_ips) > 1:
        print(f"  - Toutes les IPs: {', '.join(sorted_ips)}")
    
    return info


def get_hostname() -> str:
    """
    Récupérer le nom d'hôte de la machine
    
    Returns:
        Nom d'hôte
    """
    return socket.gethostname()


def get_os_name() -> str:
    """
    Récupérer le nom du système d'exploitation
    
    Returns:
        Nom du système d'exploitation
    """
    return platform.system()


def get_os_version() -> str:
    """
    Récupérer la version du système d'exploitation
    
    Returns:
        Version du système d'exploitation
    """
    return platform.version()


def get_os_platform() -> str:
    """
    Récupérer la plateforme du système d'exploitation
    
    Returns:
        Plateforme (ex: Windows-10-10.0.19045-SP0)
    """
    return platform.platform()


def get_architecture() -> str:
    """
    Récupérer l'architecture du système
    
    Returns:
        Architecture (ex: 64bit)
    """
    return platform.architecture()[0]


def get_ip_address() -> str:
    """
    Récupérer l'adresse IP locale de la machine
    
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


def get_mac_address() -> str:
    """
    Récupérer l'adresse MAC de la machine
    
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


def get_domain_name() -> str:
    """
    Récupérer le nom du domaine Active Directory
    
    Returns:
        Nom du domaine
    """
    try:
        # Sur Windows, essayer plusieurs méthodes
        if platform.system() == 'Windows':
            # Méthode 1: wmic (plus fiable sur domaine)
            try:
                result = subprocess.run(['wmic', 'computersystem', 'get', 'domain'], 
                                      capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=5)
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and line != 'Domain' and line != 'WORKGROUP':
                        return line
            except Exception:
                pass
            
            # Méthode 2: systeminfo
            try:
                result = subprocess.run(['systeminfo'], capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=5)
                for line in result.stdout.split('\n'):
                    if 'Domain:' in line:
                        domain = line.split(':')[1].strip()
                        if domain != 'WORKGROUP':
                            return domain
            except Exception:
                pass
            
            # Méthode 3: ipconfig /all (rechercher le suffixe DNS primaire)
            try:
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=5)
                for line in result.stdout.split('\n'):
                    if 'Suffixe DNS primaire' in line or 'Primary DNS Suffix' in line:
                        domain = line.split(':')[1].strip()
                        if domain and domain != '(vide)':
                            return domain
            except Exception:
                pass
        
        # Méthode 4: utiliser hostname FQDN
        try:
            result = subprocess.run(['hostname', '-f'], capture_output=True, text=True, timeout=5)
            hostname = result.stdout.strip()
            if '.' in hostname:
                parts = hostname.split('.')
                if len(parts) > 1:
                    return '.'.join(parts[1:])
        except Exception:
            pass
        
        # Fallback: essayer hostname simple
        try:
            result = subprocess.run(['hostname'], capture_output=True, text=True, timeout=5)
            hostname = result.stdout.strip()
            if '.' in hostname:
                parts = hostname.split('.')
                if len(parts) > 1:
                    return '.'.join(parts[1:])
        except Exception:
            pass
        
        return "UNKNOWN_DOMAIN"
        
    except Exception as e:
        print(f"[ERROR] Impossible d'obtenir le nom du domaine: {e}")
        return "UNKNOWN_DOMAIN"


def get_workgroup() -> str:
    """
    Récupérer le nom du workgroup
    
    Returns:
        Nom du workgroup
    """
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['systeminfo'], capture_output=True, text=True, encoding='utf-8', errors='ignore')
            for line in result.stdout.split('\n'):
                if 'Workgroup:' in line:
                    return line.split(':')[1].strip()
        
        return "WORKGROUP"
        
    except Exception as e:
        print(f"[ERROR] Impossible d'obtenir le workgroup: {e}")
        return "WORKGROUP"


def get_network_interfaces() -> list:
    """
    Récupérer les informations des interfaces réseau
    
    Returns:
        Liste des interfaces réseau
    """
    interfaces = []
    
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, encoding='utf-8', errors='ignore')
            
            current_interface = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == 'Description':
                        if current_interface:
                            interfaces.append(current_interface)
                        current_interface = {'name': value}
                    elif key in ['Physical Address', 'IP Address', 'IPv4 Address']:
                        current_interface[key] = value
            
            if current_interface:
                interfaces.append(current_interface)
        else:
            # Pour Linux/Mac
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            
            current_interface = {}
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith(' '):
                    if current_interface:
                        interfaces.append(current_interface)
                    current_interface = {'name': line.split(':')[0]}
                elif 'inet ' in line:
                    current_interface['IP Address'] = line.split()[1]
                elif 'ether ' in line:
                    current_interface['Physical Address'] = line.split()[1]
            
            if current_interface:
                interfaces.append(current_interface)
        
    except Exception as e:
        print(f"[ERROR] Impossible d'obtenir les interfaces réseau: {e}")
    
    return interfaces


def get_firewall_status() -> str:
    """
    Récupérer l'état du pare-feu
    
    Returns:
        État du pare-feu (ex: 'Enabled', 'Disabled')
    """
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                  capture_output=True, text=True, encoding='utf-8', errors='ignore')
            
            for line in result.stdout.split('\n'):
                if 'State' in line:
                    state = line.split(':')[1].strip()
                    return state
        
        return "UNKNOWN"
        
    except Exception as e:
        print(f"[ERROR] Impossible d'obtenir l'état du pare-feu: {e}")
        return "UNKNOWN"
