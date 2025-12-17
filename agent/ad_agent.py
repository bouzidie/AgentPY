#!/usr/bin/env python3
"""
Agent de reconnaissance Active Directory
Script autonome pour collecter les informations du réseau
"""

import sys
import os
import json
import time
from datetime import datetime
from typing import Dict, List

# Ajouter le chemin du module collector
sys.path.append(os.path.join(os.path.dirname(__file__), 'collector'))

from collector.network import PassiveNetworkScanner, ActivePortScanner, get_local_ip, get_mac_address
from collector.ad import LDAPCollector
from collector.local import get_local_machine_info


class ADAgent:
    """
    Agent principal de reconnaissance Active Directory
    """
    
    def __init__(self, server_url: str = None):
        """
        Initialiser l'agent
        
        Args:
            server_url: URL du serveur central (optionnel)
        """
        self.server_url = server_url or 'http://localhost:5000/api/v1/report'
        self.local_info = {}
        self.discovered_hosts = []
        self.network_scan_results = []
        self.users = []
        self.machines = []
        self.spn_accounts = []
        
    def run(self):
        """
        Exécuter l'agent complet
        """
        print("=" * 80)
        print("Agent de Reconnaissance Active Directory")
        print("=" * 80)
        print()
        
        # Collecte des informations locales
        print("[1/5] Collecte des informations locales...")
        self.collect_local_info()
        print()
        
        # Scan passif du réseau
        print("[2/5] Scan passif du réseau (écoute UDP)...")
        self.scan_passive_network()
        print()
        
        # Scan actif des ports
        print("[3/5] Scan actif des ports critiques...")
        self.scan_active_ports()
        print()
        
        # Interrogation Active Directory
        print("[4/5] Interrogation Active Directory via LDAP...")
        self.collect_ad_info()
        print()
        
        # Préparation du rapport
        print("[5/5] Préparation du rapport...")
        report = self.prepare_report()
        print()
        
        # Affichage du résumé
        self.print_summary(report)
        
        # Envoi du rapport au serveur
        if self.server_url:
            print()
            print("[ENVOI] Envoi du rapport au serveur...")
            self.send_report(report)
        else:
            print()
            print("[INFO] Aucune URL de serveur spécifiée, le rapport n'a pas été envoyé.")
            print("[INFO] Sauvegarde du rapport dans un fichier local...")
            self.save_report_local(report)
        
        print()
        print("=" * 80)
        print("Agent terminé avec succès!")
        print("=" * 80)
    
    def collect_local_info(self):
        """
        Collecter les informations locales de la machine
        """
        from collector.local import get_local_machine_info
        self.local_info = get_local_machine_info()
    
    def scan_passive_network(self):
        """
        Scanner le réseau passivement via UDP
        """
        from collector.network import PassiveNetworkScanner
        import os
        
        # Timeout configurable via env var AGENT_PASSIVE_TIMEOUT (seconds)
        passive_timeout = int(os.getenv('AGENT_PASSIVE_TIMEOUT', '10'))
        scanner = PassiveNetworkScanner(timeout=passive_timeout)
        scanner.start_capture()
        self.discovered_hosts = scanner.get_discovered_hosts()
    
    def scan_active_ports(self):
        """
        Scanner les ports critiques de manière active
        """
        from collector.network import ActivePortScanner
        import os
        
        # Timeout configurable via env var AGENT_ACTIVE_PORT_TIMEOUT (seconds)
        active_timeout = float(os.getenv('AGENT_ACTIVE_PORT_TIMEOUT', '1.0'))
        
        # Scanner les hôtes découverts passivement
        if self.discovered_hosts:
            hosts = [host['ip'] for host in self.discovered_hosts]
            
            scanner = ActivePortScanner(timeout=active_timeout)
            self.network_scan_results = scanner.scan_hosts(hosts)
        else:
            # Scanner l'adresse IP locale
            local_ip = self.local_info.get('ip_address', '127.0.0.1')
            scanner = ActivePortScanner(timeout=active_timeout)
            self.network_scan_results = scanner.scan_hosts([local_ip])
    
    def collect_ad_info(self):
        """
        Collecter les informations Active Directory via LDAP
        """
        from collector.ad import LDAPCollector
        import os
        
        ldap_user = os.getenv('AD_LDAP_USER')
        ldap_pass = os.getenv('AD_LDAP_PASS')
        
        # Tenter en priorité les IPs où le port 389 a été trouvé ouvert
        ldap_ips = []
        if self.network_scan_results:
            ldap_ips = [r['host'] for r in self.network_scan_results if r.get('port') == 389 and r.get('is_open')]
        
        connected = False
        for ip in ldap_ips:
            ldap_collector = LDAPCollector(domain_controller=ip, user=ldap_user, password=ldap_pass)
            if ldap_collector.connect():
                self.users = ldap_collector.get_users()
                self.machines = ldap_collector.get_machines()
                self.spn_accounts = ldap_collector.get_spn_accounts()
                ldap_collector.close()
                connected = True
                break
        
        # Si aucune IP n'a fonctionné, essayer la découverte automatique (fallback)
        if not connected:
            ldap_collector = LDAPCollector(user=ldap_user, password=ldap_pass)
            if ldap_collector.connect():
                self.users = ldap_collector.get_users()
                self.machines = ldap_collector.get_machines()
                self.spn_accounts = ldap_collector.get_spn_accounts()
                ldap_collector.close()
            else:
                print("[WARNING] Impossible de se connecter au contrôleur de domaine. Les informations AD ne seront pas collectées.")
    
    def prepare_report(self) -> Dict:
        """
        Préparer le rapport final
        
        Returns:
            Dictionnaire contenant le rapport complet
        """
        report = {
            'agent_name': self.local_info.get('hostname', 'UNKNOWN'),
            'domain_name': self.local_info.get('domain_name', 'UNKNOWN_DOMAIN'),
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': self.local_info.get('ip_address', '127.0.0.1'),
            'mac_address': self.local_info.get('mac_address', 'UNKNOWN'),
            'raw_data': {
                'local_info': self.local_info,
                'network_scan': self.network_scan_results,
                'users': self.users,
                'machines': self.machines,
                'spn_accounts': self.spn_accounts
            },
            'users_count': len(self.users),
            'machines_count': len(self.machines),
            'spn_accounts_count': len(self.spn_accounts)
        }
        
        return report
    
    def send_report(self, report: Dict):
        """
        Envoyer le rapport au serveur central
        
        Args:
            report: Rapport à envoyer
        """
        try:
            import requests
            
            # Envoyer le rapport au serveur
            response = requests.post(
                self.server_url,
                json=report,
                timeout=10
            )
            
            if response.status_code == 201:
                print("[SUCCESS] Rapport envoyé avec succès au serveur!")
                print(f"[INFO] ID du rapport: {response.json().get('report_id')}")
            else:
                print(f"[ERROR] Erreur lors de l'envoi du rapport: {response.status_code}")
                print(f"[ERROR] Message: {response.text}")
                
        except Exception as e:
            print(f"[ERROR] Impossible d'envoyer le rapport: {e}")
            print("[INFO] Sauvegarde du rapport dans un fichier local...")
            self.save_report_local(report)
    
    def save_report_local(self, report: Dict):
        """
        Sauvegarder le rapport dans un fichier local
n        
        Args:
            report: Rapport à sauvegarder
        """
        try:
            # Créer le nom du fichier
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"ad_report_{timestamp}.json"
            
            # Sauvegarder le rapport
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            print(f"[SUCCESS] Rapport sauvegardé dans: {filename}")
            
        except Exception as e:
            print(f"[ERROR] Impossible de sauvegarder le rapport: {e}")
    
    def print_summary(self, report: Dict):
        """
        Afficher un résumé du rapport
        
        Args:
            report: Rapport à afficher
        """
        print("=" * 80)
        print("RÉSUMÉ DU RAPPORT")
        print("=" * 80)
        print()
        
        print(f"Agent: {report['agent_name']}")
        print(f"Domaine: {report['domain_name']}")
        print(f"Adresse IP: {report['ip_address']}")
        print(f"Adresse MAC: {report['mac_address']}")
        print(f"Horodatage: {report['timestamp']}")
        print()
        
        print("STATISTIQUES:")
        print(f"  - Utilisateurs: {report['users_count']}")
        print(f"  - Machines: {report['machines_count']}")
        print(f"  - Comptes SPN: {report['spn_accounts_count']}")
        print(f"  - Ports scannés: {len(report['raw_data']['network_scan'])}")
        print()
        
        # Afficher les ports ouverts
        open_ports = [p for p in report['raw_data']['network_scan'] if p['is_open']]
        if open_ports:
            print("PORTS OUVERTS DÉTECTÉS:")
            for port in open_ports[:10]:  # Afficher les 10 premiers
                print(f"  - {port['host']}:{port['port']} ({port['service_name']})")
            if len(open_ports) > 10:
                print(f"  ... et {len(open_ports) - 10} autres ports ouverts")
        print()
        
        # Afficher les comptes SPN
        if report['spn_accounts_count'] > 0:
            print(f"COMPTES AVEC SPN DÉTECTÉS: {report['spn_accounts_count']}")
            print("  Ces comptes sont vulnérables à l'attaque Kerberoasting!")
            print()
        
        print("=" * 80)


if __name__ == '__main__':
    # Créer l'agent
    agent = ADAgent()
    
    # Exécuter l'agent
    agent.run()
