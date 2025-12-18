#!/usr/bin/env python3
"""
Agent de reconnaissance Active Directory - Version Multithreadée
Script autonome avec multithreading pour accélérer les scans
"""

import sys
import os
import json
import time
from datetime import datetime
from threading import Thread, Lock
from typing import Dict, List

# Ajouter le chemin du module collector
sys.path.append(os.path.join(os.path.dirname(__file__), 'collector'))

from collector.network import PassiveNetworkScanner, ActivePortScanner, get_local_ip, get_mac_address
from collector.ad import LDAPCollector
from collector.local import get_local_machine_info


class ADAgentMultithreaded:
    """
    Agent principal de reconnaissance Active Directory avec multithreading
    """
    
    def __init__(self, server_url: str = None, max_threads: int = 20):
        """
        Initialiser l'agent multithreadé
        
        Args:
            server_url: URL du serveur central (optionnel)
            max_threads: Nombre maximum de threads à utiliser
        """
        import os
        self.server_url = server_url or os.getenv('AGENT_SERVER_URL', 'http://localhost:5000/api/v1/report')
        # Permettre d'override via variable d'environnement AGENT_MAX_THREADS
        self.max_threads = int(os.getenv('AGENT_MAX_THREADS', str(max_threads)))
        self.local_info = {}
        self.discovered_hosts = []
        self.network_scan_results = []
        self.users = []
        self.machines = []
        self.spn_accounts = []
        self.lock = Lock()
        
    def run(self):
        """
        Exécuter l'agent complet avec multithreading
        """
        print("=" * 80)
        print("Agent de Reconnaissance Active Directory - Version Multithreadée")
        print("=" * 80)
        print()
        
        # Collecte des informations locales (séquentiel)
        print("[1/5] Collecte des informations locales...")
        self.collect_local_info()
        print()
        
        # Scan passif du réseau (séquentiel - doit être fait en premier)
        print("[2/5] Scan passif du réseau (écoute UDP)...")
        self.scan_passive_network()
        print()
        
        # Scan actif des ports (multithreadé)
        print("[3/5] Scan actif des ports critiques (multithreadé)...")
        self.scan_active_ports_multithreaded()
        print()
        
        # Interrogation Active Directory (multithreadé)
        print("[4/5] Interrogation Active Directory via LDAP (multithreadé)...")
        self.collect_ad_info_multithreaded()
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
        
        # Afficher les détails des interfaces réseau
        print()
        if self.local_info.get('all_ip_addresses'):
            print("📡 INTERFACES RÉSEAU DÉTECTÉES:")
            for i, ip in enumerate(self.local_info['all_ip_addresses'], 1):
                if ip.startswith('70.70.70.'):
                    print(f"   [{i}] {ip} ← RÉSEAU DOMAINE (70.70.70.0/24)")
                else:
                    print(f"   [{i}] {ip} ← NAT/AUTRE")
        print()
    
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
    
    def scan_active_ports_multithreaded(self):
        """
        Scanner les ports critiques de manière active avec multithreading
        """
        from collector.network import ActivePortScanner
        
        # Préparer les tâches
        tasks = []
        results = []
        
        # Scanner les hôtes découverts passivement
        if self.discovered_hosts:
            hosts = [host['ip'] for host in self.discovered_hosts]
        else:
            # Si aucun hôte découvert passivement, scanner le sous-réseau complet
            import ipaddress
            import os
            from collector.network import get_all_network_interfaces
            
            # Permettre override via env var AGENT_SCAN_NETWORK (ex: 70.70.70.0/24)
            scan_network = os.getenv('AGENT_SCAN_NETWORK')
            
            hosts = []
            
            if scan_network:
                # Utiliser le réseau fourni en env var
                print(f"[INFO] Scan du réseau spécifié: {scan_network}")
                try:
                    net = ipaddress.ip_network(scan_network, strict=False)
                    hosts = [str(h) for h in net.hosts()]
                except Exception as e:
                    print(f"[ERROR] Réseau invalide: {e}")
                    hosts = [self.local_info.get('ip_address', '127.0.0.1')]
            else:
                # Détecter tous les réseaux locaux
                # PRIORITAIRE: scanner le réseau domaine 70.70.70.0/24 d'abord
                try:
                    interfaces = get_all_network_interfaces()
                    if interfaces:
                        # Trier les interfaces pour mettre 70.70.70.x en premier
                        domain_interfaces = [i for i in interfaces if i.get('ip', '').startswith('70.70.70.')]
                        other_interfaces = [i for i in interfaces if not i.get('ip', '').startswith('70.70.70.')]
                        sorted_interfaces = domain_interfaces + other_interfaces
                        
                        print(f"[INFO] Collecte des hôtes à scanner depuis {len(sorted_interfaces)} interface(s)")
                        for iface in sorted_interfaces:
                            if iface.get('subnet'):
                                print(f"[INFO] Interface {iface['name']}: {iface['subnet']}")
                                try:
                                    net = ipaddress.ip_network(iface['subnet'], strict=False)
                                    hosts.extend([str(h) for h in net.hosts()])
                                except Exception as e:
                                    print(f"[ERROR] Erreur pour {iface['subnet']}: {e}")
                except Exception as e:
                    print(f"[ERROR] Erreur lors de la détection des interfaces: {e}")
                
                # Fallback
                if not hosts:
                    local_ip = self.local_info.get('ip_address', '127.0.0.1')
                    print(f"[INFO] Fallback: tentative sur réseau domaine 70.70.70.0/24")
                    try:
                        # Essayer d'abord le réseau domaine
                        network = ipaddress.ip_network('70.70.70.0/24', strict=False)
                        hosts = [str(h) for h in network.hosts()]
                        if not hosts:
                            # Si échec, essayer le /24 de l'IP locale
                            print(f"[INFO] Fallback sur le /24 de {local_ip}")
                            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
                            hosts = [str(h) for h in network.hosts()]
                    except Exception as e:
                        print(f"[ERROR] Erreur lors du fallback: {e}")
                        hosts = [local_ip]
        
        # Créer une fonction pour scanner un hôte
        import os
        active_timeout = float(os.getenv('AGENT_ACTIVE_PORT_TIMEOUT', '2.0'))

        def scan_host_task(host, port, results_list):
            """Tâche de scan d'un port sur un hôte"""
            try:
                scanner = ActivePortScanner(timeout=active_timeout)
                result = scanner.scan_host(host, port)
                with self.lock:
                    results_list.append(result)
            except Exception as e:
                print(f"[ERROR] Erreur lors du scan de {host}:{port}: {e}")
        
        # Créer les threads
        threads = []
        critical_ports = [445, 389, 88, 53]
        
        print(f"[INFO] Scan de {len(hosts)} hôtes sur {len(critical_ports)} ports = {len(hosts) * len(critical_ports)} tâches")
        
        for host in hosts:
            for port in critical_ports:
                while len(threads) >= self.max_threads:
                    # Attendre que certains threads se terminent
                    threads = [t for t in threads if t.is_alive()]
                    time.sleep(0.05)
                
                thread = Thread(target=scan_host_task, args=(host, port, results))
                threads.append(thread)
                thread.start()
        
        # Attendre la fin de tous les threads avec meilleure gestion du timeout
        active_threads = list(threads)
        while active_threads:
            active_threads = [t for t in active_threads if t.is_alive()]
            time.sleep(0.1)
        
        self.network_scan_results = results
        
        # Afficher les résultats
        open_ports = [p for p in results if p['is_open']]
        print(f"[INFO] Scan terminé: {len(results)} ports scannés, {len(open_ports)} ports ouverts")
        if open_ports:
            print(f"[INFO] Ports OUVERTS trouvés:")
            for port in open_ports:
                print(f"       - {port['host']}:{port['port']} ({port['service_name']})")
    
    def collect_ad_info_multithreaded(self):
        """
        Collecter les informations Active Directory via LDAP avec multithreading
        """
        from collector.ad import LDAPCollector
        import os

        ldap_user = os.getenv('AD_LDAP_USER')
        ldap_pass = os.getenv('AD_LDAP_PASS')

        # Prioriser les IPs avec 389 ouvert
        # IMPORTANT: Trier pour mettre 70.70.70.4 (DC domaine) en premier
        ldap_ips = [r['host'] for r in self.network_scan_results if r.get('port') == 389 and r.get('is_open')]
        ldap_ips = sorted(ldap_ips, key=lambda ip: (not ip.startswith('70.70.70.'), ip))
        print(f"[INFO] IPs avec LDAP détectées: {ldap_ips}")

        ldap_collector = None
        for ip in ldap_ips:
            try:
                print(f"[INFO] Tentative de connexion LDAP vers {ip}")
                tmp = LDAPCollector(domain_controller=ip, user=ldap_user, password=ldap_pass)
                if tmp.connect():
                    ldap_collector = tmp
                    print(f"[SUCCESS] Connexion LDAP établie vers {ip}")
                    break
            except Exception as e:
                print(f"[ERROR] Connexion LDAP vers {ip} échouée: {e}")
                continue

        # Fallback à l'autodétection si nécessaire
        if ldap_collector is None:
            try:
                print("[INFO] Tentative de connexion LDAP avec autodétection du DC")
                ldap_collector = LDAPCollector(user=ldap_user, password=ldap_pass)
                if ldap_collector.connect():
                    print("[SUCCESS] Connexion LDAP établie via autodétection")
                else:
                    print("[WARNING] Impossible de se connecter au contrôleur de domaine. Les informations AD ne seront pas collectées.")
                    return
            except Exception as e:
                print(f"[ERROR] Connexion LDAP autodétection échouée: {e}")
                print("[WARNING] Impossible de se connecter au contrôleur de domaine. Les informations AD ne seront pas collectées.")
                return

        # Créer une fonction pour récupérer les données
        def collect_data(task_name, func, results_list):
            """Tâche de collecte de données"""
            try:
                data = func()
                with self.lock:
                    results_list.extend(data)
                print(f"[INFO] {task_name}: {len(data)} éléments récupérés")
            except Exception as e:
                print(f"[ERROR] Erreur lors de la collecte {task_name}: {e}")

        # Créer et démarrer les threads
        threads = []

        users_thread = Thread(target=collect_data, args=('Utilisateurs', ldap_collector.get_users, self.users))
        threads.append(users_thread)
        users_thread.start()

        machines_thread = Thread(target=collect_data, args=('Machines', ldap_collector.get_machines, self.machines))
        threads.append(machines_thread)
        machines_thread.start()

        spn_thread = Thread(target=collect_data, args=('Comptes SPN', ldap_collector.get_spn_accounts, self.spn_accounts))
        threads.append(spn_thread)
        spn_thread.start()

        # Attendre la fin de tous les threads
        for thread in threads:
            thread.join(timeout=30.0)

        # Fermer la connexion
        ldap_collector.close()
    
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
            'all_ip_addresses': self.local_info.get('all_ip_addresses', []),
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
        print(f"  - Utilisateurs détectés: {report['users_count']}")
        print(f"  - Machines détectées: {report['machines_count']}")
        print(f"  - Comptes SPN: {report['spn_accounts_count']}")
        print(f"  - Ports OUVERTS: {len([p for p in report['raw_data']['network_scan'] if p['is_open']])}")
        print()
        
        # Afficher SEULEMENT les ports ouverts
        open_ports = [p for p in report['raw_data']['network_scan'] if p['is_open']]
        if open_ports:
            print("PORTS OUVERTS DÉTECTÉS:")
            for port in open_ports:
                print(f"  ✓ {port['host']:15} : {str(port['port']):5} ({port['service_name']})")
        else:
            print("Aucun port ouvert détecté")
        print()
        
        # Afficher les utilisateurs détectés
        if report['users_count'] > 0:
            print(f"UTILISATEURS DÉTECTÉS ({report['users_count']}):")
            for user in report['raw_data']['users'][:20]:  # Max 20
                status = "DÉSACTIVÉ" if user.get('is_disabled') else "ACTIF"
                print(f"  - {user['username']:20} | {user['full_name']:30} | {status}")
            if report['users_count'] > 20:
                print(f"  ... et {report['users_count'] - 20} autres utilisateurs")
        print()
        
        # Afficher les comptes SPN
        if report['spn_accounts_count'] > 0:
            print(f"COMPTES AVEC SPN DÉTECTÉS ({report['spn_accounts_count']}):")
            print("  ⚠️  Ces comptes sont vulnérables à l'attaque Kerberoasting!")
            for spn in report['raw_data']['spn_accounts'][:10]:  # Max 10
                print(f"  - {spn.get('username', 'UNKNOWN'):20} | SPN: {spn.get('service_principal_name', 'N/A')}")
            if report['spn_accounts_count'] > 10:
                print(f"  ... et {report['spn_accounts_count'] - 10} autres comptes SPN")
        print()
        
        print("=" * 80)


if __name__ == '__main__':
    # Créer l'agent multithreadé
    agent = ADAgentMultithreaded(max_threads=20)
    
    # Exécuter l'agent
    agent.run()
