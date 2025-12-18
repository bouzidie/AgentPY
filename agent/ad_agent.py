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
        import os
        self.server_url = server_url or os.getenv('AGENT_SERVER_URL', 'http://localhost:5000/api/v1/report')
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
    
    def scan_active_ports(self):
        """
        Scanner les ports critiques de manière active
        """
        from collector.network import ActivePortScanner, get_all_network_interfaces
        import os
        import ipaddress
        
        # Timeout configurable via env var AGENT_ACTIVE_PORT_TIMEOUT (seconds)
        active_timeout = float(os.getenv('AGENT_ACTIVE_PORT_TIMEOUT', '2.0'))
        
        scanner = ActivePortScanner(timeout=active_timeout)
        
        # Scanner les hôtes découverts passivement
        if self.discovered_hosts:
            hosts = [host['ip'] for host in self.discovered_hosts]
            self.network_scan_results = scanner.scan_hosts(hosts)
        else:
            # Si aucun hôte découvert passivement, scanner le sous-réseau complet
            # Permettre override via env var AGENT_SCAN_NETWORK (ex: 70.70.70.0/24)
            scan_network = os.getenv('AGENT_SCAN_NETWORK')
            
            if scan_network:
                # Utiliser le réseau fourni en env var
                print(f"[INFO] Scan du réseau spécifié: {scan_network}")
                import ipaddress
                try:
                    net = ipaddress.ip_network(scan_network, strict=False)
                    results_all = []
                    for host in net.hosts():
                        host_str = str(host)
                        for port in scanner.critical_ports.keys():
                            result = scanner.scan_host(host_str, port)
                            results_all.append(result)
                            if result['is_open']:
                                print(f"[INFO] Port {port}/{result['service_name']} ouvert sur {host_str}")
                    self.network_scan_results = results_all
                except Exception as e:
                    print(f"[ERROR] Erreur lors du scan du réseau spécifié: {e}")
                    self.network_scan_results = []
            else:
                # Détecter tous les réseaux locaux et scanner chacun
                # PRIORITAIRE: scanner le réseau domaine 70.70.70.0/24 d'abord
                interfaces = get_all_network_interfaces()
                
                if interfaces:
                    # Trier les interfaces pour mettre 70.70.70.x en premier
                    domain_interfaces = [i for i in interfaces if i.get('ip', '').startswith('70.70.70.')]
                    other_interfaces = [i for i in interfaces if not i.get('ip', '').startswith('70.70.70.')]
                    sorted_interfaces = domain_interfaces + other_interfaces
                    
                    print(f"[INFO] Scan de {len(sorted_interfaces)} sous-réseau(x) (domaine d'abord)")
                    results_all = []
                    for iface in sorted_interfaces:
                        if iface.get('subnet'):
                            print(f"[INFO] Scan du sous-réseau {iface['subnet']} (via {iface['name']})")
                            try:
                                import ipaddress
                                net = ipaddress.ip_network(iface['subnet'], strict=False)
                                for host in net.hosts():
                                    host_str = str(host)
                                    for port in scanner.critical_ports.keys():
                                        result = scanner.scan_host(host_str, port)
                                        results_all.append(result)
                                        if result['is_open']:
                                            print(f"[INFO] Port {port}/{result['service_name']} ouvert sur {host_str}")
                            except Exception as e:
                                print(f"[ERROR] Erreur lors du scan de {iface['subnet']}: {e}")
                    self.network_scan_results = results_all
                else:
                    # Fallback: scanner le /24 de l'IP locale - mais d'abord essayer 70.70.70.0/24
                    local_ip = self.local_info.get('ip_address', '127.0.0.1')
                    print(f"[INFO] Aucune interface détectée - tentatives de fallback")
                    
                    # Essayer d'abord le réseau domaine par défaut
                    networks_to_try = ['70.70.70.0/24', f"{local_ip}/24"]
                    results_all = []
                    
                    for target_net in networks_to_try:
                        print(f"[INFO] Tentative de scan sur {target_net}")
                        try:
                            net = ipaddress.ip_network(target_net, strict=False)
                            for host in net.hosts():
                                host_str = str(host)
                                for port in scanner.critical_ports.keys():
                                    result = scanner.scan_host(host_str, port)
                                    results_all.append(result)
                                    if result['is_open']:
                                        print(f"[INFO] Port {port}/{result['service_name']} ouvert sur {host_str}")
                        except Exception as e:
                            print(f"[ERROR] Erreur lors du scan de {target_net}: {e}")
                    self.network_scan_results = results_all
    
    def collect_ad_info(self):
        """
        Collecter les informations Active Directory via LDAP
        """
        from collector.ad import LDAPCollector
        import os
        
        ldap_user = os.getenv('AD_LDAP_USER')
        ldap_pass = os.getenv('AD_LDAP_PASS')
        
        # Tenter en priorité les IPs où le port 389 a été trouvé ouvert
        # IMPORTANT: Trier pour mettre 70.70.70.x (DC domaine) en premier
        ldap_ips = []
        if self.network_scan_results:
            ldap_ips = [r['host'] for r in self.network_scan_results if r.get('port') == 389 and r.get('is_open')]
            # Trier pour mettre les IPs du réseau domaine en premier
            ldap_ips = sorted(ldap_ips, key=lambda ip: (not ip.startswith('70.70.70.'), ip))
            if ldap_ips:
                print(f"[INFO] IPs avec LDAP détectées: {ldap_ips}")
        
        connected = False
        
        # Essayer chaque IP détectée avec le port 389 ouvert
        for ip in ldap_ips:
            try:
                print(f"[INFO] Tentative de connexion LDAP vers {ip}")
                ldap_collector = LDAPCollector(domain_controller=ip, user=ldap_user, password=ldap_pass)
                if ldap_collector.connect():
                    self.users = ldap_collector.get_users()
                    self.machines = ldap_collector.get_machines()
                    self.spn_accounts = ldap_collector.get_spn_accounts()
                    ldap_collector.close()
                    connected = True
                    print(f"[SUCCESS] Connexion LDAP établie vers {ip}")
                    break
            except Exception as e:
                print(f"[ERROR] Connexion LDAP vers {ip} échouée: {e}")
        
        # Si aucune IP n'a fonctionné, essayer la découverte automatique SEULEMENT si pas d'IPs trouvées
        if not connected and not ldap_ips:
            try:
                print("[INFO] Aucune IP LDAP trouvée par scan - tentative avec autodétection du DC")
                ldap_collector = LDAPCollector(user=ldap_user, password=ldap_pass)
                if ldap_collector.connect():
                    self.users = ldap_collector.get_users()
                    self.machines = ldap_collector.get_machines()
                    self.spn_accounts = ldap_collector.get_spn_accounts()
                    ldap_collector.close()
                    connected = True
                    print("[SUCCESS] Connexion LDAP établie via autodétection")
            except Exception as e:
                print(f"[ERROR] Connexion LDAP autodétection échouée: {e}")
        
        if not connected:
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
        
        # Afficher les machines détectées
        if report['machines_count'] > 0:
            print(f"MACHINES DÉTECTÉES ({report['machines_count']}):")
            for machine in report['raw_data']['machines'][:10]:  # Max 10
                os_info = machine.get('os_version', 'N/A')
                print(f"  - {machine['hostname']:20} | {os_info}")
            if report['machines_count'] > 10:
                print(f"  ... et {report['machines_count'] - 10} autres machines")
        print()
        
        # Analyser et afficher les vulnérabilités
        print("ANALYSE DE VULNÉRABILITÉS:")
        vulnerabilities = self._analyze_vulnerabilities(report)
        if vulnerabilities:
            for vuln in vulnerabilities:
                print(f"  ⚠️  [{vuln['severity']}] {vuln['title']}")
                print(f"      {vuln['description']}")
                print(f"      → Recommandation: {vuln['recommendation']}")
                print()
        else:
            print("  ✓ Aucune vulnérabilité majeure détectée")
        print()
        
        print("=" * 80)
    
    def _analyze_vulnerabilities(self, report: Dict) -> List[Dict]:
        """
        Analyser les vulnérabilités détectées
        
        Args:
            report: Rapport d'analyse
            
        Returns:
            Liste des vulnérabilités trouvées
        """
        vulns = []
        
        # 1. Kerberoasting - Comptes SPN
        if report['spn_accounts_count'] > 0:
            vulns.append({
                'severity': 'HIGH',
                'title': 'Kerberoasting - Comptes avec SPN détectés',
                'description': f'{report["spn_accounts_count"]} compte(s) avec Service Principal Names trouvé(s). Ces comptes peuvent être vulnérables aux attaques Kerberoasting.',
                'recommendation': 'Utiliser des mots de passe forts (25+ caractères) ou des comptes gérés (gMSA). Monitorer les tickets Kerberos.'
            })
        
        # 2. Comptes désactivés non supprimés
        disabled_users = [u for u in report['raw_data']['users'] if u.get('is_disabled')]
        if len(disabled_users) > 3:
            vulns.append({
                'severity': 'MEDIUM',
                'title': f'Comptes désactivés non nettoyés ({len(disabled_users)})',
                'description': f'{len(disabled_users)} compte(s) désactivé(s) sont toujours présent(s) dans le domaine.',
                'recommendation': 'Supprimer ou archiver les comptes désactivés après 6-12 mois d\'inactivité.'
            })
        
        # 3. Comptes bloqués
        locked_users = [u for u in report['raw_data']['users'] if u.get('is_locked')]
        if len(locked_users) > 5:
            vulns.append({
                'severity': 'MEDIUM',
                'title': f'Plusieurs comptes bloqués ({len(locked_users)})',
                'description': f'{len(locked_users)} compte(s) sont bloqué(s), possiblement suite à des tentatives de brute-force.',
                'recommendation': 'Vérifier les logs de sécurité pour détecter des attaques. Implémenter une politique de verrouillage après N tentatives.'
            })
        
        # 4. Ports critiques ouverts
        open_ldap = [p for p in report['raw_data']['network_scan'] if p.get('port') == 389 and p.get('is_open')]
        open_smb = [p for p in report['raw_data']['network_scan'] if p.get('port') == 445 and p.get('is_open')]
        
        if len(open_smb) > 1:
            vulns.append({
                'severity': 'HIGH',
                'title': f'SMB ouvert sur {len(open_smb)} machine(s)',
                'description': 'Le service SMB (port 445) est exposé. Risque de ransomware et accès non autorisé.',
                'recommendation': 'Restreindre l\'accès SMB avec des pare-feu. Utiliser SMB3 avec signature obligatoire. Patcher les vulnérabilités SMB (EternalBlue, etc.).'
            })
        
        # 5. Services critiques potentiellement vulnérables
        if report['machines_count'] > 0:
            # Chercher des OS anciens/vulnérables
            old_os_machines = [m for m in report['raw_data']['machines'] 
                             if 'Server 2008' in m.get('os_version', '') or 'Server 2003' in m.get('os_version', '')]
            if old_os_machines:
                vulns.append({
                    'severity': 'CRITICAL',
                    'title': f'Serveurs obsolètes détectés ({len(old_os_machines)})',
                    'description': f'{len(old_os_machines)} serveur(s) Windows Server 2008/2003 trouvé(s). Ces OS ne reçoivent plus de patchs de sécurité.',
                    'recommendation': 'Mettre à jour vers Windows Server 2019 ou 2022 au minimum. Isoler les serveurs obsolètes si migration impossible.'
                })
        
        return vulns


if __name__ == '__main__':
    # Créer l'agent
    agent = ADAgent()
    
    # Exécuter l'agent
    agent.run()
