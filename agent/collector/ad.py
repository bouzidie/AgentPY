"""
Module de collecte Active Directory via LDAP
Interroge le contrôleur de domaine pour récupérer les informations
"""

import ldap3
from typing import List, Dict
import re


class LDAPCollector:
    """
    Collecteur d'informations Active Directory via LDAP
    """
    
    def __init__(self, domain_controller: str = None, user: str = None, password: str = None):
        """
        Initialiser le collecteur LDAP
        
        Args:
            domain_controller: Adresse du contrôleur de domaine (optionnel)
            user: Nom d'utilisateur pour l'authentification LDAP (optionnel)
            password: Mot de passe pour l'authentification LDAP (optionnel)
        """
        self.domain_controller = domain_controller
        self.user = user
        self.password = password
        self.connection = None
        self.domain_name = None
        self.base_dn = None
        
    def connect(self) -> bool:
        """
        Se connecter au contrôleur de domaine
        
        Returns:
            True si la connexion réussit, False sinon
        """
        try:
            # Obtenir le contrôleur de domaine automatiquement si non spécifié
            if not self.domain_controller:
                self.domain_controller = self._get_domain_controller()
            
            # Créer la connexion LDAP
            server = ldap3.Server(self.domain_controller, get_info=ldap3.ALL)
            
            # Tenter de se connecter (avec auth si fourni, sinon anonyme)
            bind_mode = 'credentials' if (self.user and self.password) else 'anonymous bind'
            print(f"[INFO] Tentative de connexion LDAP vers {self.domain_controller} ({bind_mode})")
            if self.user and self.password:
                self.connection = ldap3.Connection(server, user=self.user, password=self.password, auto_bind=True)
            else:
                self.connection = ldap3.Connection(server, auto_bind=True)
            
            # Récupérer les informations du domaine
            self.domain_name = self._get_domain_name()
            self.base_dn = self._get_base_dn()
            
            print(f"[INFO] Connexion LDAP établie avec {self.domain_controller}")
            print(f"[INFO] Domaine: {self.domain_name}")
            print(f"[INFO] Base DN: {self.base_dn}")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Impossible de se connecter au contrôleur de domaine: {e}")
            return False
    
    def _get_domain_controller(self) -> str:
        """
        Obtenir automatiquement l'adresse du contrôleur de domaine
        
        Returns:
            Adresse IP du contrôleur de domaine
        """
        try:
            import socket
            # Tenter de résoudre le nom du contrôleur de domaine
            dc_name = socket.getfqdn()
            return socket.gethostbyname(dc_name)
        except Exception as e:
            print(f"[WARNING] Impossible d'obtenir automatiquement le contrôleur de domaine: {e}")
            # Retourner une adresse par défaut
            return "127.0.0.1"
    
    def _get_domain_name(self) -> str:
        """
        Récupérer le nom du domaine
        
        Returns:
            Nom du domaine
        """
        try:
            # Rechercher les informations du domaine
            self.connection.search(
                search_base='',
                search_filter='(objectClass=domainDNS)',
                search_scope=ldap3.BASE,
                attributes=['defaultNamingContext']
            )
            
            if self.connection.entries:
                return str(self.connection.entries[0].defaultNamingContext)
            
            return "UNKNOWN_DOMAIN"
            
        except Exception as e:
            print(f"[ERROR] Impossible de récupérer le nom du domaine: {e}")
            return "UNKNOWN_DOMAIN"
    
    def _get_base_dn(self) -> str:
        """
        Récupérer le Base DN du domaine
        
        Returns:
            Base DN
        """
        try:
            # Rechercher le Base DN
            self.connection.search(
                search_base='',
                search_filter='(objectClass=domainDNS)',
                search_scope=ldap3.BASE,
                attributes=['defaultNamingContext']
            )
            
            if self.connection.entries:
                return str(self.connection.entries[0].defaultNamingContext)
            
            return "DC=UNKNOWN,DC=LOCAL"
            
        except Exception as e:
            print(f"[ERROR] Impossible de récupérer le Base DN: {e}")
            return "DC=UNKNOWN,DC=LOCAL"
    
    def get_users(self) -> List[Dict]:
        """
        Récupérer la liste des utilisateurs du domaine
        
        Returns:
            Liste de dictionnaires contenant les informations des utilisateurs
        """
        users = []
        
        try:
            # Rechercher les VRAIS utilisateurs (pas les ordinateurs)
            # Filtre: objectClass=user ET NOT computer
            search_filter = '(&(objectClass=user)(!(objectClass=computer)))'
            print(f"[DEBUG] Recherche d'utilisateurs avec filtre: {search_filter}")
            
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=['sAMAccountName', 'displayName', 'mail', 'userAccountControl', 
                           'lastLogon', 'whenCreated', 'pwdLastSet']
            )
            
            print(f"[DEBUG] {len(self.connection.entries)} entrées trouvées")
            
            for entry in self.connection.entries:
                try:
                    username = str(entry.sAMAccountName) if entry.sAMAccountName else ''
                    # Filtrer les comptes système
                    if username.lower() in ['krbtgt', 'guest', 'administrator']:
                        continue
                    
                    user = {
                        'username': username,
                        'full_name': str(entry.displayName) if entry.displayName else '',
                        'email': str(entry.mail) if entry.mail else '',
                        'is_disabled': self._is_account_disabled(entry.userAccountControl),
                        'is_locked': self._is_account_locked(entry.userAccountControl),
                        'last_logon': self._convert_ad_timestamp(entry.lastLogon) if entry.lastLogon else None,
                        'created': self._convert_ad_timestamp(entry.whenCreated) if entry.whenCreated else None,
                        'password_last_set': self._convert_ad_timestamp(entry.pwdLastSet) if entry.pwdLastSet else None
                    }
                    users.append(user)
                    print(f"[DEBUG] Utilisateur trouvé: {username}")
                except Exception as e:
                    print(f"[ERROR] Erreur lors de la récupération d'un utilisateur: {e}")
            
            print(f"[INFO] {len(users)} utilisateurs récupérés")
            
        except Exception as e:
            print(f"[ERROR] Impossible de récupérer les utilisateurs: {e}")
        
        return users
    
    def get_machines(self) -> List[Dict]:
        """
        Récupérer la liste des machines du domaine
        
        Returns:
            Liste de dictionnaires contenant les informations des machines
        """
        machines = []
        
        try:
            # Rechercher toutes les machines (ordinateurs)
            search_filter = '(objectClass=computer)'
            print(f"[DEBUG] Recherche de machines avec filtre: {search_filter}")
            
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=['cn', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion',
                           'userAccountControl', 'lastLogon', 'whenCreated']
            )
            
            print(f"[DEBUG] {len(self.connection.entries)} machines trouvées")
            
            for entry in self.connection.entries:
                try:
                    hostname = str(entry.cn) if entry.cn else ''
                    machine = {
                        'hostname': hostname,
                        'dns_hostname': str(entry.dNSHostName) if entry.dNSHostName else '',
                        'os_version': str(entry.operatingSystem) if entry.operatingSystem else '',
                        'os_version_detail': str(entry.operatingSystemVersion) if entry.operatingSystemVersion else '',
                        'is_disabled': self._is_account_disabled(entry.userAccountControl),
                        'last_logon': self._convert_ad_timestamp(entry.lastLogon) if entry.lastLogon else None,
                        'created': self._convert_ad_timestamp(entry.whenCreated) if entry.whenCreated else None
                    }
                    machines.append(machine)
                    print(f"[DEBUG] Machine trouvée: {hostname}")
                except Exception as e:
                    print(f"[ERROR] Erreur lors de la récupération d'une machine: {e}")
            
            print(f"[INFO] {len(machines)} machines récupérées")
            
        except Exception as e:
            print(f"[ERROR] Impossible de récupérer les machines: {e}")
        
        return machines
    
    def get_spn_accounts(self) -> List[Dict]:
        """
        Récupérer la liste des comptes avec Service Principal Names (SPN)
        
        Returns:
            Liste de dictionnaires contenant les informations des comptes SPN
        """
        spn_accounts = []
        
        try:
            # Rechercher les comptes avec SPN (machines et utilisateurs avec SPN)
            search_filter = '(servicePrincipalName=*)'
            print(f"[DEBUG] Recherche de comptes SPN avec filtre: {search_filter}")
            
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=['sAMAccountName', 'servicePrincipalName', 'displayName', 'objectClass']
            )
            
            print(f"[DEBUG] {len(self.connection.entries)} comptes SPN trouvés")
            
            for entry in self.connection.entries:
                try:
                    username = str(entry.sAMAccountName) if entry.sAMAccountName else ''
                    
                    # Récupérer tous les SPN
                    spn_list = []
                    if entry.servicePrincipalName:
                        if isinstance(entry.servicePrincipalName, ldap3.utils.conv.list_types):
                            spn_list = [str(spn) for spn in entry.servicePrincipalName]
                        else:
                            spn_list = [str(entry.servicePrincipalName)]
                    
                    for spn in spn_list:
                        # Extraire les informations du SPN
                        spn_info = self._parse_spn(spn)
                        
                        spn_account = {
                            'username': username,
                            'full_name': str(entry.displayName) if entry.displayName else '',
                            'spn': spn,
                            'service_class': spn_info['service_class'],
                            'hostname': spn_info['hostname'],
                            'port': spn_info['port']
                        }
                        spn_accounts.append(spn_account)
                        print(f"[DEBUG] SPN trouvé: {spn} -> {username}")
                except Exception as e:
                    print(f"[ERROR] Erreur lors de la récupération d'un compte SPN: {e}")
            
            print(f"[INFO] {len(spn_accounts)} comptes avec SPN récupérés")
            
        except Exception as e:
            print(f"[ERROR] Impossible de récupérer les comptes SPN: {e}")
        
        return spn_accounts
    
    def _is_account_disabled(self, user_account_control) -> bool:
        """
        Vérifier si un compte est désactivé
        
        Args:
            user_account_control: Valeur de l'attribut userAccountControl
        
        Returns:
            True si le compte est désactivé, False sinon
        """
        try:
            if user_account_control:
                # Flag pour compte désactivé: 0x0002
                return bool(int(user_account_control) & 0x0002)
        except:
            pass
        return False
    
    def _is_account_locked(self, user_account_control) -> bool:
        """
        Vérifier si un compte est bloqué
        
        Args:
            user_account_control: Valeur de l'attribut userAccountControl
        
        Returns:
            True si le compte est bloqué, False sinon
        """
        try:
            if user_account_control:
                # Flag pour compte bloqué: 0x0010
                return bool(int(user_account_control) & 0x0010)
        except:
            pass
        return False
    
    def _convert_ad_timestamp(self, timestamp) -> str:
        """
        Convertir un timestamp Active Directory en format ISO
        
        Args:
            timestamp: Timestamp AD
        
        Returns:
            Date au format ISO
        """
        try:
            if timestamp:
                # Les timestamps AD sont en 100-nanosecond intervals depuis 1601-01-01
                from datetime import datetime, timedelta
                
                # Convertir en secondes
                seconds = int(timestamp) / 10000000
                
                # Calculer la date
                ad_epoch = datetime(1601, 1, 1)
                date = ad_epoch + timedelta(seconds=seconds)
                
                return date.isoformat()
        except:
            pass
        return None
    
    def _parse_spn(self, spn: str) -> Dict:
        """
        Parser un SPN pour extraire les informations
        
        Args:
            spn: Service Principal Name
        
        Returns:
            Dictionnaire avec les informations du SPN
        """
        try:
            # Format: service_class/hostname:port
            parts = spn.split('/')
            
            if len(parts) >= 2:
                service_class = parts[0]
                host_info = parts[1].split(':')
                hostname = host_info[0]
                port = host_info[1] if len(host_info) > 1 else None
                
                return {
                    'service_class': service_class,
                    'hostname': hostname,
                    'port': port
                }
        except:
            pass
        
        return {
            'service_class': 'UNKNOWN',
            'hostname': 'UNKNOWN',
            'port': None
        }
    
    def close(self):
        """
        Fermer la connexion LDAP
        """
        if self.connection:
            self.connection.unbind()
            print("[INFO] Connexion LDAP fermée")
