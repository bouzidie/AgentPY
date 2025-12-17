# Configuration pour Multi-NIC (Dual Network) - Cas 70.70.70.0/24

## Situation identifiée
- **PC1 (Agent)** : 2 cartes réseau
  - NIC 1 : 70.70.70.6 (réseau du domaine megachange.nyx) ✅ **À SCANNER**
  - NIC 2 : 10.0.3.15 (réseau de test)
- **DC (Contrôleur de domaine)** : 70.70.70.4
- **Réseau domaine** : 70.70.70.0/24

## Problème précédent
L'agent détectait l'IP 10.0.3.15 en priorité et scannait le /24 10.0.3.0/24, ratant le vrai domaine sur 70.70.70.0/24.

## Solution implémentée
- Détection automatique de **TOUTES** les NICs actives
- Scan de TOUS les sous-réseaux en parallèle (ou séquentiel selon la version)
- Option override via variable `AGENT_SCAN_NETWORK`

---

## Commandes pour lancer l'agent correctement

### Option 1 : Automatique (recommandé pour multi-NIC)
```powershell
cd C:\Users\auditAgent\AgentPY
.\.venv\Scripts\Activate

# L'agent détectera automatiquement les 2 NICs et scannera les 2 réseaux
python .\agent\ad_agent_multithreaded.py
```

**Résultat attendu** :
```
[INFO] 2 interface(s) réseau détectée(s):
  - Ethernet: 70.70.70.6 (70.70.70.0/24)
  - Ethernet 2: 10.0.3.15 (10.0.3.0/24)
[INFO] Collecte des hôtes à scanner depuis 2 interface(s)
[INFO] Interface Ethernet: 70.70.70.0/24
[INFO] Interface Ethernet 2: 10.0.3.0/24
[INFO] Port 389/LDAP ouvert sur 70.70.70.4
...
```

### Option 2 : Forcer un seul réseau (si besoin)
Si tu veux scanner **seulement** le réseau 70.70.70.0/24 :
```powershell
cd C:\Users\auditAgent\AgentPY
.\.venv\Scripts\Activate

$env:AGENT_SCAN_NETWORK = "70.70.70.0/24"
$env:AGENT_PASSIVE_TIMEOUT = "5"
$env:AGENT_ACTIVE_PORT_TIMEOUT = "1.0"
$env:AD_LDAP_USER = "admin@megachange.nyx"
$env:AD_LDAP_PASS = "TonPassword"

python .\agent\ad_agent_multithreaded.py
```

### Option 3 : Script PowerShell automatisé
```powershell
cd C:\Users\auditAgent\AgentPY
.\agent\run_agent.ps1
```

---

## Variables d'environnement mises à jour

| Variable | Exemple | Description |
|----------|---------|-------------|
| `AGENT_SCAN_NETWORK` | `70.70.70.0/24` | **NOUVEAU** — Force le scan d'un réseau spécifique (CIDR) |
| `AGENT_PASSIVE_TIMEOUT` | 5 | Durée écoute passive (secondes) |
| `AGENT_ACTIVE_PORT_TIMEOUT` | 1.0 | Timeout scan port (secondes) |
| `AGENT_MAX_THREADS` | 15 | Max threads (multithreaded agent) |
| `AGENT_SERVER_URL` | http://192.168.1.100:5000/api/v1/report | URL serveur Flask |
| `AD_LDAP_USER` | admin@megachange.nyx | Nom utilisateur LDAP |
| `AD_LDAP_PASS` | TonPassword | Mot de passe LDAP |

---

## Résultat attendu

Après correction, l'agent devrait :

1. ✅ Détecter le domaine **megachange.nyx** (pas UNKNOWN_DOMAIN)
2. ✅ Détecter les 2 NICs (70.70.70.6 et 10.0.3.15)
3. ✅ Scanner les 2 réseaux (ou seulement 70.70.70.0/24 si `AGENT_SCAN_NETWORK` défini)
4. ✅ Trouver le DC à **70.70.70.4** (port 389 LDAP ouvert)
5. ✅ Récupérer la liste des utilisateurs, machines, comptes SPN
6. ✅ Générer un rapport complet avec vulnérabilités
7. ✅ Envoyer le rapport au serveur Flask

---

## Dépannage

### Si l'agent ne détecte pas 70.70.70.6
```powershell
# Vérifier les interfaces
ipconfig /all

# Vérifier la route par défaut
route print

# Tester manuellement la connectivité vers le DC
Test-NetConnection -ComputerName 70.70.70.4 -Port 389
```

### Si LDAP échoue (WinError 10061)
- Vérifier que le DC est bien à 70.70.70.4 :
  ```powershell
  ping 70.70.70.4
  Test-NetConnection -ComputerName 70.70.70.4 -Port 389
  ```
- Fournir des identifiants LDAP valides :
  ```powershell
  $env:AD_LDAP_USER = "admin@megachange.nyx"
  $env:AD_LDAP_PASS = "YourPassword"
  ```

### Si le rapport n'est pas envoyé au serveur
- Vérifier que le serveur Flask tourne : `http://localhost:5000/` (ou IP du serveur)
- Configurer l'URL correcte :
  ```powershell
  $env:AGENT_SERVER_URL = "http://<IP_SERVEUR>:5000/api/v1/report"
  ```

---

Lance maintenant et partage l'output! 🚀
