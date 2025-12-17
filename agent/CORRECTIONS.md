# Corrections & Améliorations — Résumé des changements

## Problèmes identifiés et solutions apportées

### 1. Domaine non détecté (UNKNOWN_DOMAIN)
**Problème** : `get_domain_name()` échouait à détecter le domaine "megachange.nyx" même si la machine était jointe au domaine.

**Solution** : Amélioration de la détection du domaine avec 4 méthodes en fallback :
- `wmic computersystem get domain` (plus fiable pour les domaines)
- `systeminfo` (méthode précédente)
- `ipconfig /all` (cherche le suffixe DNS primaire)
- Résolution hostname FQDN

**Fichier modifié** : `collector/local.py`

---

### 2. Agent scanne seulement sa machine (0 hôtes découverts passivement)
**Problème** : Le scan passif (UDP) retournait 0 hôtes, donc l'agent ne scannait que sa propre IP (10.0.3.15), pas tout le domaine.

**Solution** : 
- Ajout d'une méthode `scan_subnet()` dans `ActivePortScanner` qui, si aucun hôte n'est découvert passivement, scanne automatiquement la plage /24 autour de l'IP locale.
- Exemple : si l'agent est sur 10.0.3.15, il scannera 10.0.3.1 → 10.0.3.254 pour les ports critiques (445, 389, 88, 53).

**Fichiers modifiés** : `collector/network.py`, `ad_agent.py`, `ad_agent_multithreaded.py`

---

### 3. URL serveur en dur (localhost:5000)
**Problème** : L'agent était codé en dur pour envoyer les rapports à `localhost:5000`. Si le serveur était sur une autre machine, impossible de le configurer sans modifier le code.

**Solution** : 
- Support d'une variable d'environnement `AGENT_SERVER_URL` qui override l'URL par défaut.
- Exemple : `$env:AGENT_SERVER_URL = 'http://192.168.1.100:5000/api/v1/report'`

**Fichiers modifiés** : `ad_agent.py`, `ad_agent_multithreaded.py`

---

### 4. Impossible de se connecter au contrôleur de domaine (port 389)
**Problème** : L'agent tentait une connexion LDAP vers 10.0.3.15 (sa propre machine) qui n'est pas le DC, d'où l'erreur "connection refused" (WinError 10061).

**Solution** : 
- Après le scan actif, l'agent essaie LDAP en priorité sur les IPs où le port 389 est ouvert (détectées par le scan).
- Si pas de 389 ouvert, il utilise l'autodétection (fallback).
- Support de variables d'environnement `AD_LDAP_USER` et `AD_LDAP_PASS` pour l'authentification.

**Fichiers modifiés** : `ad_agent.py`, `ad_agent_multithreaded.py`

---

## Comment lancer l'agent maintenant

### Méthode 1 : Script PowerShell automatisé (recommandé)
```powershell
cd C:\Users\auditAgent\AgentPY
.\ agent\run_agent.ps1
```
Ce script va :
- Détecter automatiquement le domaine et le DC
- Configurer les variables d'environnement
- Optionnellement demander les identifiants LDAP
- Lancer l'agent (simple ou multithreaded au choix)

### Méthode 2 : Commandes manuelles
```powershell
cd C:\Users\auditAgent\AgentPY
.\.venv\Scripts\Activate

# Définir les variables (adapter à votre environnement)
$env:AGENT_PASSIVE_TIMEOUT = "10"
$env:AGENT_ACTIVE_PORT_TIMEOUT = "1.0"
$env:AGENT_MAX_THREADS = "15"
$env:AGENT_SERVER_URL = "http://<IP_SERVER>:5000/api/v1/report"
$env:AD_LDAP_USER = "admin@megachange.nyx"
$env:AD_LDAP_PASS = "YourPassword"

# Lancer l'agent multithread
python .\agent\ad_agent_multithreaded.py
```

---

## Variables d'environnement disponibles

| Variable | Valeur par défaut | Description |
|----------|------------------|-------------|
| `AGENT_PASSIVE_TIMEOUT` | 10 | Durée écoute passive (secondes) |
| `AGENT_ACTIVE_PORT_TIMEOUT` | 1.0 | Timeout scan port (secondes) |
| `AGENT_MAX_THREADS` | 20 | Max threads (multithreaded agent) |
| `AGENT_SERVER_URL` | http://localhost:5000/api/v1/report | URL serveur Flask |
| `AD_LDAP_USER` | (vide) | Nom utilisateur LDAP (optionnel) |
| `AD_LDAP_PASS` | (vide) | Mot de passe LDAP (optionnel) |

---

## Résultat attendu après les corrections

1. **Domaine détecté** : affichage de "megachange.nyx" au lieu de "UNKNOWN_DOMAIN"
2. **Réseau scanné** : l'agent scannera la plage 10.0.3.0/24 et trouvera :
   - Le DC (port 389 LDAP ouvert)
   - Les autres machines du domaine
3. **Utilisateurs/Machines récupérés** : connexion LDAP au DC → liste des utilisateurs, machines, comptes SPN
4. **Rapport envoyé** : envoi au serveur Flask (ou sauvegarde locale si serveur non accessible)

---

## Notes techniques

- **Scan passif** : bind sur port UDP aléatoire et écoute les paquets entrants. Utile si la machine génère naturellement du trafic AD.
- **Scan actif** : teste connexions TCP sur les 4 ports critiques. Si aucun hôte découvert passivement, bascule sur scan complet du /24.
- **LDAP automatique** : essaie liaison anonyme d'abord, puis avec credentials si fournis.
- **Multithreading** : augmente performance sur grandes plages (permet d'éviter le timeout 15s mentionné dans le projet).

---

Si tu as des questions ou des erreurs, partage l'output du script et je pourrai t'aider!
