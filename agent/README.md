# AD Recon Agent — Guide rapide

Ce document explique comment exécuter l'agent dans un lab VirtualBox (Domain Controller + client Windows 2019) et comment fournir des identifiants si nécessaire.

## 1) Recommandation d'exécution
- Exécutez l'agent **depuis la VM cliente** jointe au domaine (recommandé). Cela facilite la découverte passive (les clients génèrent naturellement du trafic AD).
- Alternative : exécuter depuis l'hôte si votre réseau VirtualBox permet l'accès (utilisez `Bridged Adapter`).

## 2) Installer dépendances
- Créer un environnement Python et installer :
  - python -m venv .venv
  - .venv\Scripts\activate  (Windows PowerShell)
  - pip install -r agent\requirements.txt

## 3) Variables d'environnement utiles
- `AD_LDAP_USER` — nom d'utilisateur pour bind LDAP (ex: `admin@domain.local` ou `DOMAIN\\user`)
- `AD_LDAP_PASS` — mot de passe LDAP
- `AGENT_PASSIVE_TIMEOUT` — durée en secondes pour la capture UDP passive (par défaut 10)
- `AGENT_ACTIVE_PORT_TIMEOUT` — timeout en secondes pour le scan actif (par défaut 1.0)
- `AGENT_MAX_THREADS` — nombre max de threads (multithreaded agent)

Exemples PowerShell :

```powershell
$env:AD_LDAP_USER = 'admin@domain.local'
$env:AD_LDAP_PASS = 'P@ssw0rd'
$env:AGENT_PASSIVE_TIMEOUT = '8'
$env:AGENT_ACTIVE_PORT_TIMEOUT = '1.0'
$env:AGENT_MAX_THREADS = '10'
```

## 4) Exécution
- Agent simple (séquentiel) :
  - python agent\ad_agent.py

- Agent multithread (recommandé pour performance) :
  - python agent\ad_agent_multithreaded.py

Pendant la phase de capture passive (par défaut 10s), **générez du trafic** sur la VM cliente :
- `nslookup <domain controller>`
- `dir \\<DC>\C$` (SMB)
- ouvrir une session AD (domain logon)

Cela augmente fortement les hôtes découverts passivement.

## 5) Vérifier la connectivité LDAP (tests rapides)
- Sur Windows (PowerShell) :
  - Test-NetConnection -ComputerName <IP_DC> -Port 389
  - Test-NetConnection -ComputerName <IP_DC> -Port 88

- Si ldapsearch disponible (Linux) :
  - ldapsearch -x -H ldap://<IP_DC> -b '' -s base '(objectClass=*)' defaultNamingContext

## 6) Notes de sécurité
- N'exécutez l'outil que dans un lab autorisé.
- N'enregistrez pas de mots de passe en clair dans le dépôt. Utilisez variables d'environnement.

---

Si vous voulez, je peux :
- Ajuster les valeurs par défaut (par ex. passive timeout = 5s) pour respecter la contrainte "terminer en < 15s".
- Ajouter quelques tests unitaires minimalistes pour valider le flux sans AD réel.
