# Guide rapide — Scanner les 2 réseaux (70.70.70.0/24 ET 10.0.3.0/24)

## Problème corrigé
- ❌ Avant : détection des interfaces échouait (`socket.has_ipv4` n'existe pas)
- ✅ Après : parsing correct de `ipconfig /all` pour récupérer toutes les NICs

## Commandes pour lancer l'agent (scan les 2 réseaux automatiquement)

```powershell
cd C:\Users\auditAgent\AgentPY\agent
..\. venv\Scripts\Activate
python .\ad_agent_multithreaded.py
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

---

## Améliorer le scan passif UDP (0 hôtes découverts)

Le scan UDP passif écoute les paquets UDP arrivant sur un port aléatoire. Pour que le DC envoie des paquets :

**Pendant que l'agent exécute la phase [2/5] (Scan passif)**, sur le même PC ou une autre machine, lancer :

```powershell
# Test 1 : DNS query vers le DC
nslookup dc.megachange.nyx 70.70.70.4

# Test 2 : Kerberos (tentative de ticket)
kinit user@MEGACHANGE.NYX

# Test 3 : SMB (accès partage)
net view \\70.70.70.4

# Test 4 : Ping (ICMP, moins probable pour UDP)
ping 70.70.70.4
```

**Résultat** : si ces commandes génèrent du trafic UDP, le scanner passif les capturera.

---

## Option : Forcer les 2 réseaux sans attendre la correction

Si tu ne veux pas attendre, utilise l'env var (scanne seulement le réseau spécifié) :

```powershell
$env:AGENT_SCAN_NETWORK = "70.70.70.0/24"
python .\ad_agent_multithreaded.py
```

Puis relance pour 10.0.3.0/24 si besoin :
```powershell
$env:AGENT_SCAN_NETWORK = "10.0.3.0/24"
python .\ad_agent_multithreaded.py
```

---

## Résumé des changements

| Correction | Fichier |
|-----------|---------|
| Parsing `ipconfig /all` robuste | `collector/network.py` |
| Détection multi-NIC correcte | `collector/network.py` |
| Scan des 2 réseaux en parallèle | `ad_agent.py`, `ad_agent_multithreaded.py` |

Lance maintenant et partage l'output! 🚀
