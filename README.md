# Projet AD Reconnaissance - Mini Projet Python pour Cyber Sécurité

**Reconnaissance passive et scan réseau d'Active Directory**

Ce projet implémente un système complet de reconnaissance réseau pour Active Directory, permettant de découvrir les machines, utilisateurs, services et vulnérabilités d'un domaine AD de manière passive et active.

---

## 📋 Table des Matières

- [Présentation](#présentation)
- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Exemples](#exemples)
- [Sécurité](#sécurité)
- [Performance](#performance)
- [Documentation](#documentation)
- [Licence](#licence)

---

## 🎯 Présentation

Ce projet répond aux besoins d'un **pentest autorisé** dans un environnement Active Directory. Il permet de :

- **Découvrir passivement** les machines du réseau sans envoyer de paquets
- **Scanner activement** les ports critiques (SMB, LDAP, Kerberos, DNS)
- **Interroger Active Directory** pour récupérer utilisateurs, machines et comptes SPN
- **Détecter automatiquement** les risques de sécurité (Kerberoasting, comptes désactivés, etc.)
- **Visualiser** les résultats dans une interface web moderne

---

## ✨ Fonctionnalités

### 1. Scan Passif du Réseau
- Écoute UDP pour capturer les requêtes réseau
- Découverte automatique des noms de machines et services
- **100% passif** : aucun paquet envoyé
- Temps d'écoute configurable (30-60 secondes)

### 2. Scan Actif Léger
- Vérification des ports critiques :
  - **445** : SMB (Server Message Block)
  - **389** : LDAP (Lightweight Directory Access Protocol)
  - **88** : Kerberos (Authentification)
  - **53** : DNS (Domain Name System)
- **Multithreading** pour accélérer les scans (10-20x plus rapide)
- Timeout rapide pour chaque port (2-3 secondes)

### 3. Interrogation Active Directory
- Connexion LDAP au contrôleur de domaine
- Récupération de la liste des utilisateurs
- Récupération de la liste des machines
- **Détection des comptes avec SPN** (risque Kerberoasting)
- Fonctionne avec un compte utilisateur normal (sans droits admin)

### 4. Interface Web Innovante
- **Dashboard moderne** avec statistiques en temps réel
- Tableaux de bord pour utilisateurs, machines, risques
- **Visualisations** avec Chart.js
- **Détection automatique** des vulnérabilités
- **Recommandations** de sécurité

### 5. Multithreading
- Accélération de **10 à 20 fois** des scans
- Gestion efficace des ressources système
- Pool de threads configurable
- Gestion des erreurs et timeouts

---

## 🏗️ Architecture

Le système est composé de deux composants principaux :

### Serveur Flask
- **API REST** pour réception des rapports d'agents
- **Stockage** dans une base de données SQLite
- **Interface web** avec dashboard moderne
- **Visualisation** des informations du domaine AD
- **Détection automatique** des risques de sécurité

### Agent Python
- **Scan passif** du réseau (écoute UDP)
- **Scan actif** des ports critiques
- **Interrogation LDAP** pour AD
- **Collecte locale** des informations système
- **Envoi HTTP** des données au serveur
- **Script autonome** sans installation

---

## 🚀 Installation

### Prérequis

- **Python 3.8+**
- **Système d'exploitation** : Windows, Linux ou macOS
- **Environnement** : Active Directory (Windows Server 2019+)

### Installation du Serveur

```bash
# Naviguer vers le dossier du serveur
cd /chemin/vers/ad_recon_project/server

# Installer les dépendances
pip install -r requirements.txt

# Démarrer le serveur
python app.py
```

Le serveur sera accessible sur `http://localhost:5000`

### Installation de l'Agent

```bash
# Naviguer vers le dossier de l'agent
cd /chemin/vers/ad_recon_project/agent

# Installer les dépendances
pip install -r requirements.txt
```

---

## 📖 Utilisation

### Démarrer le Serveur

```bash
# Depuis le dossier server
python app.py
```

Le serveur démarre sur `http://localhost:5000`

### Exécuter l'Agent

#### Version Basique (Séquentielle)

```bash
# Depuis le dossier agent
python ad_agent.py
```

#### Version Multithreadée (Recommandée)

```bash
# Depuis le dossier agent
python ad_agent_multithreaded.py
```

#### Spécifier l'URL du Serveur

```bash
# Avec URL du serveur
python ad_agent_multithreaded.py --server-url http://votre-serveur:5000/api/v1/report
```

### Accéder à l'Interface Web

Ouvrir un navigateur et se rendre sur :
```
http://localhost:5000
```

---

## 🎓 Exemples

### Exemple 1 : Scan d'un Réseau AD

```bash
# Démarrer le serveur
python server/app.py

# Dans un autre terminal, exécuter l'agent
python agent/ad_agent_multithreaded.py
```

### Exemple 2 : Utilisation en Ligne de Commande

```bash
# Exécuter l'agent et sauvegarder le rapport localement
python agent/ad_agent.py

# Le rapport sera sauvegardé dans : ad_report_YYYYMMDD_HHMMSS.json
```

### Exemple 3 : Utilisation dans un Script Python

```python
from agent.ad_agent import ADAgent

# Créer l'agent
agent = ADAgent(server_url='http://localhost:5000/api/v1/report')

# Exécuter l'agent
agent.run()
```

---

## 🔒 Sécurité

### Principes de Sécurité

✅ **Pas de modification** : L'outil ne change rien dans le réseau  
✅ **Compte normal** : Fonctionne avec droits utilisateur standard  
✅ **Environnement autorisé** : À utiliser uniquement dans des environnements testés  
✅ **Pas d'installation** : Agent autonome, serveur local  

### Bonnes Pratiques

- **Autorisation** : Toujours obtenir l'autorisation avant d'utiliser l'outil
- **Environnement de test** : Utiliser uniquement dans des environnements de test
- **Compte standard** : Utiliser un compte utilisateur normal (pas admin)
- **Audit** : Documenter tous les scans effectués

---

## ⚡ Performance

### Temps d'Exécution

- **Agent basique** : < 15 secondes
- **Agent multithreadé** : < 5 secondes
- **Scan passif** : 30 secondes
- **Scan actif** : 2-3 secondes par hôte

### Optimisations

- **Multithreading** : 10-20x plus rapide
- **Timeouts courts** : 2-3 secondes par connexion
- **Pool de threads** : Configurable (par défaut 20)
- **Gestion efficace** : Des ressources système

---

## 📚 Documentation

### Fichiers de Documentation

- **ARCHITECTURE.md** : Architecture technique détaillée
- **USAGE.md** : Guide d'utilisation complet
- **API.md** : Documentation de l'API REST
- **SECURITY.md** : Guide de sécurité

### Structure du Projet

```
ad_recon_project/
├── server/                      # Serveur Flask
│   ├── app.py                   # Application principale
│   ├── models.py                # Modèles SQLAlchemy
│   ├── config.py                # Configuration
│   └── requirements.txt         # Dépendances
│
├── agent/                       # Agent de collecte
│   ├── ad_agent.py              # Script principal
│   ├── ad_agent_multithreaded.py # Version multithreadée
│   ├── collector/               # Modules de collecte
│   │   ├── network.py           # Scan réseau
│   │   ├── ad.py                # LDAP/AD
│   │   └── local.py             # Collecte locale
│   └── requirements.txt
│
├── web/                         # Interface web
│   ├── templates/               # Templates HTML
│   └── static/                  # CSS, JS, images
│
├── docs/                        # Documentation
│   ├── ARCHITECTURE.md          # Architecture
│   └── USAGE.md                 # Guide d'utilisation
│
├── test_integration.py          # Tests d'intégration
└── README.md                    # Documentation principale
```

---

## 📝 Licence

Ce projet est développé dans le cadre d'un **mini projet académique** pour le cours de **Python pour Cyber Sécurité**.

**Avertissement** : Cet outil doit être utilisé uniquement dans des environnements autorisés et pour des fins éducatives. L'utilisation non autorisée sur des systèmes informatiques peut constituer une infraction pénale.

---

## 👥 Auteurs

**Groupe SSIRF-4-C**
- Étudiant 1 : Islem Bouzidi
- Étudiant 2 : Fatma Guent

**Enseignant** : [Nom de l'enseignant]

**Établissement** : [Nom de l'établissement]

**Année académique** : 2025/2026

---

## 🎓 Objectifs Pédagogiques

Ce projet vise à développer les compétences suivantes :

1. **Programmation Python** : Développement d'applications réseau
2. **Cyber Sécurité** : Techniques de reconnaissance réseau
3. **Architecture Web** : Serveur Flask, API REST, interface web
4. **Multithreading** : Optimisation des performances
5. **Bases de Données** : SQLAlchemy, SQLite
6. **Protocoles Réseau** : UDP, TCP, LDAP, Kerberos

---

## 🚨 Avertissement Légal

**Cet outil est destiné uniquement à des fins éducatives et de test dans des environnements autorisés.**

L'utilisation non autorisée de cet outil sur des systèmes informatiques peut constituer une infraction pénale selon les lois en vigueur dans votre juridiction.

**Vous êtes responsable de l'utilisation légale et éthique de cet outil.**

---

## 📞 Support

Pour toute question ou problème, veuillez contacter votre enseignant ou consulter la documentation.

---

**© 2025 AD Reconnaissance - Mini Projet Python pour Cyber Sécurité**
