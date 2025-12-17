# Script PowerShell pour lancer l'agent avec configuration automatique
# Cet script détecte automatiquement le domaine, le DC, et configure les variables d'environnement

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "AD Recon Agent - Configuration & Lancement" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1) Détection du domaine
Write-Host "[1/5] Détection du domaine..." -ForegroundColor Yellow
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
if ($domain -eq "WORKGROUP") {
    Write-Host "[ERROR] Cette machine n'est pas jointe à un domaine!" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Domaine détecté: $domain" -ForegroundColor Green
Write-Host ""

# 2) Détection du contrôleur de domaine
Write-Host "[2/5] Détection du contrôleur de domaine..." -ForegroundColor Yellow
$dc_ip = $null
try {
    # Essayer nslookup pour trouver le DC
    $dc_query = nslookup -type=SRV "_ldap._tcp.dc._msdcs.$domain" 2>$null | Select-String "Name server:"
    if ($dc_query) {
        Write-Host "[OK] DC trouvé via DNS" -ForegroundColor Green
    }
    
    # Obtenir l'IP du DC principal
    $dc_name = (Get-ADDomainController -DomainName $domain -Discover).HostName -ErrorAction SilentlyContinue
    if ($dc_name) {
        $dc_ip = [System.Net.Dns]::GetHostAddresses($dc_name)[0].IPAddressToString
        Write-Host "[OK] DC: $dc_name ($dc_ip)" -ForegroundColor Green
    }
} catch {
    Write-Host "[WARNING] Impossible de détecter le DC automatiquement" -ForegroundColor Yellow
}

# 3) Configuration des variables d'environnement
Write-Host ""
Write-Host "[3/5] Configuration des variables d'environnement..." -ForegroundColor Yellow

# Timeouts (en secondes)
$env:AGENT_PASSIVE_TIMEOUT = "10"          # Écoute passive 10s
$env:AGENT_ACTIVE_PORT_TIMEOUT = "1.0"    # Timeout scan port 1s
$env:AGENT_MAX_THREADS = "15"              # Max threads

# Si DC détecté, le fournir
if ($dc_ip) {
    $env:AD_LDAP_SERVER = $dc_ip
    Write-Host "[OK] AGENT_PASSIVE_TIMEOUT = $($env:AGENT_PASSIVE_TIMEOUT)" -ForegroundColor Green
    Write-Host "[OK] AGENT_ACTIVE_PORT_TIMEOUT = $($env:AGENT_ACTIVE_PORT_TIMEOUT)" -ForegroundColor Green
    Write-Host "[OK] AGENT_MAX_THREADS = $($env:AGENT_MAX_THREADS)" -ForegroundColor Green
    Write-Host "[OK] AD_LDAP_SERVER = $dc_ip" -ForegroundColor Green
} else {
    Write-Host "[WARNING] Impossible de détecter le DC. Utilisation de l'autodétection." -ForegroundColor Yellow
}

# Option: demander credentials LDAP si nécessaire
Write-Host ""
Write-Host "[4/5] Configuration LDAP (optionnel)..." -ForegroundColor Yellow
Write-Host "Si la liaison LDAP anonyme échoue, vous pouvez fournir un compte." -ForegroundColor Cyan
$use_creds = Read-Host "Utiliser des identifiants LDAP? (o/n)"

if ($use_creds -eq "o") {
    $ldap_user = Read-Host "Nom d'utilisateur (ex: admin@domaine.local ou DOMAINE\user)"
    $env:AD_LDAP_USER = $ldap_user
    
    # Prompt for password sécurisé
    $ldap_pass = Read-Host -AsSecureString "Mot de passe"
    $env:AD_LDAP_PASS = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($ldap_pass))
    
    Write-Host "[OK] Identifiants configurés" -ForegroundColor Green
} else {
    Write-Host "[INFO] Tentative de liaison anonyme." -ForegroundColor Cyan
}

# 5) URL du serveur (optionnel)
Write-Host ""
Write-Host "[5/5] Configuration du serveur (optionnel)..." -ForegroundColor Yellow
$use_server = Read-Host "Configurer l'URL du serveur Flask? (o/n, défaut: localhost:5000)"

if ($use_server -eq "o") {
    $server_url = Read-Host "URL du serveur (ex: http://192.168.1.100:5000/api/v1/report)"
    $env:AGENT_SERVER_URL = $server_url
    Write-Host "[OK] AGENT_SERVER_URL = $server_url" -ForegroundColor Green
} else {
    Write-Host "[INFO] Utilisation du serveur par défaut: http://localhost:5000/api/v1/report" -ForegroundColor Cyan
}

# Activation du venv et lancement
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Lancement de l'agent..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Activer venv
$venv_path = Join-Path $PSScriptRoot ".venv" "Scripts" "Activate.ps1"
if (Test-Path $venv_path) {
    & $venv_path
    Write-Host "[OK] Environnement virtuel activé" -ForegroundColor Green
} else {
    Write-Host "[WARNING] Environnement virtuel non trouvé. Assurez-vous que .venv est créé." -ForegroundColor Yellow
}

# Choisir entre simple et multithreaded
Write-Host ""
Write-Host "Quel agent voulez-vous lancer?" -ForegroundColor Cyan
Write-Host "  1 = ad_agent.py (simple, séquentiel)"
Write-Host "  2 = ad_agent_multithreaded.py (rapide, multithreaded)"
$choice = Read-Host "Choix (1 ou 2, défaut: 2)"

if ($choice -eq "1") {
    Write-Host "Lancement de ad_agent.py..." -ForegroundColor Yellow
    python .\ad_agent.py
} else {
    Write-Host "Lancement de ad_agent_multithreaded.py..." -ForegroundColor Yellow
    python .\ad_agent_multithreaded.py
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Agent terminé!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
