# TP2 – Exercice 3 : rapport

**Groupe :** ______________________   **Date :** ______________   **Cible attaquée :** ______________

## 1. Les défenses de l'autre groupe, ce que mon scanner a montré, comment je les ai contournées

| Défense du groupe adverse (d'après leur papier) | Ce que mon scanner a montré (état, raison, commande/options) | Comment je l'ai contournée |
|---|---|---|
| ex. port piège | ex. `-p-` : tout devient filtered après ~30 s | ex. scan en 2 parties sans le port 1337, avec `-T1` |
| | | |
| | | |
| | | |

*(Joignez 1 ou 2 captures du tableau du scanner. Pour chaque ligne : option utilisée et résultat avant/après.)*

## 2. La défense la plus difficile à contourner, et pourquoi

______________________________________________________________________________
______________________________________________________________________________
*(Expliquez : ce qu'elle bloque, pourquoi les options habituelles échouent, ce qu'il a fallu combiner.)*

## 3. Ce que mes propres logs ont montré sur leurs scans

Commandes : `sudo dmesg | grep -E 'HONEYPOT|TRAP|RATE-LIMIT|DEFENSE-DROP'` et `cat services.log`

- Adresse source du scanner : ______  Premières et dernières traces : ______ (durée du scan : ______)
- Ports visés et ordre (aléatoire = nmap ; séquentiel = masscan ou `--randomize` désactivé) : ______
- Rythme (paquets/s) et déclenchement de `[RATE-LIMIT]` : ______
- A-t-il touché le piège `[TRAP]` ? à quel moment ? : ______
- Connexions au honeypot 2222 (`[HONEYPOT-SYN]`, services.log) : ______
- Ce que le défenseur en déduit (type de scan, outil, patience de l'attaquant) : ______

## 4. Protection de ma page web (elle tourne en root)

| Risque | Protection mise en place |
|---|---|
| Accès depuis le réseau | écoute sur `127.0.0.1` uniquement ; en-tête `Host` vérifié (anti DNS-rebinding) |
| Exécution de code à distance | `debug=False` (la console Flask en debug exécute du code) |
| Injection de commande | nmap/masscan lancés par `subprocess` avec une **liste** d'arguments, **sans shell** |
| Options dangereuses | cible = une IPv4 **du réseau du labo** ; types de scan en **liste blanche** ; ports, délai, port source validés par **regex/entiers** |
| Page piégée qui déclenche un scan (CSRF) | jeton CSRF dans le formulaire + cookie de session `SameSite=Strict` |
| XSS (bannière de service malveillante) | Jinja échappe toutes les valeurs ; CSP `default-src 'none'` |
| Clickjacking, cache | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Cache-Control: no-store` |
| Déni de service | un seul scan à la fois (verrou), timeout, requêtes limitées à 4 Ko |
| Scan d'une machine interdite | validation de la cible avant tout lancement |

**Limite restante :** le serveur reste root ; une faille dans Flask ou nmap donnerait un accès root à la VM Kali. Mitigation : VM isolée, écoute locale uniquement, aucun accès extérieur.
