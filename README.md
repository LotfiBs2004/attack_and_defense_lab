# Kali-Lab : TP2 exercice 3 (version corrigée et complète)

```
Kali-Lab/
├── Attack/                  → sur la VM KALI
│   ├── app.py               interface web (Flask), sécurisée
│   ├── scanner.py           moteur : validation, nmap/masscan, lecture du XML (utilisable seul en terminal)
│   └── templates/index.html la page (Flask exige le dossier "templates")
├── Defense/                 → sur la VM UBUNTU
│   ├── services.py          faux services : honeypot 2222, secret 7777, UDP 5300 (remplace honeypot.py)
│   └── defend.sh            lance les services + tout le pare-feu iptables
├── PAPIER_DEFENSE.md        le papier CACHÉ (ne pas le montrer à l'autre groupe)
└── RAPPORT.md               modèle du rapport d'une page
```

## 1. Ce qui a été corrigé par rapport à la version de départ

| Avant | Maintenant |
|---|---|
| `debug=True` en root (console qui exécute du code) | `debug=False`, écoute sur 127.0.0.1 seulement |
| `index.html` à côté de `app.py` → `TemplateNotFound` | dans `templates/` |
| La variable `error` n'était jamais affichée | bandeau d'erreur rouge dans la page |
| Pas de `sudo` | `sudo python3 app.py` (avertissement si pas root) |
| Tous les réseaux privés acceptés | seulement `LAB_NET` (réseau du labo) |
| Pas de protection CSRF / Host / en-têtes, état global sans verrou | jeton CSRF, contrôle du Host, CSP, verrou, timeout |
| Ports : pas de plages (`1-1000` refusé) | plages, `T:22,U:5300` et `-` (tous) |
| `Scan completed` indenté dans la boucle | corrigé |
| Aucune option avancée | UDP, types de scan, -T, -Pn, -f, -D, -g, --scan-delay, --defeat-rst-ratelimit, masscan, -sC |
| 1 seul service (honeypot) et tout en REJECT | 4 services + 5 techniques de défense, DROP par défaut |

## 2. Mise en place

### Sur Kali
1. Copiez le dossier `Attack` (avec son sous-dossier `templates`).
2. Ouvrez `Attack/scanner.py` et changez **`LAB_NET`** : si votre Kali est `192.168.1.23`, laissez `192.168.1.0/24` ; si c'est `10.0.2.15`, mettez `10.0.2.0/24`.
3. Lancez :
   ```
   cd Attack
   sudo python3 app.py
   ```
4. Ouvrez Firefox sur `http://127.0.0.1:5000`.

Utilisation en terminal (sans page web), même moteur :
```
sudo python3 scanner.py TARGET -p - --pn --json resultat.json
sudo python3 scanner.py TARGET -p T:22,U:5300 --udp --source-port 53 --timing 1
```

### Sur Ubuntu (dans la fenêtre de la VM, pas par SSH)
1. Copiez le dossier `Defense` (par `scp` depuis Kali : `scp -r Defense user@TARGET:~`, **avant** d'activer la défense).
2. Lancez, avec l'adresse de **votre** Kali :
   ```
   cd Defense
   chmod +x defend.sh
   sudo ./defend.sh ADRESSE_DE_VOTRE_KALI
   ```
3. Pour arrêter : `sudo ./defend.sh stop`. Pour garder les règles après redémarrage : `sudo apt install iptables-persistent` puis `sudo ./defend.sh save`. Les services Python sont à relancer après un redémarrage (`sudo ./defend.sh KALI_IP`).

## 3. Tester VOTRE défense depuis VOTRE Kali (avant le jeu)

| Commande (sur Kali) | Résultat attendu |
|---|---|
| `sudo nmap -sV -p 22,2222,8080 TARGET` | 22 open (autorisé pour votre Kali), 2222 open (bannière OpenSSH 8.9), 8080 open (Python http.server) |
| `sudo nmap -p 7777 TARGET` | **filtered** |
| `sudo nmap -g 53 -p 7777 TARGET` | **open** (port source 53) |
| `sudo nmap -sU -p 5300 TARGET` | open |
| `sudo nmap -p 9000 TARGET` | **closed** (fausse fermeture) |
| `sudo nmap -p 80,443 TARGET` | **filtered**, pas closed (policy DROP) |
| `sudo nmap -p 1337 TARGET` puis tout de suite `sudo nmap -p 2222 TARGET` | 2222 devient **filtered** pendant 120 s (liste noire), puis redevient open |
| `sudo nmap -p- -T4 TARGET` | beaucoup de ports en filtered, certains services manqués (limite de débit et/ou piège) |

Sur Ubuntu, regardez ce que la défense a vu :
```
sudo dmesg | grep -E 'HONEYPOT|TRAP|RATE-LIMIT|DEFENSE-DROP'
cat Defense/services.log
```
Vous restez joignable en SSH depuis votre Kali même quand le piège se déclenche (la règle SSH est avant la liste noire).

## 4. Plan d'attaque contre l'autre groupe (avec votre scanner)

1. Scan simple (top 1000), noter ce qui est open / closed / filtered et les raisons (colonne « Raison »).
2. `-p-` : si tout devient filtered à partir d'un moment, soupçonner un piège ou une limite de débit.
3. Même chose en **lent** : `-T1` ou `--scan-delay 1s`, éventuellement par morceaux de ports (`1-1336,1338-65535` pour éviter un port suspect).
4. `-sA` (type ACK) pour voir quels ports sont filtrés ou non.
5. `-g 53`, `-g 80`, `-g 20` : services réservés à certains ports sources.
6. UDP : `-sU` sur une plage ciblée, ex. `U:1-10000` (l'UDP est lent).
7. `-Pn` si l'hôte « semble éteint » (il bloque le ping).
8. `-sV -sC` sur chaque port trouvé ; comparer les bannières (un faux service se trahit).
9. Après le jeu : lire leur papier et comparer avec ce que vous aviez deviné.

## 5. Limites à connaître
- Je n'ai pas pu tester les règles iptables sur de vraies VM : faites le tableau de la section 3 pour vérifier chez vous.
- Le scanner web attend la fin du scan avant d'afficher (pas de barre de progression).
- masscan : TCP seulement, débit fixé à 500 paquets/s ; il peut échouer sur certains réseaux Wi-Fi. nmap reste le moteur de référence.
# attack_and_defense_lab
