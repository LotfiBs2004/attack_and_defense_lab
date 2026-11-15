# PAPIER CACHÉ : ne pas montrer à l'autre groupe avant la fin du jeu

Groupe : ____________     Adresse de mon Ubuntu : ____________     Adresse de mon Kali (admin) : ____________

## Services

| Port | Protocole | Service | Vrai ou faux ? | Comment le trouver |
|---|---|---|---|---|
| 8080 | TCP | HTTP public (Python http.server) | vrai | visible dans un scan normal |
| 2222 | TCP | faux SSH « OpenSSH 8.9p1 » (honeypot) | **faux** (leurre) | visible ; la bannière est fausse, aucun échange de clés |
| 7777 | TCP | service « secret » (SECRET-SERVICE 1.0) | vrai | ouvert **seulement si le port source du client est 53** (`-g 53`) |
| 5300 | UDP | service UDP (répond « UDP-SERVICE OK ») | vrai | scan UDP (`-sU`, `U:5300`) |
| 22 | TCP | SSH réel | vrai | **seulement mon Kali** (invisible pour les autres) |
| 9000 | TCP | rien | **faux** | répond « closed » (RST), fausse piste |
| 1337 | TCP | **PIÈGE** | rien | toute IP qui le touche est ignorée pendant 120 s |

## Défenses

1. **Politique DROP** : tout ce qui n'est pas autorisé est jeté en silence, donc « filtered » partout.
2. **Port piège 1337** + liste noire 120 s (`recent`) : casse les scans complets `-p-`.
3. **Limite de débit globale par IP source** (25 SYN/s, burst 50, idem UDP) : jette les sondes d'un scan rapide (`-T4`, masscan). Contournement : scanner lentement (`-T1`, `--scan-delay`).
4. **Règle sur le port source** : 7777 n'est ouvert qu'avec `--sport 53`. Contournement : `-g 53`.
5. **Faux service** 2222 (honeypot) qui journalise les connexions + limite par source.
6. **Fausse fermeture** du port 9000 (REJECT tcp-reset).
7. **Ping et SSH réservés à mon Kali** : les autres ne reçoivent pas de réponse au ping (utiliser `-Pn` ou ARP sur le même réseau).
8. **Journaux** : préfixes `[TRAP]`, `[RATE-LIMIT]`, `[HONEYPOT-SYN]`, `[DEFENSE-DROP]` (dmesg) + `services.log`.

## Notes pour moi
- Contournements possibles que je connais : ______________________________________
- Ce que j'ai observé dans mes logs pendant leur attaque : ________________________
