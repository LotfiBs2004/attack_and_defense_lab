#!/bin/bash
# =============================================================================
# Défense - TP2 exercice 3 (VM Ubuntu)
#   sudo ./defend.sh KALI_IP     active les services + le pare-feu
#   sudo ./defend.sh stop        enlève tout (policy ACCEPT, règles vidées)
#   sudo ./defend.sh save        garde les règles après un redémarrage
# A lancer dans la FENÊTRE de la VM (pas par SSH) : une erreur peut couper la session.
# =============================================================================
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
C="DEFENSE-IN"       # chaîne principale
R="DEFENSE-RATE"     # chaîne : journalise puis jette ce qui dépasse une limite de débit

usage() { echo "Usage: sudo $0 KALI_IP | stop | save"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Lancez avec sudo."; exit 1; }
[ $# -ge 1 ] || usage

cleanup_rules() {
  iptables -P INPUT ACCEPT          # d'abord ACCEPT, sinon tout est coupé pendant le nettoyage
  iptables -F INPUT
  for chain in "$C" "$R"; do
    iptables -F "$chain" 2>/dev/null
    iptables -X "$chain" 2>/dev/null
  done
}

case "$1" in
  stop)
    cleanup_rules
    pkill -f "$DIR/services.py" 2>/dev/null
    pkill -f "http.server 8080" 2>/dev/null
    echo "Défense arrêtée."
    exit 0 ;;
  save)
    if command -v netfilter-persistent >/dev/null; then
      netfilter-persistent save
    else
      mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4
    fi
    echo "Règles sauvegardées (les services Python, eux, sont à relancer au démarrage)."
    exit 0 ;;
esac

KALI="$1"
[[ "$KALI" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || usage

# --- 1. Services -------------------------------------------------------------
pkill -f "$DIR/services.py" 2>/dev/null
pkill -f "http.server 8080" 2>/dev/null
mkdir -p "$DIR/pub" && echo "Public service" > "$DIR/pub/index.html"
cd "$DIR"
nohup python3 -m http.server 8080 --directory "$DIR/pub" >/dev/null 2>&1 &
nohup python3 "$DIR/services.py" >/dev/null 2>&1 &
sleep 1

# --- 2. Pare-feu : on repart de zéro ----------------------------------------
cleanup_rules
iptables -N "$C"
iptables -N "$R"
iptables -A INPUT -j "$C"
A() { iptables -A "$C" "$@"; }

# Chaîne DEFENSE-RATE : on note (5 lignes/min max), puis on jette
iptables -A "$R" -m limit --limit 5/minute -j LOG --log-prefix "[RATE-LIMIT] " --log-level 4
iptables -A "$R" -j DROP

# --- 3. Règles de base -------------------------------------------------------
A -i lo -j ACCEPT                                                  # la machine se parle à elle-même
A -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT             # réponses aux connexions déjà ouvertes
A -p udp --sport 67 --dport 68 -j ACCEPT                           # réponses DHCP
A -p icmp --icmp-type echo-request -s "$KALI" -j ACCEPT            # ping : seulement votre Kali
A -p tcp --dport 22 -s "$KALI" -j ACCEPT                           # SSH : seulement votre Kali

# --- 4. Technique 1 : PORT PIÈGE + liste noire de 120 s ----------------------
# Aucun service sur 1337. Quiconque l'effleure est mémorisé (liste SCANNERS) et ignoré 120 s.
A -m recent --name SCANNERS --rcheck --seconds 120 -j DROP
A -p tcp --dport 1337 -m limit --limit 10/minute -j LOG --log-prefix "[TRAP] " --log-level 4
A -p tcp --dport 1337 -m recent --name SCANNERS --set -j DROP

# --- 5. Technique 2 : LIMITE DE DÉBIT GLOBALE par adresse source ------------
# Compte TOUS les SYN (tous ports confondus) : un scan rapide (nmap -T4, masscan) dépasse
# le seuil et voit ses sondes jetées ; un client normal ou un scan lent passe.
A -p tcp --tcp-flags SYN,RST,ACK,FIN SYN -m hashlimit --hashlimit-name syn \
  --hashlimit-mode srcip --hashlimit-above 25/second --hashlimit-burst 50 -j "$R"
A -p udp -m hashlimit --hashlimit-name udp \
  --hashlimit-mode srcip --hashlimit-above 25/second --hashlimit-burst 50 -j "$R"

# --- 6. Services -------------------------------------------------------------
# HTTP public 8080 : ouvert à tous
A -p tcp --dport 8080 -j ACCEPT

# Honeypot 2222 (faux SSH) : on journalise les SYN, on limite par source, on accepte
A -p tcp --dport 2222 --tcp-flags SYN,RST,ACK,FIN SYN -m limit --limit 10/minute --limit-burst 20 \
  -j LOG --log-prefix "[HONEYPOT-SYN] " --log-level 4
A -p tcp --dport 2222 -m hashlimit --hashlimit-name honey --hashlimit-mode srcip \
  --hashlimit-above 30/minute --hashlimit-burst 10 -j DROP
A -p tcp --dport 2222 -j ACCEPT

# Technique 3 : SERVICE SECRET 7777 : n'existe que si le port SOURCE du client est 53
A -p tcp --sport 53 --dport 7777 -j ACCEPT

# Service UDP 5300 : ouvert
A -p udp --dport 5300 -j ACCEPT

# Technique 4 : FAUSSE FERMETURE : 9000 répond "closed" (RST) alors qu'on ne cache rien
A -p tcp --dport 9000 -j REJECT --reject-with tcp-reset

# --- 7. Journal de tout le reste, puis politique DROP EN DERNIER -------------
A -m limit --limit 10/minute --limit-burst 20 -j LOG --log-prefix "[DEFENSE-DROP] " --log-level 4
iptables -P INPUT DROP

iptables -L "$C" -n -v --line-numbers
echo
echo "Défense active. Voir les logs :"
echo "  sudo dmesg | grep -E 'HONEYPOT|TRAP|RATE-LIMIT|DEFENSE-DROP'"
echo "  cat $DIR/services.log"
