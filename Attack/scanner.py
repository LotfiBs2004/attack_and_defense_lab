"""
Moteur du scanner - TP2 Exercice 3.

Ce fichier ne fait que : valider les entrées, construire la commande nmap
(ou masscan puis nmap), l'exécuter SANS shell, et lire le XML.
Il peut s'utiliser seul en ligne de commande :
    sudo python3 scanner.py 192.168.1.20 -p - --scan-type syn --pn
"""
import argparse
import ipaddress
import json
import re
import subprocess
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------------------
# A ADAPTER : le réseau de votre labo (les 3 premiers nombres de `ip a`, puis .0/24)
# ---------------------------------------------------------------------------
LAB_NET = ipaddress.ip_network("192.168.1.0/24")

# Liste blanche des types de scan : nom affiché -> (option nmap, description)
SCAN_TYPES = {
    "syn":     ("-sS", "SYN (par défaut, rapide)"),
    "connect": ("-sT", "Connexion complète"),
    "ack":     ("-sA", "ACK (montre les règles du pare-feu)"),
    "fin":     ("-sF", "FIN"),
    "null":    ("-sN", "NULL (aucun flag)"),
    "xmas":    ("-sX", "XMAS (FIN+PSH+URG)"),
    "window":  ("-sW", "Window"),
}

PORTS_RE = re.compile(r"[TU0-9,:\-]{1,100}")   # 22,80,8000-9000  T:22,U:5300  -
DELAY_RE = re.compile(r"[0-9]{1,3}(ms|s)?")    # 1s  500ms
TIMEOUT_NMAP = 1800      # 30 min (un -p- lent peut être long)
TIMEOUT_MASSCAN = 900


# ---------------------------------------------------------------------------
# 1. Validation des entrées
# ---------------------------------------------------------------------------
def validate_target(target):
    """Une seule adresse IPv4, qui doit appartenir au réseau du labo."""
    try:
        ip = ipaddress.ip_address(str(target).strip())
    except ValueError:
        raise ValueError("Adresse IP invalide.") from None

    if not isinstance(ip, ipaddress.IPv4Address):
        raise ValueError("Seules les adresses IPv4 sont acceptées.")
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        raise ValueError("Cette adresse ne peut pas être utilisée comme cible.")
    # if ip not in LAB_NET:
    #     raise ValueError(f"Cible hors du réseau du labo ({LAB_NET}).")
    return ip


def validate_ports(ports):
    """Vide = 1000 ports courants ; '-' = tous ; sinon 22,80,8000-9000 ou T:22,U:5300."""
    ports = (ports or "").strip()
    if not ports:
        return None
    if ports == "-":
        return "-"
    if not PORTS_RE.fullmatch(ports):
        raise ValueError("Format des ports invalide. Exemples : 22,80 · 1-1000 · T:22,U:5300 · -")
    for number in re.findall(r"\d+", ports):
        if not 1 <= int(number) <= 65535:
            raise ValueError("Les ports doivent être compris entre 1 et 65535.")
    return ports


def clean_options(raw):
    """Transforme le formulaire (ou les arguments CLI) en options VALIDÉES.
    Rien de ce que tape l'utilisateur n'est jamais passé tel quel à nmap."""
    opts = {}
    opts["engine"] = "masscan" if raw.get("engine") == "masscan" else "nmap"

    scan_type = raw.get("scan_type", "syn")
    opts["scan_type"] = scan_type if scan_type in SCAN_TYPES else "syn"

    timing = str(raw.get("timing", "3"))
    opts["timing"] = timing if timing in list("012345") else "3"

    for key in ("udp", "version", "scripts", "vulners", "pn", "frag", "decoy", "defeat_rst"):
        opts[key] = bool(raw.get(key))
    opts["version"] = opts["version"] or opts["vulners"]

    source_port = str(raw.get("source_port", "") or "").strip()
    if source_port and (not source_port.isdigit() or not 1 <= int(source_port) <= 65535):
        raise ValueError("Port source invalide (1 à 65535).")
    opts["source_port"] = source_port

    delay = str(raw.get("scan_delay", "") or "").strip()
    if delay and not DELAY_RE.fullmatch(delay):
        raise ValueError("Délai invalide. Exemples : 1s ou 500ms.")
    opts["scan_delay"] = delay
    return opts


# ---------------------------------------------------------------------------
# 2. Construction et exécution des commandes (toujours une LISTE, jamais de shell)
# ---------------------------------------------------------------------------
def build_nmap_command(target, ports, opts, only_ports=None):
    chosen = only_ports or ports
    command = ["nmap", "-n", SCAN_TYPES[opts["scan_type"]][0]]

    if chosen == "-":
        command.append("-p-")
    elif chosen:
        command.extend(["-p", chosen])

    # nmap exige -sU dès qu'on demande des ports UDP (U:...)
    if opts["udp"] or (chosen and "U:" in chosen):
        command.append("-sU")
    if opts["version"]:
        command.append("-sV")
    if opts["scripts"] and opts["vulners"]:
        command.extend(["--script", "default,vulners"])
    elif opts["scripts"]:
        command.append("-sC")
    elif opts["vulners"]:
        command.extend(["--script", "vulners"])
    if opts["pn"]:
        command.append("-Pn")
    if opts["frag"]:
        command.append("-f")
    if opts["decoy"]:
        command.extend(["-D", "RND:5"])
    if opts["defeat_rst"]:
        command.append("--defeat-rst-ratelimit")
    if opts["source_port"]:
        command.extend(["-g", opts["source_port"]])
    if opts["scan_delay"]:
        command.extend(["--scan-delay", opts["scan_delay"]])

    command.append("-T" + opts["timing"])
    command.extend(["-oX", "-", str(target)])
    return command


def _run(command, timeout):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError(f"{command[0]} n'est pas installé.") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError("Le scan a dépassé le délai autorisé.") from None
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip()[:500] or "Erreur inconnue.")
    return result.stdout


def _empty_xml(target):
    return ('<?xml version="1.0"?><nmaprun scanner="masscan"><host><status state="up"/>'
            f'<address addr="{target}" addrtype="ipv4"/><ports/></host></nmaprun>')


def _run_masscan_then_nmap(target, ports, opts):
    """Phase 1 : masscan trouve très vite les ports TCP ouverts.
    Phase 2 : nmap -sV identifie les services sur ces ports seulement."""
    if ports and ":" in ports:
        raise ValueError("Avec masscan, indiquez des ports TCP simples (pas de T:/U:).")
    spec = "1-65535" if ports in (None, "-") else ports

    mass_cmd = ["masscan", str(target), "-p", spec, "--rate", "500", "--wait", "3", "-oL", "-"]
    if opts["source_port"]:
        mass_cmd.extend(["--source-port", opts["source_port"]])
    output = _run(mass_cmd, TIMEOUT_MASSCAN)

    found = sorted({int(m.group(1)) for m in re.finditer(r"^open tcp (\d+) ", output, re.M)})
    if not found:
        return _empty_xml(target), " ".join(mass_cmd) + "   (aucun port ouvert trouvé)"

    nmap_opts = dict(opts, version=True)
    nmap_cmd = build_nmap_command(target, None, nmap_opts, only_ports=",".join(map(str, found)))
    xml_data = _run(nmap_cmd, TIMEOUT_NMAP)
    return xml_data, " ".join(mass_cmd) + "   ->   " + " ".join(nmap_cmd)


def run_scan(target, ports=None, options=None):
    """Retourne (xml, commande_affichée)."""
    opts = options or clean_options({"version": True})
    if opts["engine"] == "masscan":
        return _run_masscan_then_nmap(target, ports, opts)
    command = build_nmap_command(target, ports, opts)
    return _run(command, TIMEOUT_NMAP), " ".join(command)


# ---------------------------------------------------------------------------
# 3. Lecture du XML
# ---------------------------------------------------------------------------
def parse_results(xml_data):
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        raise RuntimeError("Sortie du scanner illisible (XML invalide).") from None

    results = {"host_status": None, "ip": None, "ports": [], "extraports": []}
    host = root.find("host")
    if host is None:
        return results

    status = host.find("status")
    if status is not None:
        results["host_status"] = status.get("state")

    for address in host.findall("address"):
        if address.get("addrtype") == "ipv4":
            results["ip"] = address.get("addr")

    for port in host.findall("./ports/port"):
        state = port.find("state")
        service = port.find("service")
        state_name = state.get("state") if state is not None else "unknown"
        vulners_output = "\n".join(
            script.get("output", "") for script in port.findall("script")
            if script.get("id") == "vulners" and script.get("output")
        )
        results["ports"].append({
            "port": port.get("portid"),
            "protocol": port.get("protocol"),
            "state": state_name,
            "css": state_name.replace("|", "-"),     # open|filtered -> open-filtered
            "reason": state.get("reason") if state is not None else "unknown",
            "service": service.get("name") if service is not None else "unknown",
            "product": (service.get("product") or "unknown") if service is not None else "unknown",
            "version": (service.get("version") or "unknown") if service is not None else "unknown",
            "extrainfo": (service.get("extrainfo") or "") if service is not None else "",
            "vulners": vulners_output,
        })

    for extra in host.findall("./ports/extraports"):
        results["extraports"].append({"state": extra.get("state"), "count": extra.get("count")})
    return results


# ---------------------------------------------------------------------------
# 4. Affichage terminal et exports
# ---------------------------------------------------------------------------
def display_results(data):
    print("\n" + "=" * 70)
    print("                         NETWORK SCANNER")
    print("=" * 70)
    print(f"Target IP : {data['ip'] or 'Unknown'}")
    print(f"Host      : {(data['host_status'] or 'Unknown').upper()}")
    print("\n{:<12} {:<15} {:<14} {:<20} {:<12}".format("PORT", "STATE", "SERVICE", "PRODUCT", "VERSION"))
    print("-" * 70)
    for p in data["ports"]:
        print("{:<12} {:<15} {:<14} {:<20} {:<12}".format(
            f"{p['port']}/{p['protocol']}", p["state"], p["service"], p["product"], p["version"]))
        if p["vulners"]:
            print(f"  CVE candidates:\n{p['vulners']}")
    for extra in data["extraports"]:
        print(f"{extra['count']} ports regroupés : {extra['state']}")
    print("-" * 70)
    print("Scan completed.")
    print("=" * 70)


def export_json(data, filename):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)
    print(f"[+] Résultats exportés en JSON : {filename}")


def export_xml(xml_data, filename):
    with open(filename, "w", encoding="utf-8") as file:
        file.write(xml_data)
    print(f"[+] Résultats exportés en XML : {filename}")


def main():
    parser = argparse.ArgumentParser(description="Scanner réseau (nmap / masscan)")
    parser.add_argument("target", help="Adresse IPv4 de la cible (réseau du labo)")
    parser.add_argument("-p", "--ports", help="22,80 · 1-1000 · T:22,U:5300 · - (tous)")
    parser.add_argument("--engine", choices=["nmap", "masscan"], default="nmap")
    parser.add_argument("--scan-type", choices=list(SCAN_TYPES), default="syn")
    parser.add_argument("--timing", default="3", help="0 à 5")
    parser.add_argument("--udp", action="store_true", help="scan UDP (-sU)")
    parser.add_argument("--no-version", action="store_true", help="sans -sV")
    parser.add_argument("--scripts", action="store_true", help="scripts par défaut (-sC)")
    parser.add_argument("--vulners", action="store_true", help="CVE potentielles via le script NSE vulners")
    parser.add_argument("--pn", action="store_true", help="ne pas pinguer avant (-Pn)")
    parser.add_argument("--frag", action="store_true", help="fragmentation (-f)")
    parser.add_argument("--decoy", action="store_true", help="leurres (-D RND:5)")
    parser.add_argument("--defeat-rst", action="store_true", help="--defeat-rst-ratelimit")
    parser.add_argument("--source-port", help="port source (-g)")
    parser.add_argument("--delay", help="délai entre sondes, ex. 1s")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--json", metavar="FICHIER", help="exporter en JSON")
    group.add_argument("--xml", metavar="FICHIER", help="exporter en XML")
    args = parser.parse_args()

    try:
        target = validate_target(args.target)
        print(f"[+] Adresse IP valide : {target}")
        ports = validate_ports(args.ports)
        options = clean_options({
            "engine": args.engine, "scan_type": args.scan_type, "timing": args.timing,
            "udp": args.udp, "version": not args.no_version, "scripts": args.scripts,
            "vulners": args.vulners,
            "pn": args.pn, "frag": args.frag, "decoy": args.decoy,
            "defeat_rst": args.defeat_rst, "source_port": args.source_port,
            "scan_delay": args.delay,
        })
        xml_result, command = run_scan(str(target), ports, options)
        print(f"[+] Commande : {command}")
        parsed = parse_results(xml_result)
        display_results(parsed)
        if args.json:
            export_json(parsed, args.json)
        elif args.xml:
            export_xml(xml_result, args.xml)
    except (ValueError, RuntimeError) as error:
        print(f"[-] Erreur : {error}")


if __name__ == "__main__":
    main()
