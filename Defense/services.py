#!/usr/bin/env python3
"""
Services factices de la VM Ubuntu (défense, exercice 3).
  TCP 2222 : honeypot (faux SSH OpenSSH 8.9)        -> leurre qui enregistre qui se connecte
  TCP 7777 : service "secret" (le pare-feu ne l'ouvre qu'aux clients dont le port source est 53)
  UDP 5300 : service UDP qui répond "UDP-SERVICE OK"
(Le service HTTP public 8080 est lancé par defend.sh.)
Chaque connexion est écrite à l'écran ET dans services.log.
"""
import socket
import threading
import time
from datetime import datetime

LOG_FILE = "services.log"
log_lock = threading.Lock()


def log(message):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} {message}"
    print(line, flush=True)
    with log_lock, open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def handle_tcp(conn, addr, port, banner, label):
    """Traite UNE connexion (dans son propre thread : un client lent ne bloque pas les autres)."""
    try:
        log(f"[{label}] TCP {port} - connexion de {addr[0]}:{addr[1]}")
        conn.settimeout(3)
        conn.sendall(banner)
        try:
            conn.recv(1024)
        except OSError:
            pass
    except OSError:
        pass
    finally:
        conn.close()


def tcp_service(port, banner, label):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(50)
    log(f"[{label}] écoute sur TCP {port}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_tcp, args=(conn, addr, port, banner, label),
                         daemon=True).start()


def udp_service(port, reply, label):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", port))
    log(f"[{label}] écoute sur UDP {port}")
    while True:
        _, addr = server.recvfrom(1024)
        log(f"[{label}] UDP {port} - paquet de {addr[0]}:{addr[1]}")
        server.sendto(reply, addr)


if __name__ == "__main__":
    jobs = [
        (tcp_service, (2222, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n", "HONEYPOT")),
        (tcp_service, (7777, b"SECRET-SERVICE 1.0 ready\r\n", "SECRET")),
        (udp_service, (5300, b"UDP-SERVICE OK\n", "UDP")),
    ]
    for function, args in jobs:
        threading.Thread(target=function, args=args, daemon=True).start()
    while True:
        time.sleep(3600)
