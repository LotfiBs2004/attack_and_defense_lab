"""
Interface web du scanner - TP2 Exercice 3.
Lancer (root nécessaire pour les scans SYN / UDP / -g ...) :
    cd Attack && sudo python3 app.py        puis ouvrir http://127.0.0.1:5000

Comme ce programme tourne en ROOT, il est protégé ainsi :
  - écoute uniquement sur 127.0.0.1, debug désactivé
  - l'en-tête Host doit être 127.0.0.1 ou localhost (anti DNS-rebinding)
  - jeton CSRF sur le formulaire, cookie de session SameSite=Strict
  - en-têtes de sécurité (CSP stricte, pas de cadre, pas de cache)
  - cible = UNE IPv4 du réseau du labo ; options = liste blanche + regex (scanner.py)
  - nmap lancé sans shell ; un seul scan à la fois ; timeout ; requêtes < 4 Ko
  - Jinja échappe tout ce qui vient du scan (anti-XSS)
"""
import json
import os
import re
import secrets
import threading
from io import BytesIO

from flask import Flask, abort, redirect, render_template, request, send_file, session

from scanner import (LAB_NET, SCAN_TYPES, clean_options, parse_results, run_scan,
                     validate_ports, validate_target)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)          # change à chaque démarrage
app.config["MAX_CONTENT_LENGTH"] = 4096
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

scan_lock = threading.Lock()
last_scan = None


@app.before_request
def only_localhost():
    if request.host.split(":")[0] not in ("127.0.0.1", "localhost"):
        abort(403)


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


def page(status=200, **context):
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    context.setdefault("form", {})
    html = render_template("index.html", csrf=session["csrf"], scan_types=SCAN_TYPES,
                           lab_net=str(LAB_NET), **context)
    return html, status


@app.route("/")
def home():
    return page()


@app.route("/scan", methods=["POST"])
def scan():
    global last_scan

    expected = session.get("csrf")
    received = request.form.get("csrf", "")
    if not expected or not secrets.compare_digest(received.encode(), expected.encode()):
        abort(403)

    form = request.form
    if not scan_lock.acquire(blocking=False):
        return page(429, error="Un scan est déjà en cours, attendez sa fin.", form=form)
    try:
        target_ip = validate_target(form.get("target", ""))
        ports = validate_ports(form.get("ports", ""))
        options = clean_options(form)

        xml_data, command = run_scan(str(target_ip), ports, options)
        results = parse_results(xml_data)

        last_scan = {"results": results, "xml_data": xml_data}
        return page(results=results, command=command, form=form,
                    vulners_enabled=options["vulners"])

    except ValueError as error:
        return page(400, error=str(error), form=form)
    except RuntimeError as error:
        return page(500, error=str(error), form=form)
    finally:
        scan_lock.release()


@app.route("/export/json")
def export_json_file():
    if last_scan is None:
        return redirect("/")
    json_data = json.dumps(last_scan["results"], indent=4, ensure_ascii=False)
    return send_file(BytesIO(json_data.encode("utf-8")), mimetype="application/json",
                     as_attachment=True, download_name="scan_results.json")


@app.route("/export/xml")
def export_xml_file():
    if last_scan is None:
        return redirect("/")
    # on retire la ligne de feuille de style XSL ajoutée par nmap
    xml_data = re.sub(r"<\?xml-stylesheet[^>]*\?>\s*", "", last_scan["xml_data"])
    return send_file(BytesIO(xml_data.encode("utf-8")), mimetype="application/xml",
                     as_attachment=True, download_name="scan_results.xml")


if __name__ == "__main__":
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Pas root : les scans SYN, UDP et -g échoueront. Relancez avec : sudo python3 app.py")
    app.run(host="127.0.0.1", port=5000, debug=False)
