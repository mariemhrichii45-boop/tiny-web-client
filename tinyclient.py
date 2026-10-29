#!/usr/bin/env python3

import argparse
import socket
import ssl
import sys
import time

DEFAULT_TIMEOUT = 10          # secondes
MAX_RESPONSE_SIZE = 10 * 1024 * 1024   # 10 Mo
MAX_URL_LENGTH = 2048
RECV_CHUNK_SIZE = 4096
MAX_REDIRECTS = 5
SUPPORTED_SCHEMES = ("http", "https")


class TinyClientError(Exception):
 

def validate_url_string(url: str) -> None:
    """Valide l'URL brute AVANT tout parsing / toute connexion réseau.

    Vérifie :
      - la longueur maximale (2048 caractères)
      - l'absence de caractères de contrôle (code ASCII < 32, notamment \\r et \\n)
    """
    if len(url) > MAX_URL_LENGTH:
        raise TinyClientError(
            f"URL trop longue ({len(url)} caractères, max {MAX_URL_LENGTH})"
        )

    for ch in url:
        if ord(ch) < 32:
            raise TinyClientError(
                "Caractere de controle detecte dans l'URL"
            )


def validate_path(path: str) -> None:
    """Protection contre l'injection CRLF (Section 3.2).

    Un attaquant pourrait injecter %0d%0a (\\r\\n) dans le chemin pour
    faire croire au client qu'il doit ajouter de nouveaux en-têtes HTTP
    arbitraires (HTTP Response/Request Splitting).
    """
    if "\r" in path or "\n" in path:
        raise TinyClientError("Injection CRLF detectee dans le chemin de l'URL")


# ---------------------------------------------------------------------------
# 2. Parsing d'URL (Section 2.1.1)
# ---------------------------------------------------------------------------

def parse_url(url: str):
    """Extrait (scheme, host, port, path) d'une URL http(s)://...

    Ne s'appuie sur AUCUNE bibliothèque de parsing d'URL de haut niveau :
    implémentation manuelle conforme à l'esprit de la RFC 3986 pour les
    besoins pédagogiques du projet (version simplifiée, suffisante pour
    des URLs http/https classiques).
    """
    validate_url_string(url)

    if "://" not in url:
        raise TinyClientError(
            "URL invalide : le protocole est manquant (utilisez http:// ou https://)"
        )

    scheme, remainder = url.split("://", 1)
    scheme = scheme.lower()

    if scheme not in SUPPORTED_SCHEMES:
        raise TinyClientError(
            f"Protocole '{scheme}' non supporte. Utilisez http:// ou https://"
        )

    if remainder == "":
        raise TinyClientError("URL invalide : hote manquant")

    # Sépare "host[:port]" du reste "path?query#fragment"
    slash_index = remainder.find("/")
    if slash_index == -1:
        host_port = remainder
        path = "/"
    else:
        host_port = remainder[:slash_index]
        path = remainder[slash_index:]

    if host_port == "":
        raise TinyClientError("URL invalide : hote manquant")

    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        if host == "":
            raise TinyClientError("URL invalide : hote manquant")
        try:
            port = int(port_str)
        except ValueError:
            raise TinyClientError(f"Port invalide : '{port_str}'")
        if not (1 <= port <= 65535):
            raise TinyClientError(f"Port hors limites : {port}")
    else:
        host = host_port
        port = 443 if scheme == "https" else 80

    validate_path(path)

    return scheme, host, port, path


# ---------------------------------------------------------------------------
# 3. Résolution DNS + connexion TCP (Sections 2.1.3 / 2.1.4)
# ---------------------------------------------------------------------------

def resolve_and_connect(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> socket.socket:
    try:
        addr_infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise TinyClientError(f"[Erreur DNS] Impossible de resoudre '{host}'")

    last_error = None
    for family, socktype, proto, _, sockaddr in addr_infos:
        try:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except socket.timeout:
            last_error = TinyClientError(f"[Erreur] Timeout apres {timeout:.0f} secondes")
        except ConnectionRefusedError:
            last_error = TinyClientError(f"[Erreur] Connexion refusee par {host}:{port}")
        except OSError as exc:
            last_error = TinyClientError(f"[Erreur reseau] {exc}")

    raise last_error if last_error else TinyClientError("[Erreur] Connexion impossible")


def wrap_tls(sock: socket.socket, host: str, verify: bool = True, verbose: bool = False) -> ssl.SSLSocket:

    verify=False désactive volontairement la vérification du certificat :
    cette option n'existe QUE pour la démonstration pédagogique du danger
    (cf. badssl.com) et ne doit jamais être utilisée en usage réel.
    """
    if verify:
        context = ssl.create_default_context()
    else:
        context = ssl._create_unverified_context()  # DEMO SEULEMENT — dangereux en prod

    tls_sock = context.wrap_socket(sock, server_hostname=host)

    if verbose:
        cert = tls_sock.getpeercert()
        cn = None
        if cert:
            for field in cert.get("subject", ()):
                for key, value in field:
                    if key == "commonName":
                        cn = value
        print("[TLS] Connexion securisee etablie")
        if verify:
            print(f"[TLS] Certificat verifie : CN={cn or 'inconnu'}")
        else:
            print("[TLS] ATTENTION : verification du certificat DESACTIVEE (mode demo)")

    return tls_sock


# ---------------------------------------------------------------------------
# 4. Construction et envoi de la requête (Section 2.1.5)
# ---------------------------------------------------------------------------

def build_request(method: str, host: str, path: str, extra_headers: dict = None,
                   body: bytes = None) -> bytes:
    """Construit une requête HTTP/1.1 conforme (RFC 7230).

    En-têtes obligatoires : Host, Connection: close.
    """
    validate_path(path)  # défense en profondeur, même si déjà validé en amont

    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        "Connection: close",
        "User-Agent: TinyWebClient/2.0",
    ]

    if body is not None:
        headers.append(f"Content-Length: {len(body)}")

    if extra_headers:
        for key, value in extra_headers.items():
            # Défense en profondeur contre l'injection CRLF via des en-têtes custom
            if "\r" in str(value) or "\n" in str(value) or "\r" in str(key) or "\n" in str(key):
                raise TinyClientError("Injection CRLF detectee dans un en-tete personnalise")
            headers.append(f"{key}: {value}")

    request_text = "\r\n".join(headers) + "\r\n\r\n"
    request_bytes = request_text.encode("ascii")

    if body is not None:
        request_bytes += body

    return request_bytes


def send_request(sock, request_bytes: bytes) -> None:
    sock.sendall(request_bytes)


# ---------------------------------------------------------------------------
# 5. Réception bornée de la réponse (Sections 2.1.6 / 3.3)
# ---------------------------------------------------------------------------

def receive_response(sock, max_size: int = MAX_RESPONSE_SIZE) -> bytes:
    """Lit la réponse complète en octets bruts, avec une limite de taille.

    Les données sont traitées comme des octets bruts avant tout décodage
    texte (contrainte du cahier des charges, Section 4.3).
    """
    chunks = []
    total = 0
    while True:
        try:
            data = sock.recv(RECV_CHUNK_SIZE)
        except socket.timeout:
            raise TinyClientError(f"[Erreur] Timeout pendant la reception de la reponse")
        if not data:
            break
        total += len(data)
        if total > max_size:
            raise TinyClientError(
                f"[Erreur] Reponse trop grande (> {max_size // (1024*1024)} Mo), lecture interrompue"
            )
        chunks.append(data)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# 6. Parsing de la réponse (Section 2.1.7)
# ---------------------------------------------------------------------------

def parse_response(raw: bytes):
    """Sépare la réponse en (status_line, headers_dict, body_bytes)."""
    separator = b"\r\n\r\n"
    idx = raw.find(separator)
    if idx == -1:
        raise TinyClientError("Reponse HTTP malformee : separateur en-tetes/corps introuvable")

    header_block = raw[:idx].decode("iso-8859-1")
    body = raw[idx + len(separator):]

    lines = header_block.split("\r\n")
    status_line = lines[0]

    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()

    return status_line, headers, body


def parse_status_code(status_line: str) -> int:
    """Extrait le code numérique de la ligne de statut (ex: 'HTTP/1.1 200 OK' -> 200)."""
    parts = status_line.split(" ", 2)
    if len(parts) < 2:
        raise TinyClientError(f"Ligne de statut invalide : '{status_line}'")
    try:
        return int(parts[1])
    except ValueError:
        raise TinyClientError(f"Code de statut invalide : '{parts[1]}'")


# ---------------------------------------------------------------------------
# 7. Décodage du Transfer-Encoding: chunked (bonus priorité 2)
# ---------------------------------------------------------------------------

def decode_chunked(body: bytes) -> bytes:
    """Décode un corps encodé en chunked transfer encoding.

    Format : <taille hexa>\\r\\n<données>\\r\\n ... 0\\r\\n\\r\\n
    """
    result = bytearray()
    pos = 0
    n = len(body)

    while pos < n:
        line_end = body.find(b"\r\n", pos)
        if line_end == -1:
            raise TinyClientError("Chunked encoding malforme : taille de chunk introuvable")

        size_line = body[pos:line_end].split(b";")[0].strip()  # ignore extensions de chunk
        try:
            chunk_size = int(size_line, 16)
        except ValueError:
            raise TinyClientError(f"Chunked encoding malforme : taille invalide '{size_line}'")

        pos = line_end + 2

        if chunk_size == 0:
            break  # chunk final atteint

        chunk_data = body[pos:pos + chunk_size]
        if len(chunk_data) < chunk_size:
            raise TinyClientError("Chunked encoding malforme : donnees tronquees")

        result.extend(chunk_data)
        pos += chunk_size + 2  # + \r\n de fin de chunk

    return bytes(result)


# ---------------------------------------------------------------------------
# 8. Une seule requête complète (fonction d'orchestration réutilisable)
# ---------------------------------------------------------------------------

def perform_request(url: str, method: str = "GET", body: bytes = None,
                     timeout: float = DEFAULT_TIMEOUT, max_size: int = MAX_RESPONSE_SIZE,
                     verify_tls: bool = True, verbose: bool = False, head_only: bool = False):
    """Effectue une requête HTTP/HTTPS unique et retourne (status_line, headers, decoded_body, elapsed)."""
    scheme, host, port, path = parse_url(url)

    method_used = "HEAD" if head_only else method

    start = time.perf_counter()

    raw_sock = resolve_and_connect(host, port, timeout=timeout)
    if scheme == "https":
        sock = wrap_tls(raw_sock, host, verify=verify_tls, verbose=verbose)
    else:
        sock = raw_sock

    try:
        request_bytes = build_request(method_used, host, path, body=body)
        send_request(sock, request_bytes)
        raw_response = receive_response(sock, max_size=max_size)
    finally:
        sock.close()

    elapsed = time.perf_counter() - start

    status_line, headers, body_bytes = parse_response(raw_response)

    if headers.get("Transfer-Encoding", "").lower() == "chunked":
        body_bytes = decode_chunked(body_bytes)

    return scheme, status_line, headers, body_bytes, elapsed


# ---------------------------------------------------------------------------
# 9. Gestion des redirections (bonus priorité 3)
# ---------------------------------------------------------------------------

def follow_redirects(url: str, method: str, body: bytes, timeout: float, max_size: int,
                      verify_tls: bool, verbose: bool, head_only: bool):
    visited = set()
    current_url = url
    current_scheme = parse_url(url)[0]

    for _ in range(MAX_REDIRECTS + 1):
        if current_url in visited:
            raise TinyClientError("[Erreur] Boucle de redirection detectee")
        visited.add(current_url)

        scheme, status_line, headers, body_bytes, elapsed = perform_request(
            current_url, method=method, body=body, timeout=timeout, max_size=max_size,
            verify_tls=verify_tls, verbose=verbose, head_only=head_only,
        )

        code = parse_status_code(status_line)

        if code in (301, 302, 303, 307, 308) and "Location" in headers:
            location = headers["Location"]
            new_scheme = parse_url(location)[0] if "://" in location else scheme

            if scheme == "https" and new_scheme == "http":
                raise TinyClientError(
                    "[Erreur Securite] Refus de suivre une redirection HTTPS -> HTTP"
                )

            if verbose:
                print(f"[Redirection] {code} -> {location}")

            current_url = location
            current_scheme = new_scheme
            continue

        return scheme, status_line, headers, body_bytes, elapsed

    raise TinyClientError(f"[Erreur] Trop de redirections (> {MAX_REDIRECTS})")


# ---------------------------------------------------------------------------
# 10. Interface en ligne de commande
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tinyclient",
        description="Tiny Web Client — client HTTP/HTTPS bas niveau (sockets bruts)",
    )
    parser.add_argument("url", help="URL cible, ex: http://example.com/index.html")
    parser.add_argument("-X", "--method", default="GET", choices=["GET", "POST"],
                         help="Methode HTTP (defaut: GET)")
    parser.add_argument("-d", "--data", default=None,
                         help="Corps de la requete (utilise avec -X POST)")
    parser.add_argument("--head", action="store_true",
                         help="N'affiche que les en-tetes (methode HEAD)")
    parser.add_argument("-o", "--output", default=None,
                         help="Sauvegarde le corps de la reponse dans un fichier")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                         help=f"Timeout de connexion en secondes (defaut: {DEFAULT_TIMEOUT})")
    parser.add_argument("--max-size", type=int, default=MAX_RESPONSE_SIZE,
                         help="Taille maximale de reponse acceptee, en octets")
    parser.add_argument("--no-verify", action="store_true",
                         help="[DEMO SECURITE] Desactive la verification du certificat TLS")
    parser.add_argument("--no-redirect", action="store_true",
                         help="Ne pas suivre les redirections 301/302")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Affiche des informations supplementaires (TLS, redirections, timing)")
    return parser


def print_response(status_line: str, headers: dict, body: bytes, elapsed: float, verbose: bool):
    print(f"[Status] {status_line.split(' ', 1)[1] if ' ' in status_line else status_line}")
    print("[Headers]")
    for key, value in headers.items():
        print(f"{key}: {value}")

    if body:
        print("[Body]")
        try:
            print(body.decode("utf-8"))
        except UnicodeDecodeError:
            print(f"<contenu binaire, {len(body)} octets — non affichable en texte>")

    if verbose:
        print(f"[Timing] Temps de reponse : {elapsed * 1000:.1f} ms")


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    body_bytes = args.data.encode("utf-8") if args.data else None
    method = "POST" if args.data is not None else args.method

    try:
        if args.no_redirect:
            scheme, status_line, headers, body, elapsed = perform_request(
                args.url, method=method, body=body_bytes, timeout=args.timeout,
                max_size=args.max_size, verify_tls=not args.no_verify,
                verbose=args.verbose, head_only=args.head,
            )
        else:
            scheme, status_line, headers, body, elapsed = follow_redirects(
                args.url, method=method, body=body_bytes, timeout=args.timeout,
                max_size=args.max_size, verify_tls=not args.no_verify,
                verbose=args.verbose, head_only=args.head,
            )
    except TinyClientError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[Interrompu par l'utilisateur]", file=sys.stderr)
        return 130

    print_response(status_line, headers, body, elapsed, args.verbose)

    if args.output and body:
        with open(args.output, "wb") as f:
            f.write(body)
        print(f"\n[Sauvegarde] Corps de la reponse ecrit dans '{args.output}'")

    return 0


if __name__ == "__main__":
    sys.exit(main())
