#!/usr/bin/env python3
"""
encrypt.py — Cifra uno o varios archivos
Uso:
  python encrypt.py archivo.pdf
  python encrypt.py foto.jpg documento.docx notas.txt
  python encrypt.py --no-recovery archivo.pdf    (sin recovery key)
"""

import sys
import getpass
import argparse
from pathlib import Path

try:
    from filecrypt_core import (
        encrypt_file,
        generate_recovery_key,
        recovery_key_to_str,
    )
except ImportError:
    print("ERROR: filecrypt_core.py debe estar en el mismo directorio.")
    sys.exit(1)


def print_recovery_key_card(rk_str: str):
    lines = [
        "┌─────────────────────────────────────────────────────┐",
        "│           ★  RECOVERY KEY — GUARDALA SEGURA  ★      │",
        "│                                                      │",
    ]
    # Dividir en dos filas de 4 grupos
    groups = rk_str.split("-")
    row1 = "  ".join(groups[:8])
    row2 = "  ".join(groups[8:])
    lines.append(f"│   {row1:<48} │")
    lines.append(f"│   {row2:<48} │")
    lines.append("│                                                      │")
    lines.append("│  Si perdés la contraseña, usá esta clave para        │")
    lines.append("│  recuperar tus archivos con:                         │")
    lines.append("│    python decrypt.py --recovery archivo.enc          │")
    lines.append("└─────────────────────────────────────────────────────┘")
    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(
        description="Cifra archivos con AES-256-GCM + Argon2id"
    )
    parser.add_argument("files", nargs="+", help="Archivos a cifrar")
    parser.add_argument(
        "--no-recovery",
        action="store_true",
        help="No generar recovery key (solo contraseña)",
    )
    parser.add_argument(
        "--output-dir",
        help="Directorio de salida (por defecto: mismo directorio del archivo)",
    )
    args = parser.parse_args()

    # Verificar archivos existen
    paths = []
    for f in args.files:
        p = Path(f)
        if not p.exists():
            print(f"  ERROR: No existe: {f}")
            sys.exit(1)
        if p.suffix == ".enc":
            print(f"  AVISO: '{f}' ya tiene extensión .enc — ¿ya está cifrado?")
        paths.append(p)

    # Contraseña
    print()
    while True:
        pw = getpass.getpass("Contraseña: ")
        pw2 = getpass.getpass("Repetir contraseña: ")
        if pw == pw2:
            break
        print("  Las contraseñas no coinciden. Intentá de nuevo.\n")

    # Recovery key
    recovery_key = None
    rk_str = None
    if not args.no_recovery:
        recovery_key = generate_recovery_key()
        rk_str = recovery_key_to_str(recovery_key)

    print()
    ok = 0
    fail = 0

    for p in paths:
        if args.output_dir:
            out = Path(args.output_dir) / (p.name + ".enc")
        else:
            out = p.with_suffix(p.suffix + ".enc")

        try:
            print(f"  Cifrando {p.name}...", end=" ", flush=True)
            encrypt_file(
                str(p),
                str(out),
                password=pw if pw else None,
                recovery_key=recovery_key,
            )
            print(f"→ {out.name}  ✓")
            ok += 1
        except Exception as e:
            print(f"✗ ERROR: {e}")
            fail += 1

    print(f"\n  Total: {ok} cifrados, {fail} fallidos")

    # Mostrar recovery key al final
    if rk_str and ok > 0:
        print()
        print_recovery_key_card(rk_str)
        print()
        print("  ⚠  Anotá o imprimí esta clave AHORA.")
        print("  ⚠  No se vuelve a mostrar.\n")


if __name__ == "__main__":
    main()
