#!/usr/bin/env python3
"""
decrypt.py — Descifra uno o varios archivos .enc
Uso:
  python decrypt.py archivo.pdf.enc
  python decrypt.py *.enc
  python decrypt.py --recovery archivo.pdf.enc     (usar recovery key)
  python decrypt.py --output-dir D:\Recuperados archivo.pdf.enc
"""

import sys
import getpass
import argparse
from pathlib import Path

try:
    from filecrypt_core import decrypt_file, recovery_key_from_str
except ImportError:
    print("ERROR: filecrypt_core.py debe estar en el mismo directorio.")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Descifra archivos .enc (AES-256-GCM + Argon2id)"
    )
    parser.add_argument("files", nargs="+", help="Archivos .enc a descifrar")
    parser.add_argument(
        "--recovery",
        action="store_true",
        help="Descifrar usando recovery key en lugar de contraseña",
    )
    parser.add_argument(
        "--output-dir",
        help="Directorio de salida (por defecto: mismo directorio del archivo)",
    )
    args = parser.parse_args()

    # Verificar archivos
    paths = []
    for f in args.files:
        p = Path(f)
        if not p.exists():
            print(f"  ERROR: No existe: {f}")
            sys.exit(1)
        paths.append(p)

    print()

    # Obtener credencial
    password = None
    recovery_key = None

    if args.recovery:
        rk_str = getpass.getpass("Recovery key: ")
        try:
            recovery_key = recovery_key_from_str(rk_str)
        except ValueError as e:
            print(f"  ERROR: {e}")
            sys.exit(1)
    else:
        password = getpass.getpass("Contraseña: ")

    print()
    ok = 0
    fail = 0

    for p in paths:
        # Determinar nombre de salida (quitar .enc)
        if p.suffix == ".enc":
            base_name = p.stem   # quita .enc
        else:
            base_name = p.name + ".dec"

        if args.output_dir:
            out = Path(args.output_dir) / base_name
        else:
            out = p.parent / base_name

        # Evitar sobreescribir sin avisar
        if out.exists():
            resp = input(f"  '{out.name}' ya existe. ¿Sobreescribir? [s/N]: ").strip().lower()
            if resp != "s":
                print(f"  Saltando {p.name}")
                continue

        try:
            print(f"  Descifrando {p.name}...", end=" ", flush=True)
            decrypt_file(
                str(p),
                str(out),
                password=password,
                recovery_key=recovery_key,
            )
            print(f"→ {out.name}  ✓")
            ok += 1
        except ValueError as e:
            print(f"✗  {e}")
            fail += 1
        except Exception as e:
            print(f"✗  Error inesperado: {e}")
            fail += 1

    print(f"\n  Total: {ok} descifrados, {fail} fallidos")

    if fail > 0 and not args.recovery:
        print()
        print("  Si olvidaste la contraseña, intentá con la recovery key:")
        print("    python decrypt.py --recovery archivo.enc")


if __name__ == "__main__":
    main()
