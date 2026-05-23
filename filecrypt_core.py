"""
filecrypt_core.py — Motor de cifrado
Arquitectura:
  Contraseña/RecoveryKey → Argon2id → Master Key (32 bytes)
  Master Key cifra una File Key aleatoria (32 bytes) con AES-256-GCM
  File Key cifra el contenido del archivo con AES-256-GCM

Formato del archivo .enc:
  [4 bytes]  magic: b'FCRY'
  [1 byte]   version: 0x01
  [1 byte]   flags: bit0=cifrado_con_recovery_key
  [16 bytes] salt Argon2id
  [12 bytes] IV del wrapped file key
  [16 bytes] tag del wrapped file key
  [32 bytes] wrapped file key (cifrada con master key)
  [12 bytes] IV del contenido
  [16 bytes] tag del contenido
  [N bytes]  contenido cifrado
"""

import os
import struct
import base64
import secrets
from pathlib import Path

from argon2.low_level import hash_secret_raw, Type
from Crypto.Cipher import AES

# ── Constantes ────────────────────────────────────────────────────────────────
MAGIC        = b'FCRY'
VERSION      = 0x01
FLAG_RECOVERY = 0x01

# Argon2id params (2026-recomendado, ajustable)
ARGON2_TIME_COST   = 3
ARGON2_MEMORY_COST = 65536   # 64 MB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN    = 32
ARGON2_SALT_LEN    = 16

# Recovery key: 32 bytes → codificada en grupos de 4 chars Base32
RECOVERY_KEY_BYTES = 32


# ── Recovery Key ──────────────────────────────────────────────────────────────

def generate_recovery_key() -> bytes:
    """Genera 32 bytes aleatorios como recovery key."""
    return secrets.token_bytes(RECOVERY_KEY_BYTES)


def recovery_key_to_str(key_bytes: bytes) -> str:
    """Convierte bytes a formato legible: XXXX-XXXX-XXXX-... (Base32, sin padding)."""
    b32 = base64.b32encode(key_bytes).decode().rstrip("=")
    return "-".join(b32[i:i+4] for i in range(0, len(b32), 4))


def recovery_key_from_str(key_str: str) -> bytes:
    """Parsea una recovery key en formato string a bytes."""
    clean = key_str.upper().replace("-", "").replace(" ", "")
    # Base32 necesita padding múltiplo de 8
    pad = (8 - len(clean) % 8) % 8
    try:
        return base64.b32decode(clean + "=" * pad)
    except Exception:
        raise ValueError("Recovery key inválida. Verificá que la copiaste correctamente.")


# ── KDF ───────────────────────────────────────────────────────────────────────

def derive_master_key(secret: bytes, salt: bytes) -> bytes:
    """Deriva master key de 32 bytes usando Argon2id."""
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


# ── AES-256-GCM helpers ───────────────────────────────────────────────────────

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes, bytes]:
    """Cifra con AES-256-GCM. Retorna (iv, tag, ciphertext)."""
    iv = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv, tag, ciphertext


def aes_gcm_decrypt(key: bytes, iv: bytes, tag: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Descifra con AES-256-GCM. Lanza ValueError si el tag no coincide."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ── Encrypt ───────────────────────────────────────────────────────────────────

def encrypt_file(
    input_path: str,
    output_path: str,
    password: str | None = None,
    recovery_key: bytes | None = None,
) -> None:
    """
    Cifra un archivo. Requiere password y/o recovery_key.
    Si se pasan ambos, el archivo puede descifrarse con cualquiera de los dos.
    """
    if not password and recovery_key is None:
        raise ValueError("Se requiere al menos contraseña o recovery key.")

    data = Path(input_path).read_bytes()

    # File key aleatoria — cifra el contenido real
    file_key = secrets.token_bytes(32)

    # Cifrar contenido con file key
    # AAD = magic + version para integridad del header
    aad_content = MAGIC + bytes([VERSION])
    iv_content, tag_content, ct_content = aes_gcm_encrypt(file_key, data, aad=aad_content)

    # Preparar bloque(s) de wrapped key
    # Siempre guardamos el bloque de contraseña; opcionalmente el de recovery key
    salt = secrets.token_bytes(ARGON2_SALT_LEN)
    flags = 0x00

    # Wrapped key con contraseña
    if password:
        master_key_pw = derive_master_key(password.encode("utf-8"), salt)
        iv_wk_pw, tag_wk_pw, ct_wk_pw = aes_gcm_encrypt(master_key_pw, file_key)
    else:
        # Placeholder vacío si no hay contraseña (solo recovery key)
        iv_wk_pw  = bytes(12)
        tag_wk_pw = bytes(16)
        ct_wk_pw  = bytes(32)

    # Wrapped key con recovery key
    if recovery_key is not None:
        flags |= FLAG_RECOVERY
        master_key_rk = derive_master_key(recovery_key, salt)
        iv_wk_rk, tag_wk_rk, ct_wk_rk = aes_gcm_encrypt(master_key_rk, file_key)
    else:
        iv_wk_rk  = bytes(12)
        tag_wk_rk = bytes(16)
        ct_wk_rk  = bytes(32)

    # Serializar
    with open(output_path, "wb") as f:
        f.write(MAGIC)                          # 4
        f.write(bytes([VERSION]))               # 1
        f.write(bytes([flags]))                 # 1
        f.write(salt)                           # 16
        # Wrapped key (password)
        f.write(iv_wk_pw)                       # 12
        f.write(tag_wk_pw)                      # 16
        f.write(ct_wk_pw)                       # 32
        # Wrapped key (recovery)
        f.write(iv_wk_rk)                       # 12
        f.write(tag_wk_rk)                      # 16
        f.write(ct_wk_rk)                       # 32
        # Contenido
        f.write(iv_content)                     # 12
        f.write(tag_content)                    # 16
        f.write(ct_content)                     # N


# ── Decrypt ───────────────────────────────────────────────────────────────────

def decrypt_file(
    input_path: str,
    output_path: str,
    password: str | None = None,
    recovery_key: bytes | None = None,
) -> None:
    """Descifra un archivo .enc usando contraseña o recovery key."""
    if not password and recovery_key is None:
        raise ValueError("Se requiere contraseña o recovery key.")

    raw = Path(input_path).read_bytes()
    offset = 0

    def read(n):
        nonlocal offset
        chunk = raw[offset:offset+n]
        offset += n
        return chunk

    # Header
    magic = read(4)
    if magic != MAGIC:
        raise ValueError("No es un archivo .enc válido (magic bytes incorrectos).")

    version = read(1)[0]
    if version != VERSION:
        raise ValueError(f"Versión de archivo no soportada: {version}")

    flags = read(1)[0]
    salt  = read(16)

    # Wrapped keys
    iv_wk_pw  = read(12); tag_wk_pw  = read(16); ct_wk_pw  = read(32)
    iv_wk_rk  = read(12); tag_wk_rk  = read(16); ct_wk_rk  = read(32)

    # Contenido
    iv_content  = read(12)
    tag_content = read(16)
    ct_content  = raw[offset:]

    # Intentar descifrar file key
    file_key = None
    last_error = None

    if password:
        try:
            master_key = derive_master_key(password.encode("utf-8"), salt)
            file_key = aes_gcm_decrypt(master_key, iv_wk_pw, tag_wk_pw, ct_wk_pw)
        except ValueError as e:
            last_error = "Contraseña incorrecta."

    if file_key is None and recovery_key is not None:
        if not (flags & FLAG_RECOVERY):
            raise ValueError("Este archivo no fue cifrado con recovery key.")
        try:
            master_key = derive_master_key(recovery_key, salt)
            file_key = aes_gcm_decrypt(master_key, iv_wk_rk, tag_wk_rk, ct_wk_rk)
        except ValueError:
            last_error = "Recovery key incorrecta."

    if file_key is None:
        raise ValueError(last_error or "No se pudo descifrar la clave del archivo.")

    # Descifrar contenido
    aad_content = MAGIC + bytes([VERSION])
    try:
        plaintext = aes_gcm_decrypt(file_key, iv_content, tag_content, ct_content, aad=aad_content)
    except ValueError:
        raise ValueError("El archivo está corrupto o fue modificado.")

    Path(output_path).write_bytes(plaintext)
