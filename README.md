# filecrypt

CLI file encryption tool with strong cryptography and recovery key support.

## Security stack

| Component | Choice | Reason |
|-----------|--------|--------|
| Cipher | AES-256-GCM | Authenticated encryption, detects tampering |
| KDF | Argon2id | Winner of Password Hashing Competition, GPU-resistant |
| Argon2 params | t=3, m=65536, p=2 | 64MB RAM, ~0.5s per derivation |
| Architecture | Two-layer key wrapping | Change password without re-encrypting data |
| Recovery | 256-bit recovery key | Printed backup if password is lost |

## Architecture

```
Password/RecoveryKey → Argon2id → Master Key (32 bytes)
                                        ↓
                          Master Key wraps File Key (AES-256-GCM)
                                        ↓
                          File Key encrypts file content (AES-256-GCM)
```

Both password and recovery key wrap the same file key independently, so either can decrypt the file.

## Requirements

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Encrypt one or more files (any type)
python encrypt.py photo.jpg document.pdf notes.txt

# Encrypt without recovery key
python encrypt.py --no-recovery archive.zip

# Encrypt to specific output directory
python encrypt.py --output-dir D:\Encrypted file.pdf

# Decrypt with password
python decrypt.py file.pdf.enc

# Decrypt with recovery key (if password is lost)
python decrypt.py --recovery file.pdf.enc

# Decrypt multiple files to a directory
python decrypt.py --output-dir D:\Recovered *.enc
```

## Recovery key

When encrypting, a recovery key is generated and displayed once:

```
┌─────────────────────────────────────────────────────┐
│           ★  RECOVERY KEY — GUARDALA SEGURA  ★      │
│                                                      │
│   LLBX-EI2K-LOPD-7KSD  Z6NJ-DRCL-E3Z6-7UF4         │
│   3MPY-CZVJ-O2OG-LAC3  ZP4Q-XXXX-XXXX-XXXX         │
│                                                      │
│  Si perdés la contraseña, usá esta clave para        │
│  recuperar tus archivos con:                         │
│    python decrypt.py --recovery archivo.enc          │
└─────────────────────────────────────────────────────┘
```

Print it and store it securely. It is never saved to disk.

## File format

```
[4 bytes]  magic: FCRY
[1 byte]   version
[1 byte]   flags (bit0 = recovery key present)
[16 bytes] Argon2id salt
[60 bytes] wrapped file key (password)
[60 bytes] wrapped file key (recovery key)
[12 bytes] content IV
[16 bytes] content GCM tag
[N bytes]  encrypted content
```
