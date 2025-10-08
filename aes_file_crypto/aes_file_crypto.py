#!/usr/bin/env python3
"""
AES File Encrypt/Decrypt Tool (AES-CBC, password-based)
Dapat dijalankan langsung di Spyder, VSCode, atau terminal tanpa argumen.

Fitur:
1. Enkripsi file teks (.txt) ke file biner terenkripsi (.bin)
2. Dekripsi file terenkripsi (.bin) kembali ke teks asli
"""

import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Konstanta
MAGIC = b'AESENC'   # 6 bytes
VERSION = b'\x01'   # 1 byte
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32       # 256-bit AES
KDF_ITERATIONS = 200_000
backend = default_backend()


# ===== Fungsi Kunci & Enkripsi =====
def derive_key(password: bytes, salt: bytes, iterations=KDF_ITERATIONS, length=KEY_SIZE) -> bytes:
    """Turunkan key AES dari password + salt dengan PBKDF2-HMAC-SHA256"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    return kdf.derive(password)


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Return encrypted blob: MAGIC + VERSION + salt + iv + ciphertext"""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode('utf-8'), salt)
    iv = os.urandom(IV_SIZE)

    # Padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return MAGIC + VERSION + salt + iv + ciphertext


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Return plaintext bytes dari blob terenkripsi"""
    expected_header_len = len(MAGIC) + 1 + SALT_SIZE + IV_SIZE
    if len(blob) < expected_header_len:
        raise ValueError("Encrypted file too short or corrupted.")

    magic = blob[:len(MAGIC)]
    version = blob[len(MAGIC):len(MAGIC)+1]
    if magic != MAGIC:
        raise ValueError("File magic mismatch.")
    if version != VERSION:
        raise ValueError("Unsupported version.")

    offset = len(MAGIC) + 1
    salt = blob[offset:offset+SALT_SIZE]
    offset += SALT_SIZE
    iv = blob[offset:offset+IV_SIZE]
    offset += IV_SIZE
    ciphertext = blob[offset:]

    key = derive_key(password.encode('utf-8'), salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext


# ===== Fungsi File =====
def encrypt_file(input_file: str, output_file: str, password: str):
    in_path = Path(input_file)
    if not in_path.exists():
        print(f"❌ File '{input_file}' tidak ditemukan.")
        return

    data = in_path.read_bytes()
    blob = encrypt_bytes(data, password)
    Path(output_file).write_bytes(blob)
    print(f"✅ Enkripsi selesai: '{input_file}' → '{output_file}'")


def decrypt_file(input_file: str, output_file: str, password: str):
    in_path = Path(input_file)
    if not in_path.exists():
        print(f"❌ File '{input_file}' tidak ditemukan.")
        return

    blob = in_path.read_bytes()
    try:
        plaintext = decrypt_bytes(blob, password)
        Path(output_file).write_bytes(plaintext)
        print(f"✅ Dekripsi selesai: '{input_file}' → '{output_file}'")
    except Exception as e:
        print("❌ Gagal mendekripsi:", str(e))


# ===== Main Menu =====
def main():
    print("="*50)
    print("🔐 AES File Encryption (Mode: CBC)")
    print("="*50)
    print("1. Enkripsi file teks (.txt)")
    print("2. Dekripsi file terenkripsi (.bin)")
    print("3. Keluar")
    print("="*50)

    choice = input("Pilih menu [1/2/3]: ").strip()
    if choice == '1':
        input_file = input("Masukkan nama file teks (.txt): ").strip()
        output_file = input("Masukkan nama file output (.bin): ").strip()
        password = input("Masukkan password: ").strip()
        encrypt_file(input_file, output_file, password)

    elif choice == '2':
        input_file = input("Masukkan nama file terenkripsi (.bin): ").strip()
        output_file = input("Masukkan nama file hasil dekripsi (.txt): ").strip()
        password = input("Masukkan password: ").strip()
        decrypt_file(input_file, output_file, password)

    elif choice == '3':
        print("Keluar dari program.")
        return
    else:
        print("Pilihan tidak valid.")
        return


if __name__ == '__main__':
    main()
