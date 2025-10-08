# 🔐 AES File Crypto Utility

Sebuah utilitas Python sederhana untuk **mengenkripsi dan mendekripsi file teks** menggunakan **AES-CBC (Advanced Encryption Standard - Cipher Block Chaining)** dengan **password-based encryption (PBKDF2-HMAC-SHA256)**.
Proyek ini dirancang agar **mudah digunakan di terminal maupun IDE seperti Spyder** tanpa membutuhkan dependensi eksternal yang rumit.

---

## 📜 Fitur

* 🔒 Enkripsi file teks (`.txt`) menjadi file biner terenkripsi (`.bin`)
* 🔓 Dekripsi file terenkripsi kembali ke teks asli
* 🔑 Proteksi menggunakan password yang dikonversi menjadi key AES 256-bit dengan PBKDF2
* 🧂 Salt dan IV (Initialization Vector) dibuat acak setiap kali enkripsi
* 🧱 Padding otomatis (PKCS7)
* 💾 File hasil enkripsi menyimpan metadata di dalamnya:

  ```
  [Magic][Version][Salt][IV][Ciphertext...]
  ```
* ✅ Kompatibel untuk dijalankan di:

  * Terminal / Command Prompt
  * Spyder, VSCode, atau IDE Python lainnya

---

## 📁 Struktur File

```
aes_file_crypto.py     ← Skrip utama
pesan.txt              ← File teks contoh untuk dienkripsi
pesan_encrypted.bin    ← File hasil enkripsi
pesan_decrypted.txt    ← File hasil dekripsi
```

---

## ⚙️ Instalasi

### 1️⃣ Persiapan Lingkungan

Pastikan Python 3 sudah terinstal:

```bash
python --version
```

Jika belum, unduh dari [python.org](https://www.python.org/downloads/).

---

### 2️⃣ Instal Dependensi

Library utama yang dibutuhkan adalah `cryptography`.
Instal dengan perintah berikut:

```bash
pip install cryptography
```

---

## 🚀 Cara Penggunaan

### 🔹 Enkripsi File

Contoh:

```bash
python aes_file_crypto.py encrypt pesan.txt pesan_encrypted.bin
```

Keterangan:

* `encrypt` → mode enkripsi
* `pesan.txt` → file input yang ingin dienkripsi
* `pesan_encrypted.bin` → file output hasil enkripsi

Setelah menjalankan perintah, program akan meminta password:

```
Password: ******
```

Jika berhasil, akan muncul pesan:

```
Encrypted 'pesan.txt' -> 'pesan_encrypted.bin' (salt and IV stored inside).
```

---

### 🔹 Dekripsi File

Contoh:

```bash
python aes_file_crypto.py decrypt pesan_encrypted.bin pesan_decrypted.txt
```

Masukkan password yang sama saat enkripsi.
Hasilnya akan muncul file `pesan_decrypted.txt` berisi isi asli teks.

Jika password salah:

```
Decryption failed: Invalid padding bytes.
```

---

### 🔹 Menjalankan di Spyder / IDE

1. Buka file `aes_file_crypto.py` di Spyder.
2. Klik kanan di area editor → **Run file** atau tekan **F5**.
3. Saat Spyder meminta argumen, masukkan misalnya:

   ```
   encrypt pesan.txt pesan_encrypted.bin
   ```
4. Program akan berjalan dan meminta password di console Spyder.

Untuk dekripsi, gunakan:

```
decrypt pesan_encrypted.bin pesan_decrypted.txt
```

---

## 🔧 Format File Enkripsi

Setiap file hasil enkripsi memiliki struktur biner:

| Komponen   | Ukuran   | Deskripsi                           |
| ---------- | -------- | ----------------------------------- |
| Magic      | 6 byte   | Penanda file (`AESENC`)             |
| Version    | 1 byte   | Versi format (saat ini `\x01`)      |
| Salt       | 16 byte  | Salt acak untuk PBKDF2              |
| IV         | 16 byte  | Initialization Vector untuk AES-CBC |
| Ciphertext | variabel | Data terenkripsi                    |

---

## 🧠 Algoritma yang Digunakan

* **AES (Advanced Encryption Standard)** dengan **256-bit key**
* **Mode CBC (Cipher Block Chaining)**
* **PBKDF2-HMAC-SHA256** untuk derivasi key dari password
* **PKCS7 Padding** untuk mengisi blok cipher

---

## 🧩 Contoh Lengkap

### File Asli (`pesan.txt`)

```
Halo, ini pesan rahasia saya!
```

### Enkripsi

```bash
python aes_file_crypto.py encrypt pesan.txt pesan_encrypted.bin
```

### Dekripsi

```bash
python aes_file_crypto.py decrypt pesan_encrypted.bin pesan_decrypted.txt
```

### Output (`pesan_decrypted.txt`)

```
Halo, ini pesan rahasia saya!
```

---

## ⚠️ Catatan Keamanan

* Gunakan **password kuat** (panjang dan unik).
* Jika file `.bin` terenkripsi hilang **atau password lupa**, **data tidak bisa dipulihkan**.
* Jangan bagikan salt/IV atau password secara publik.

---

## 📘 Lisensi

Proyek ini dirilis dengan lisensi **MIT License** — bebas digunakan untuk keperluan pribadi maupun komersial.

---

## ✨ Kontributor

* **Author:** Aditya Maulana
* **Helper AI:** ChatGPT (OpenAI GPT-5)
* **Library:** cryptography (Python)

---

## 💬 Kontak

Untuk pertanyaan atau bug report, buka *Issues* di repository GitHub Anda atau hubungi:

```
github.com/USERNAME
```
