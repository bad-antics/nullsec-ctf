<div align="center">

# 🚩 NullSec CTF Toolkit

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

**All-in-one CTF helper tool for rapid encoding/decoding, crypto challenges, forensics, and more.**

```bash
pip install nullsec-ctf
```

</div>

---

## ⚡ Quick Start

```bash
# Install
pip install nullsec-ctf

# or run directly
python nullsec-ctf.py

# Interactive mode
ctf

# One-liner
ctf decode base64 "SGVsbG8gV29ybGQ="
```

## 🛠️ Features

### Encoding/Decoding
- **Base64** - Standard & URL-safe
- **Hex** - Hexadecimal conversions
- **Binary** - Binary to/from text
- **ROT13/ROTn** - Caesar cipher with any rotation
- **URL** - URL encode/decode
- **HTML** - Entity encode/decode
- **ASCII** - Character codes
- **Morse** - Morse code translation

### Cryptography
- **Hash Identification** - Auto-detect hash types
- **Hash Cracking** - Dictionary attacks
- **XOR** - Key analysis & brute force
- **Vigenère** - Auto key-length detection
- **RSA** - Common attacks (small e, Wiener's, etc.)
- **AES** - ECB detection, padding oracle

### Forensics
- **File Carving** - Extract embedded files
- **Steganography** - LSB extraction, analyze images
- **Strings** - Extract readable strings
- **Magic Bytes** - File type identification
- **Metadata** - EXIF, document properties

### Network
- **Packet Analysis** - Quick PCAP summaries
- **DNS Lookup** - Resolve records
- **Port Scan** - Quick target enumeration

### Web
- **JWT Decode** - Parse & verify tokens
- **Cookie Decode** - Flask, Django sessions
- **SQL Injection** - Payload generator
- **XSS Payloads** - Curated XSS list

---

## 📖 Usage Examples

### Encoding

```bash
# Base64
ctf encode base64 "flag{hello}"
# Output: ZmxhZ3toZWxsb30=

ctf decode base64 "ZmxhZ3toZWxsb30="
# Output: flag{hello}

# Hex
ctf encode hex "flag"
# Output: 666c6167

# ROT13
ctf rot13 "synt{frperg}"
# Output: flag{secret}

# ROT with custom shift
ctf rot 5 "kqfl{xjhwjy}"
# Output: flag{secret}
```

### Hash Operations

```bash
# Identify hash type
ctf hash-id "5d41402abc4b2a76b9719d911017c592"
# Output: MD5

# Crack hash
ctf crack md5 "5d41402abc4b2a76b9719d911017c592" -w rockyou.txt
# Output: hello

# Generate hashes
ctf hash md5 "password"
# Output: 5f4dcc3b5aa765d61d8327deb882cf99
```

### Crypto Challenges

```bash
# XOR brute force single byte
ctf xor-brute "encrypted_hex"

# XOR with known key
ctf xor "hex_data" -k "KEY"

# Vigenère auto-solve
ctf vigenere "CIPHERTEXT"

# RSA common attacks
ctf rsa -n 123456789 -e 65537 -c 987654321
```

### Forensics

```bash
# Identify file type
ctf filetype mystery.bin

# Extract strings
ctf strings binary.exe -n 6

# Find hidden files
ctf binwalk firmware.bin

# LSB steganography
ctf steg-lsb image.png
```

### Web

```bash
# Decode JWT
ctf jwt "eyJhbGciOiJIUzI1NiIs..."

# Generate SQLi payloads
ctf sqli

# XSS payload list
ctf xss
```

---

## 🎯 Interactive Mode

```bash
$ ctf
                                  
 ███╗   ██╗██╗   ██╗██╗     ██╗     
 ████╗  ██║██║   ██║██║     ██║     
 ██╔██╗ ██║██║   ██║██║     ██║     
 ██║╚██╗██║██║   ██║██║     ██║     
 ██║ ╚████║╚██████╔╝███████╗███████╗
 ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝
       CTF Toolkit v1.0.0
                                    
CTF> help
Commands:
  encode <type> <text>    - Encode text
  decode <type> <text>    - Decode text  
  hash <algo> <text>      - Generate hash
  hash-id <hash>          - Identify hash
  crack <algo> <hash>     - Crack hash
  rot <n> <text>          - ROT cipher
  xor <data> -k <key>     - XOR operation
  ...

CTF> decode base64 ZmxhZ3t0ZXN0fQ==
flag{test}

CTF> hash-id 5d41402abc4b2a76b9719d911017c592
[+] Possible hash types:
    - MD5 (most likely)
    - MD4
    - NTLM
```

---

## 📦 Installation

```bash
# From PyPI
pip install nullsec-ctf

# From source
git clone https://github.com/bad-antics/nullsec-ctf
cd nullsec-ctf
pip install -e .

# No install (just run)
python nullsec-ctf.py
```

### Dependencies

```
pycryptodome>=3.15.0
requests>=2.28.0
beautifulsoup4>=4.11.0
Pillow>=9.0.0
```

---

## 🏆 CTF Cheat Sheet

### Common Flag Formats
```
flag{...}
FLAG{...}
ctf{...}
picoCTF{...}
HTB{...}
```

### Hash Lengths
| Algorithm | Length (chars) |
|-----------|----------------|
| MD5 | 32 |
| SHA-1 | 40 |
| SHA-256 | 64 |
| SHA-512 | 128 |

### Magic Bytes
| File Type | Magic (hex) |
|-----------|-------------|
| PNG | 89 50 4E 47 |
| JPEG | FF D8 FF |
| PDF | 25 50 44 46 |
| ZIP | 50 4B 03 04 |
| GIF | 47 49 46 38 |

---

## 🤝 Contributing

PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

<div align="center">

*Part of the [NullSec](https://github.com/bad-antics/nullsec-linux) ecosystem*

**Made for CTF players, by CTF players** ��

</div>
