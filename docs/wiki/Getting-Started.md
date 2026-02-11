# Getting Started

## Installation
```bash
git clone https://github.com/bad-antics/nullsec-ctf
cd nullsec-ctf
pip install -r requirements.txt
```

## Quick Usage

```bash
# Decode base64
python3 ctf.py decode base64 "SGVsbG8gV29ybGQ="

# ROT13
python3 ctf.py encode rot13 "Hello World"

# Analyze a file
python3 ctf.py forensics analyze suspicious_file.png

# Crack a hash
python3 ctf.py crypto crack-hash "5d41402abc4b2a76b9719d911017c592"

# XOR brute force
python3 ctf.py crypto xor-brute encrypted.bin
```

## Interactive Mode
```bash
python3 ctf.py shell
ctf> help
ctf> crypto.caesar "Uryyb Jbeyq" 13
Hello World
```
