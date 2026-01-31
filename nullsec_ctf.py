#!/usr/bin/env python3
"""
NullSec CTF Toolkit
All-in-one CTF helper for rapid encoding/decoding, crypto, and forensics
"""

import base64
import binascii
import hashlib
import string
import sys
import re
import json
import argparse
from typing import Optional, List, Tuple
from collections import Counter

BANNER = r"""
 ███╗   ██╗██╗   ██╗██╗     ██╗     ███████╗███████╗ ██████╗
 ████╗  ██║██║   ██║██║     ██║     ██╔════╝██╔════╝██╔════╝
 ██╔██╗ ██║██║   ██║██║     ██║     ███████╗█████╗  ██║     
 ██║╚██╗██║██║   ██║██║     ██║     ╚════██║██╔══╝  ██║     
 ██║ ╚████║╚██████╔╝███████╗███████╗███████║███████╗╚██████╗
 ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝
        CTF Toolkit v1.0.0 | NullSec
"""

# =============================================================================
# ENCODING/DECODING
# =============================================================================

class Encoder:
    """Encoding and decoding utilities"""
    
    @staticmethod
    def base64_encode(data: str) -> str:
        return base64.b64encode(data.encode()).decode()
    
    @staticmethod
    def base64_decode(data: str) -> str:
        try:
            return base64.b64decode(data).decode()
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def base64_url_encode(data: str) -> str:
        return base64.urlsafe_b64encode(data.encode()).decode()
    
    @staticmethod
    def base64_url_decode(data: str) -> str:
        try:
            # Add padding if needed
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            return base64.urlsafe_b64decode(data).decode()
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def hex_encode(data: str) -> str:
        return data.encode().hex()
    
    @staticmethod
    def hex_decode(data: str) -> str:
        try:
            return bytes.fromhex(data).decode()
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def binary_encode(data: str) -> str:
        return ' '.join(format(ord(c), '08b') for c in data)
    
    @staticmethod
    def binary_decode(data: str) -> str:
        try:
            binary = data.replace(' ', '')
            chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
            return ''.join(chr(int(b, 2)) for b in chars)
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def url_encode(data: str) -> str:
        from urllib.parse import quote
        return quote(data)
    
    @staticmethod
    def url_decode(data: str) -> str:
        from urllib.parse import unquote
        return unquote(data)
    
    @staticmethod
    def html_encode(data: str) -> str:
        import html
        return html.escape(data)
    
    @staticmethod
    def html_decode(data: str) -> str:
        import html
        return html.unescape(data)
    
    @staticmethod
    def ascii_encode(data: str) -> str:
        return ' '.join(str(ord(c)) for c in data)
    
    @staticmethod
    def ascii_decode(data: str) -> str:
        try:
            return ''.join(chr(int(n)) for n in data.split())
        except Exception as e:
            return f"Error: {e}"


# =============================================================================
# CIPHERS
# =============================================================================

class Ciphers:
    """Classical cipher utilities"""
    
    MORSE_CODE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
        'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....',
        '7': '--...', '8': '---..', '9': '----.'
    }
    
    @staticmethod
    def rot(text: str, n: int = 13) -> str:
        """ROT cipher with custom rotation"""
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + n) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def rot_brute(text: str) -> List[Tuple[int, str]]:
        """Try all 26 rotations"""
        results = []
        for i in range(26):
            results.append((i, Ciphers.rot(text, i)))
        return results
    
    @staticmethod
    def caesar_decrypt(text: str) -> List[Tuple[int, str, float]]:
        """Decrypt Caesar cipher with frequency analysis"""
        english_freq = {
            'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
            'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0
        }
        results = []
        for shift in range(26):
            decrypted = Ciphers.rot(text, shift)
            # Score based on frequency analysis
            freq = Counter(c.lower() for c in decrypted if c.isalpha())
            total = sum(freq.values())
            if total > 0:
                score = sum(
                    abs(freq.get(c, 0) / total * 100 - english_freq.get(c, 0))
                    for c in english_freq
                )
                results.append((shift, decrypted, score))
        return sorted(results, key=lambda x: x[2])[:5]  # Top 5 likely
    
    @staticmethod
    def xor_single_byte(data: bytes) -> List[Tuple[int, bytes, float]]:
        """XOR brute force with single byte"""
        results = []
        for key in range(256):
            decrypted = bytes(b ^ key for b in data)
            # Score printable ratio
            printable = sum(1 for b in decrypted if 32 <= b < 127)
            score = printable / len(decrypted) if decrypted else 0
            results.append((key, decrypted, score))
        return sorted(results, key=lambda x: -x[2])[:10]
    
    @staticmethod
    def xor_with_key(data: bytes, key: bytes) -> bytes:
        """XOR with repeating key"""
        return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    
    @staticmethod
    def morse_encode(text: str) -> str:
        """Encode to Morse code"""
        result = []
        for char in text.upper():
            if char in Ciphers.MORSE_CODE:
                result.append(Ciphers.MORSE_CODE[char])
            elif char == ' ':
                result.append('/')
        return ' '.join(result)
    
    @staticmethod
    def morse_decode(morse: str) -> str:
        """Decode Morse code"""
        reverse_morse = {v: k for k, v in Ciphers.MORSE_CODE.items()}
        words = morse.split(' / ')
        result = []
        for word in words:
            chars = word.split()
            result.append(''.join(reverse_morse.get(c, '?') for c in chars))
        return ' '.join(result)
    
    @staticmethod
    def atbash(text: str) -> str:
        """Atbash cipher"""
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr(25 - (ord(char) - base) + base))
            else:
                result.append(char)
        return ''.join(result)


# =============================================================================
# HASHING
# =============================================================================

class Hashing:
    """Hash utilities"""
    
    HASH_PATTERNS = {
        'MD5': (32, r'^[a-f0-9]{32}$'),
        'SHA-1': (40, r'^[a-f0-9]{40}$'),
        'SHA-256': (64, r'^[a-f0-9]{64}$'),
        'SHA-512': (128, r'^[a-f0-9]{128}$'),
        'SHA-384': (96, r'^[a-f0-9]{96}$'),
        'MD4': (32, r'^[a-f0-9]{32}$'),
        'NTLM': (32, r'^[a-f0-9]{32}$'),
        'MySQL 4.1+': (40, r'^\*[A-F0-9]{40}$'),
        'bcrypt': (60, r'^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$'),
    }
    
    @staticmethod
    def identify(hash_str: str) -> List[str]:
        """Identify possible hash types"""
        hash_str = hash_str.strip().lower()
        possible = []
        
        # Check by length and pattern
        if len(hash_str) == 32:
            possible.extend(['MD5', 'MD4', 'NTLM'])
        elif len(hash_str) == 40:
            possible.extend(['SHA-1', 'MySQL 5.x'])
        elif len(hash_str) == 64:
            possible.extend(['SHA-256', 'SHA3-256'])
        elif len(hash_str) == 128:
            possible.extend(['SHA-512', 'SHA3-512', 'Whirlpool'])
        elif len(hash_str) == 96:
            possible.append('SHA-384')
        elif hash_str.startswith('$2'):
            possible.append('bcrypt')
        elif hash_str.startswith('$6$'):
            possible.append('SHA-512 crypt')
        elif hash_str.startswith('$5$'):
            possible.append('SHA-256 crypt')
        elif hash_str.startswith('$1$'):
            possible.append('MD5 crypt')
        
        return possible if possible else ['Unknown']
    
    @staticmethod
    def generate(algorithm: str, data: str) -> str:
        """Generate hash"""
        algo_map = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'sha384': hashlib.sha384,
        }
        if algorithm.lower() in algo_map:
            return algo_map[algorithm.lower()](data.encode()).hexdigest()
        return f"Unknown algorithm: {algorithm}"
    
    @staticmethod
    def crack_wordlist(hash_str: str, algorithm: str, wordlist: List[str]) -> Optional[str]:
        """Crack hash using wordlist"""
        algo_map = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
        }
        if algorithm.lower() not in algo_map:
            return None
        
        hash_func = algo_map[algorithm.lower()]
        hash_str = hash_str.lower()
        
        for word in wordlist:
            word = word.strip()
            if hash_func(word.encode()).hexdigest() == hash_str:
                return word
        return None


# =============================================================================
# FORENSICS
# =============================================================================

class Forensics:
    """Forensics utilities"""
    
    MAGIC_BYTES = {
        b'\x89PNG\r\n\x1a\n': 'PNG Image',
        b'\xff\xd8\xff': 'JPEG Image',
        b'GIF87a': 'GIF Image (87a)',
        b'GIF89a': 'GIF Image (89a)',
        b'%PDF': 'PDF Document',
        b'PK\x03\x04': 'ZIP Archive',
        b'Rar!\x1a\x07': 'RAR Archive',
        b'\x7fELF': 'ELF Executable',
        b'MZ': 'Windows Executable',
        b'\x1f\x8b': 'GZIP Compressed',
        b'BZh': 'BZIP2 Compressed',
        b'\xfd7zXZ\x00': 'XZ Compressed',
        b'RIFF': 'RIFF (WAV/AVI)',
        b'ID3': 'MP3 Audio',
        b'ftyp': 'MP4 Video (offset +4)',
        b'SQLite format 3': 'SQLite Database',
    }
    
    @staticmethod
    def identify_file(filepath: str) -> str:
        """Identify file type by magic bytes"""
        try:
            with open(filepath, 'rb') as f:
                header = f.read(32)
            
            for magic, filetype in Forensics.MAGIC_BYTES.items():
                if header.startswith(magic):
                    return filetype
            
            # Check for text
            try:
                header.decode('utf-8')
                return 'Text/ASCII file'
            except:
                pass
            
            return 'Unknown'
        except Exception as e:
            return f"Error: {e}"
    
    @staticmethod
    def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings"""
        strings = []
        current = []
        
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        return strings
    
    @staticmethod
    def lsb_extract(data: bytes) -> bytes:
        """Extract LSB from bytes"""
        bits = []
        for byte in data:
            bits.append(byte & 1)
        
        # Convert bits to bytes
        result = []
        for i in range(0, len(bits) - 7, 8):
            byte_val = sum(bits[i+j] << (7-j) for j in range(8))
            result.append(byte_val)
        
        return bytes(result)


# =============================================================================
# WEB
# =============================================================================

class Web:
    """Web security utilities"""
    
    @staticmethod
    def decode_jwt(token: str) -> dict:
        """Decode JWT token (without verification)"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {'error': 'Invalid JWT format'}
            
            def decode_part(part):
                # Add padding
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += '=' * padding
                return json.loads(base64.urlsafe_b64decode(part))
            
            header = decode_part(parts[0])
            payload = decode_part(parts[1])
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2]
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def sqli_payloads() -> List[str]:
        """Common SQL injection payloads"""
        return [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "'; DROP TABLE users--",
            "' AND '1'='1",
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "1 AND 1=1",
            "1 AND 1=2",
        ]
    
    @staticmethod
    def xss_payloads() -> List[str]:
        """Common XSS payloads"""
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<body onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '{{constructor.constructor("alert(1)")()}}',  # Angular
            '${alert(1)}',  # Template literals
        ]


# =============================================================================
# CLI
# =============================================================================

def interactive_mode():
    """Run interactive REPL"""
    print(BANNER)
    print("Type 'help' for commands, 'quit' to exit\n")
    
    encoder = Encoder()
    ciphers = Ciphers()
    hashing = Hashing()
    
    while True:
        try:
            cmd = input("\033[36mCTF>\033[0m ").strip()
            if not cmd:
                continue
            
            parts = cmd.split(maxsplit=2)
            command = parts[0].lower()
            
            if command in ('quit', 'exit', 'q'):
                print("Goodbye!")
                break
            
            elif command == 'help':
                print("""
Commands:
  encode <type> <text>    - Encode text (base64, hex, binary, url, html)
  decode <type> <text>    - Decode text
  rot <n> <text>          - ROT cipher with shift n
  rot13 <text>            - ROT13
  rot-brute <text>        - Try all rotations
  hash <algo> <text>      - Generate hash (md5, sha1, sha256)
  hash-id <hash>          - Identify hash type
  morse <text>            - Encode to Morse
  morse-decode <morse>    - Decode Morse
  xor <hex> <key>         - XOR with key
  jwt <token>             - Decode JWT
  sqli                    - Show SQLi payloads
  xss                     - Show XSS payloads
  quit                    - Exit
""")
            
            elif command == 'encode' and len(parts) >= 3:
                enc_type = parts[1].lower()
                text = parts[2]
                if enc_type == 'base64':
                    print(encoder.base64_encode(text))
                elif enc_type == 'hex':
                    print(encoder.hex_encode(text))
                elif enc_type == 'binary':
                    print(encoder.binary_encode(text))
                elif enc_type == 'url':
                    print(encoder.url_encode(text))
                elif enc_type == 'html':
                    print(encoder.html_encode(text))
                elif enc_type == 'ascii':
                    print(encoder.ascii_encode(text))
            
            elif command == 'decode' and len(parts) >= 3:
                dec_type = parts[1].lower()
                text = parts[2]
                if dec_type == 'base64':
                    print(encoder.base64_decode(text))
                elif dec_type == 'hex':
                    print(encoder.hex_decode(text))
                elif dec_type == 'binary':
                    print(encoder.binary_decode(text))
                elif dec_type == 'url':
                    print(encoder.url_decode(text))
                elif dec_type == 'html':
                    print(encoder.html_decode(text))
                elif dec_type == 'ascii':
                    print(encoder.ascii_decode(text))
            
            elif command == 'rot' and len(parts) >= 3:
                try:
                    n = int(parts[1])
                    text = parts[2]
                    print(ciphers.rot(text, n))
                except ValueError:
                    print("Invalid rotation number")
            
            elif command == 'rot13' and len(parts) >= 2:
                print(ciphers.rot(parts[1], 13))
            
            elif command == 'rot-brute' and len(parts) >= 2:
                for i, result in ciphers.rot_brute(parts[1]):
                    print(f"ROT{i:2d}: {result}")
            
            elif command == 'hash' and len(parts) >= 3:
                print(hashing.generate(parts[1], parts[2]))
            
            elif command == 'hash-id' and len(parts) >= 2:
                types = hashing.identify(parts[1])
                print(f"Possible hash types: {', '.join(types)}")
            
            elif command == 'morse' and len(parts) >= 2:
                print(ciphers.morse_encode(parts[1]))
            
            elif command == 'morse-decode' and len(parts) >= 2:
                print(ciphers.morse_decode(parts[1]))
            
            elif command == 'jwt' and len(parts) >= 2:
                result = Web.decode_jwt(parts[1])
                print(json.dumps(result, indent=2))
            
            elif command == 'sqli':
                print("\nSQLi Payloads:")
                for p in Web.sqli_payloads():
                    print(f"  {p}")
            
            elif command == 'xss':
                print("\nXSS Payloads:")
                for p in Web.xss_payloads():
                    print(f"  {p}")
            
            else:
                print("Unknown command. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description='NullSec CTF Toolkit')
    parser.add_argument('command', nargs='?', help='Command to run')
    parser.add_argument('args', nargs='*', help='Command arguments')
    
    args = parser.parse_args()
    
    if not args.command:
        interactive_mode()
    else:
        # CLI mode - handle single commands
        encoder = Encoder()
        ciphers = Ciphers()
        hashing = Hashing()
        
        if args.command == 'decode' and len(args.args) >= 2:
            dec_type, text = args.args[0], args.args[1]
            if dec_type == 'base64':
                print(encoder.base64_decode(text))
            elif dec_type == 'hex':
                print(encoder.hex_decode(text))
        elif args.command == 'encode' and len(args.args) >= 2:
            enc_type, text = args.args[0], args.args[1]
            if enc_type == 'base64':
                print(encoder.base64_encode(text))
            elif enc_type == 'hex':
                print(encoder.hex_encode(text))
        elif args.command == 'hash-id' and args.args:
            print(', '.join(hashing.identify(args.args[0])))
        elif args.command == 'rot13' and args.args:
            print(ciphers.rot(' '.join(args.args), 13))
        else:
            interactive_mode()


if __name__ == '__main__':
    main()
