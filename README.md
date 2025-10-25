# aes-extract

Restore and brute-force pyAesCrypt `.aes` files to their original filenames  
`file.zip.aes → file.zip`, `file.tar.gz.aes → file.tar.gz`

---

## Features
- Decrypt a single `.aes` file with a known password.
- Brute-force `.aes` files using a local wordlist (supports parallel workers).
- Process a directory recursively to find and attempt to decrypt `*.aes` files.
- Writes attempts to temporary files and only moves output on success (safe).
- Simple CLI and minimal dependencies (`pyAesCrypt`).

---

## Quickstart

### Requirements
- Python 3.8+
- `pyAesCrypt` — install via pip:
```bash
pip install pyAesCrypt
```
Install (clone)
git clone https://github.com/<your-username>/aes-extract.git
cd aes-extract

### Usage examples

### Decrypt with a known password:
```
python3 aes_extract.py -e /path/to/file.zip.aes -p "correcthorsebatterystaple"
```

### Brute-force using a wordlist (parallel):
```
python3 aes_extract.py -e /path/to/file.zip.aes -w /usr/share/wordlists/rockyou.txt -P 6
```

### Scan a directory (recursive) and attempt to brute-force each .aes:
```
python3 aes_extract.py -d ./encrypted_files -w rockyou.txt -P 4 -o ./decrypted_outputs
```

### Force overwrite existing outputs:
```
python3 aes_extract.py -e file.tar.gz.aes -w wordlist.txt --force
```
### CLI help
```
python3 aes_extract.py -h
```
### Contributing

Contributions welcome! See CONTRIBUTING.md for how to open issues and PRs. Please include tests for critical changes.

### License

 MIT License — see LICENSE file.
 Use this tool in CTF environments, lab machines, or with explicit consent.
