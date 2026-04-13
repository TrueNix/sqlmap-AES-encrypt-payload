# sqlmap AES Tamper Script

A sqlmap tamper script that encrypts SQL injection payloads with AES-256-CBC
before they are sent to the target. This enables testing applications that
encrypt request parameters client-side.

Also includes a standalone CLI for encrypting/decrypting payloads independently.

## Requirements

- Python 3.8+
- [pycryptodome](https://pypi.org/project/pycryptodome/)

```bash
pip install pycryptodome
```

## Setup

1. **Configure the AES key** — choose one method:

   - **Environment variable** (recommended for tamper mode):
     ```bash
     export SQLMAP_AES_KEY="your-secret-passphrase"
     ```

   - **Sidecar file**: copy the example and edit it:
     ```bash
     cp .aes-key.example .aes-key
     # edit .aes-key with your passphrase
     ```

   - **CLI flag**: pass `--key` directly when using the standalone CLI (see below).

2. **Place the script** where sqlmap can find it:
   ```bash
   # sqlmap automatically discovers scripts in its tamper directory,
   # or you can pass an absolute path:
   sqlmap -u "http://target/vuln?id=1" --tamper=/path/to/aes_tamper.py
   ```

## Usage

### As a sqlmap tamper

```bash
sqlmap -l post.txt --tamper=aes_tamper.py --risk=3 --level=5 --dbs
```

The tamper reads the key from `SQLMAP_AES_KEY` or `.aes-key` on first load
and caches it for subsequent payloads.

### As a standalone CLI tool

```bash
# Encrypt
python aes_tamper.py encrypt --key "mysecret" "' OR 1=1--"

# Decrypt (use the base64 output from encrypt)
python aes_tamper.py decrypt --key "mysecret" "U2FsdGVkX1+..."

# Read from file
python aes_tamper.py encrypt --key "mysecret" "$(cat payload.txt)"
```

## How it works

1. sqlmap generates a SQLi payload (e.g. `' OR 1=1--`)
2. The tamper encrypts it with AES-256-CBC using your key
3. The encrypted, base64-encoded payload is sent to the target
4. The target decrypts it server-side and passes it to the database

**Encryption format**: OpenSSL-compatible `Salted__` format (CryptoJS compatible).
- Key derivation: EVP_BytesToKey with MD5 (32-byte key + 16-byte IV)
- Mode: AES-256-CBC with PKCS#7 padding
- Output: `base64("Salted__" + 8-byte salt + ciphertext)`

## Finding the key

You need the same AES key the application uses for client-side encryption:

- **Source code review**: search the JS/frontend code for the encryption key
- **Debugger**: set breakpoints on the encryption function to inspect the key at runtime
- **Network analysis**: if the key is transmitted during session setup

## Disclaimer

This tool is provided for educational and authorized security testing purposes
only. Ensure you have explicit permission to test the target systems. Use in
compliance with all applicable laws and ethical guidelines. The author is not
responsible for any misuse.
