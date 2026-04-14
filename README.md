# sqlmap AES Tamper Script

A sqlmap tamper script that encrypts SQL injection payloads with AES-256-CBC
**and decrypts server responses**, enabling sqlmap to test applications that
encrypt all request/response traffic client-side.

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

   - **CLI flag**: pass `--key` directly when using the standalone CLI.

2. **Run sqlmap** — the tamper handles both encryption and decryption:
   ```bash
   sqlmap -u "http://target/vuln" --data="q=1" \
     --tamper=aes_tamper.py --level=5 --risk=3 --tables
   ```

## Usage

### As a sqlmap tamper

```bash
sqlmap -u "http://target/vuln" --data="q=1" \
  --tamper=aes_tamper.py --level=5 --risk=3 --dbs
```

The tamper:
1. **Encrypts** every outgoing payload with AES-256-CBC before sqlmap sends it
2. **Decrypts** every server response so sqlmap can compare responses and detect injections

This means no separate decrypt proxy is needed — the tamper is self-contained.

### As a standalone CLI

```bash
# Encrypt
python aes_tamper.py encrypt --key "mysecret" "' OR 1=1--"

# Decrypt
python aes_tamper.py decrypt --key "mysecret" "U2FsdGVkX1+..."
```

## How It Works

### Encryption (outbound)

sqlmap generates a payload → tamper encrypts it with AES-256-CBC → encrypted base64 payload is sent to the target.

### Decryption (inbound)

The tamper monkey-patches sqlmap's `lib.request.connect.connect` function to intercept all HTTP responses. When a JSON response contains `data` or `error` fields, the tamper decrypts them and returns the plaintext to sqlmap. This allows sqlmap's response comparison engine to work normally.

```
sqlmap core
  ├── sends payload → tamper.encrypt() → target
  └── receives response ← tamper.decrypt() ← target
```

### Encryption format

OpenSSL-compatible `Salted__` format (CryptoJS compatible):
- **Key derivation**: EVP_BytesToKey with MD5 (32-byte key + 16-byte IV)
- **Mode**: AES-256-CBC with PKCS#7 padding
- **Output**: `base64("Salted__" + 8-byte salt + ciphertext)`

## Finding the key

You need the same AES key the application uses for client-side encryption:

- **Source code review**: search the JS/frontend code for the encryption key
- **Debugger**: set breakpoints on the encryption function to inspect the key at runtime
- **Network analysis**: if the key is transmitted during session setup
- **Page source**: look for HTML comments or inline scripts containing the key

## Disclaimer

This tool is provided for educational and authorized security testing purposes
only. Ensure you have explicit permission to test the target systems. Use in
compliance with all applicable laws and ethical guidelines. The author is not
responsible for any misuse.
