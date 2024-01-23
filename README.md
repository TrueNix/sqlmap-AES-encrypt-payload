# sqlmap-AES-encrypt-payload


## Usage

1. **Find the AES Key:**
   - Explore the source code to locate the AES encryption key.
   
2. **Configure the Script:**
   - Open the `aes-encrypt-payload.py` script and paste the discovered AES key.
   - Save the script with the key.

3. **Run sqlmap:**
   - Execute sqlmap with the tamper script and other desired options.
   - Example command:
     ```bash
     sqlmap -l post.txt --tamper=aes-encrypt-payload.py --risk=3 --level=5 --dbs
     ```
   - Adjust the command parameters according to your testing needs.

4. **Troubleshooting Tip:**
   - If you cannot find the encryption key, use a debugger to locate the encryption function in the source code.
   - Set breakpoints in the debugger to inspect key generation.

## Demo

Watch a demonstration of the script in action on YouTube:
[Watch Demo](https://youtu.be/cKLPvr2mi6c)

## Decryptor Tool

Use the standalone `decryptor.py` tool for decrypting data independently. The tool accepts the following flags (note: error handling is missing):

- `-f FILE, --file FILE`: Specify the file containing the encrypted data.
- `-k KEY, --key KEY`: Provide the encryption key.
- `-c CIPHER, --cipher CIPHER`: Specify the encryption cipher used.

## Disclaimer

This script and decryptor tool are provided for educational and testing purposes only. Ensure responsible and legal use in compliance with applicable laws and ethical guidelines. The author and contributors are not responsible for any misuse or unauthorized access to systems.


