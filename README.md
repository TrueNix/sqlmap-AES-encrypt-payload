# sqlmap-AES-encrypt-payload



Usage:
find aes key by exploring source code

open the aes-encrypt-payload.py script and paste the key and save it.

$ sqlmap -l post.txt --tamper=aes-encrypt-payload.py --risk=3 --level=5 --dbs


TIP! if you cannot find the key open debugger and locate the encryption function put brake point on it.



Demo:
https://youtu.be/cKLPvr2mi6c
