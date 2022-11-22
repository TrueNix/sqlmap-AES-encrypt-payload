#!/usr/bin/env python
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
from hashlib import md5
import argparse
import sys


BLOCK_SIZE = 16

def pad(data):
    length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data.encode() + (chr(length)*length).encode()

def unpad(data):
    return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))]

def bytes_to_key(data, salt, output=48):
    # extended from https://gist.github.com/gsakkis/4546068
    assert len(salt) == 8, len(salt)
    #print("data ", data)
    print("salt ", salt)
    data = data.encode()
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]
'''
def encrypt(message, passphrase):
    print(passphrase)
    passphrase = base64.b64decode(passphrase)
    assert passphrase[0:8] == b"Salted__"
    #salt = passphrase[8:16]
    salt = get_random_bytes(8)
    print(salt)
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    #final = base64.b64encode(salt + aes.encrypt(pad(message)))
    #final = final.encode()
    return base64.b64encode(salt + aes.encrypt(pad(message)))
'''
def encrypt(message, passphrase):
    salt = get_random_bytes(8)
    #salt = b'\x89>\x9b\x87\xea@fl'
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    #final = base64.b64encode(b"Salted__" + salt + aes.encrypt(pad(message)))
    #final = final.decode()
    return base64.b64encode(b"Salted__" + salt + aes.encrypt(pad(message)))

def decrypt(encrypted, passphrase):
    encrypted = base64.b64decode(encrypted)
    assert encrypted[0:8] == b"Salted__"
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]))
#password = "U2FsdGVkX1+JPpuH6kBmbEAxOGa5N6AuyCHF4LHhcSA=".encode()


#print(encrypt(payload,passphrase))

    # Fix Error object C in sqlmap .decode('utf-8')
#password = "some password".encode()
#U2FsdGVkX1+JPpuH6kBmbEAxOGa5N6AuyCHF4LHhcSA=

#ct_b64 = "U2FsdGVkX18TEX3Pw+l66dmiUIQedArwR435UDroikGr0hL791ZQkeG4gEd+ff/ZfL28Ai70PY7SVKpSygQyEfqGLZ8uUb8twSgC9zea7iw="

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="file")
parser.add_argument("-k", "--key", help="key")
parser.add_argument("-c", "--cipher", help="cipher")
args = parser.parse_args()
#print(args)   # for debugging help
#password = args.key
ct_b64 = args.cipher
password = "U2FsdGVkX1+JPpuH6kBmbEAxOGa5N6AuyCHF4LHhcSA="
print(args.key)
if not args.file:
    pt = decrypt(args.cipher, args.key)
else:
    with open(args.file, "r") as myfile:
       f = myfile.read()
       pt = decrypt(f, args.key)
    #pt = decrypt(args.cipher, args.key)
#pt = decrypt(args.cipher, password)
#pt = encrypt(args.cipher, args.key)
print("fuck-encryption", pt)

#print("pt", decrypt(encrypt(pt, password), password))

#https://stackoverflow.com/questions/36762098/how-to-decrypt-password-from-javascript-cryptojs-aes-encryptpassword-passphras/36780727#36780727

