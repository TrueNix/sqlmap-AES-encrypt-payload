#!/usr/bin/env python3
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
from hashlib import md5
import argparse
from lib.core.enums import PRIORITY
from lib.core.settings import UNICODE_ENCODING
import logging
from colorama import init, Fore, Style
init()

priority = PRIORITY.NORMAL
password = "do_not_break_my_encryption_please" # AES key
def dependencies():
    pass


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

def encrypt(message, passphrase):
    salt = get_random_bytes(8)
    #salt = b'\x89>\x9b\x87\xea@fl'
    #print("Payload: ", message)
    print(Fore.GREEN + Style.BRIGHT + "Payload: ", message)
    key_iv = bytes_to_key(passphrase, salt, 32+16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
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

def tamper(payload, **kwargs):
    return encrypt(payload, password).decode('utf-8')


'''
import base64
import urllib

def tamper(payload, **kwargs):
    params = 'name1=value1%s&name2=value2' % payload

    data = urllib.quote_plus(params)
    data = base64.b64encode(data)

    return data
'''


