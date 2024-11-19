#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import DES, AES
import base64
import array
import hashlib

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def aes_cbc_decrypt(encrypted_password, decryption_key, iv):
    crypter = AES.new(decryption_key, AES.MODE_CBC, iv)
    decrypted_password = unpad(crypter.decrypt(encrypted_password))
    
    return decrypted_password.decode('utf-8')

def aes_gcm_decrypt(encrypted_password, decryption_key, nonce, aad, tag):
    crypter = AES.new(decryption_key, AES.MODE_GCM, nonce)
    crypter.update(aad)
    decrypted_password = crypter.decrypt_and_verify(encrypted_password, tag)

    return decrypted_password.decode('utf-8')
    
def des_cbc_decrypt(encrypted_password, decryption_key, iv):
    crypter = DES.new(decryption_key, DES.MODE_CBC, iv)
    decrypted_password = unpad(crypter.decrypt(encrypted_password))
    
    return decrypted_password.decode('utf-8')

def decrypt_v4(encrypted, db_system_id):
    encrypted_password = base64.b64decode(encrypted)
    
    salt = bytearray.fromhex('051399429372e8ad')
    num_iteration = 42
            
    # key generation from an installation-unique value with a fixed salt
    key = bytearray(db_system_id, 'ascii') + salt
    for i in range(num_iteration):
        m = hashlib.md5(key)
        key = m.digest()
    
    secret_key = key[:8]
    iv = key[8:]
    
    decrypted = des_cbc_decrypt(encrypted_password, secret_key, iv)
    
    return decrypted 

def decrypt_v3(encrypted):
    if len(encrypted) % 2 != 0:
        print('Encrypted password length is not even (%s), aborting...' % len(encrypted))
        exit(1)
    
    if not(encrypted.startswith("05")):
        print('Encrypted password string not beginning with "05", aborting...')
        exit(1)
    
    encrypted = bytearray.fromhex(encrypted)
    secret_key = encrypted[1:9]
    encrypted_password = encrypted[9:]
    iv = bytearray("\x00" * 8, 'ascii')
    
    decrypted = des_cbc_decrypt(encrypted_password, secret_key, iv)
    
    return decrypted 

def decrypt_v19_2(encrypted, db_system_id):
    encrypted_password = base64.b64decode(encrypted)
    
    salt = array.array('b', [6, -74, 97, 35, 61, 104, 50, -72])
    key = hashlib.pbkdf2_hmac("sha256", db_system_id.encode(), salt, 5000, 32)

    iv = encrypted_password[:16]
    encrypted_password = encrypted_password[16:]
    
    try:
        decrypted = aes_cbc_decrypt(encrypted_password, key, iv)
    except:
        print('Error during decryption')
        exit(1)
    
    return decrypted

def decrypt_v23_1(encrypted, db_system_id):
    encrypted_password = base64.b64decode(encrypted)

    salt = array.array('b', [6, -74, 97, 35, 61, 104, 50, -72])
    key = hashlib.pbkdf2_hmac("sha256", db_system_id.encode(), salt, 5000, 32)

    nonce = encrypted_password[:12]
    tag = encrypted_password[-16:]
    encrypted_password = encrypted_password[12:-16]

    try:
        decrypted = aes_gcm_decrypt(encrypted_password, key, nonce, "password".encode(), tag)
    except:
        print('Error during decryption')
        exit(1)

    return decrypted