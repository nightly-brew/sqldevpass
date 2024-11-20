#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64
import array
import hashlib

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

###   AES CBC   ###
def aes_cbc_encrypt(unencrypted_password, encryption_key, iv):
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(unencrypted_password.encode('utf-8'), AES.block_size))

    return ciphertext

def aes_cbc_decrypt(encrypted_password, decryption_key, iv):
    crypter = AES.new(decryption_key, AES.MODE_CBC, iv)
    decrypted_password = unpad(crypter.decrypt(encrypted_password))
    
    return decrypted_password.decode('utf-8')

###   AES GCM   ###
def aes_gcm_encrypt(unencrypted_password, encryption_key, nonce, aad):
    cipher = AES.new(encryption_key, AES.MODE_GCM, nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(unencrypted_password.encode('utf-8'))

    return cipher, ciphertext, tag

def aes_gcm_decrypt(encrypted_password, decryption_key, nonce, aad, tag):
    crypter = AES.new(decryption_key, AES.MODE_GCM, nonce)
    crypter.update(aad)
    decrypted_password = crypter.decrypt_and_verify(encrypted_password, tag)

    return decrypted_password.decode('utf-8')

###   DES CBC   ###
def des_cbc_encrypt(unencrypted_password, encryption_key, iv):
    cipher = DES.new(encryption_key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(unencrypted_password.encode('utf-8'), DES.block_size))
    
    return ciphertext

def des_cbc_decrypt(encrypted_password, decryption_key, iv):
    crypter = DES.new(decryption_key, DES.MODE_CBC, iv)
    decrypted_password = unpad(crypter.decrypt(encrypted_password))
    
    return decrypted_password.decode('utf-8')

###########################

###   ALGO1   ###
def encrypt_v3(unencrypted):
    iv = bytearray("\x00" * 8, 'ascii')
    secret_key = get_random_bytes(8)

    encrypted_pass = des_cbc_encrypt(unencrypted, secret_key, iv)
    
    # [ 05KKKKKKKKEEEEEEEEEEEEEEEEEEEE ]
    encrypted = bytearray("\x05", 'ascii') + secret_key + encrypted_pass
    encoded = bytes(encrypted).hex()
    
    return encoded

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

###   ALGO2   ###
def encrypt_v4(unencrypted, db_system_id):
    salt = bytearray.fromhex('051399429372e8ad')
    num_iteration = 42

    # key generation from an installation-unique value with a fixed salt
    key = bytearray(db_system_id, 'ascii') + salt
    for i in range(num_iteration):
        m = hashlib.md5(key)
        key = m.digest()

    secret_key = key[:8]
    iv = key[8:]

    encrypted_password = des_cbc_encrypt(unencrypted, secret_key, iv)
    encoded_password = base64.b64encode(encrypted_password)

    return encoded_password.decode('utf-8')

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
    
    try:
        decrypted = des_cbc_decrypt(encrypted_password, secret_key, iv)
    except:
        print('Error during decryption')
        exit(1)
    
    return decrypted 

###   ALGO3   ###
def encrypt_v19_2(unencrypted, db_system_id):
    iv = get_random_bytes(16)
    salt = array.array('b', [6, -74, 97, 35, 61, 104, 50, -72])
    key = hashlib.pbkdf2_hmac("sha256", db_system_id.encode(), salt, 5000, 32)

    ciphertext = aes_cbc_encrypt(unencrypted, key, iv)

    # [ IIIIIIIIIIIIIIIIEEEEEEEEEEEEEEEE ]
    encrypted_password = iv + ciphertext
    encoded_password = base64.b64encode(encrypted_password)

    return encoded_password.decode('utf-8')

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

###   ALGO4   ###
def encrypt_v23_1(unencrypted, db_system_id):
    nonce = get_random_bytes(12)
    salt = array.array('b', [6, -74, 97, 35, 61, 104, 50, -72])
    key = hashlib.pbkdf2_hmac("sha256", db_system_id.encode(), salt, 5000, 32)

    cipher, ciphertext, tag = aes_gcm_encrypt(unencrypted, key, nonce, "password".encode())

    # [ NNNNNNNNNNNEEEEEEEEEEETTTTTTTTTTTTTTTT ]
    encrypted_password = cipher.nonce + ciphertext + tag
    encoded_password = base64.b64encode(encrypted_password)

    return encoded_password.decode('utf-8')

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