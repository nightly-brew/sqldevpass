#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of sqldeveloperpassworddecryptor.
#
# Copyright (C) 2015, 2020 Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# sqldeveloperpassworddecryptor is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# sqldeveloperpassworddecryptor is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with sqldeveloperpassworddecryptor.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import sys
import base64
import array
import hashlib

# Script version
VERSION = '2.2'

# OptionParser imports
from optparse import OptionParser
from optparse import OptionGroup

# Options definition
parser = OptionParser(usage="%prog [options]\nVersion: " + VERSION)

main_grp = OptionGroup(parser, 'Main parameters')
main_grp.add_option('-p', '--encrypted-password', help = '(mandatory): password that you want to decrypt. Ex. -p 054D4844D8549C0DB78EE1A98FE4E085B8A484D20A81F7DCF8', nargs = 1)
main_grp.add_option('-d', '--db-system-id-value', help = '(mandatory from v4): installation-unique value of "db.system.id" attribute in the "product-preferences.xml" file, or the export file encryption key. Ex: -d 6b2f64b2-e83e-49a5-9abf-cb2cd7e3a9ee', nargs = 1)
main_grp.add_option('-o', '--old', help = '(mandatory between v4 and v19.1) if the password you want to decrypt is for a product version between 4 and 19.1', action = 'store_true', default = False)
main_grp.add_option('-a', '--aged', help = '(mandatory between v19.2 and v22.2) if the password you want to decrypt is for a product version between 19.2 and 22.2', action = 'store_true', default = False)

parser.option_groups.extend([main_grp])

# Handful functions
def aes_cbc_encrypt(unencrypted_password, encryption_key):
    iv = get_random_bytes(16)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(unencrypted_password.encode('utf-8'), AES.block_size))

    return iv, ciphertext

def aes_gcm_encrypt(unencrypted_password, encryption_key, aad):
    nonce = get_random_bytes(12)
    cipher = AES.new(encryption_key, AES.MODE_GCM, nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(unencrypted_password.encode('utf-8'))

    return cipher, ciphertext, tag

def des_cbc_encrypt(unencrypted_password, encryption_key, iv):
    cipher = DES.new(encryption_key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(unencrypted_password.encode('utf-8'), DES.block_size))
    
    return ciphertext

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

def encrypt_v3(unencrypted, parser):
    iv = bytearray("\x00" * 8, 'ascii')
    secret_key = get_random_bytes(8)

    encrypted_pass = des_cbc_encrypt(unencrypted, secret_key, iv)
    
    #     05KKKKKKKKEEEEEEEEEEEEEEEEEEEE
    #     secret_key = encrypted[1:9]        (K)
    #     encrypted_password = encrypted[9:] (E)
    
    encrypted = bytearray("\x05", 'ascii') + secret_key + encrypted_pass
    encoded = bytes(encrypted).hex()
    
    return encoded

def encrypt_v19_2(unencrypted, db_system_id, parser):
    salt = array.array('b', [6, -74, 97, 35, 61, 104, 50, -72])
    key = hashlib.pbkdf2_hmac("sha256", db_system_id.encode(), salt, 5000, 32)

    iv, ciphertext = aes_cbc_encrypt(unencrypted, key)

    #    IIIIIIIIIIIIIIIIEEEEEEEEEEEEEEEE
    #    iv = encrypted_password[:16] (I)
    #    encrypted_password = encrypted_password[16:] (E)
    
    encrypted_password = iv + ciphertext
    encoded_password = base64.b64encode(encrypted_password)

    return encoded_password.decode('utf-8')

def encrypt_v23_1(unencrypted, db_system_id, parser):
    aad = "password".encode()

    salt = array.array('b', [6, -74, 97, 35, 61, 104, 50, -72])
    key = hashlib.pbkdf2_hmac("sha256", db_system_id.encode(), salt, 5000, 32)

    cipher, ciphertext, tag = aes_gcm_encrypt(unencrypted, key, aad)

    #     NNNNNNNNNNNEEEEEEEEEEETTTTTTTTTTTTTTTT
    #     nonce = encrypted_password[:12]                 (N)
    #     tag = encrypted_password[-16:]                  (T)
    #     encrypted_password = encrypted_password[12:-16] (E)

    encrypted_password = cipher.nonce + ciphertext + tag
    encoded_password = base64.b64encode(encrypted_password)

    return encoded_password.decode('utf-8')

def main():
    """
        Dat main
    """
    
    options, arguments = parser.parse_args()
    
    if not(options.encrypted_password):
        parser.error("Please specify a password to decrypt")
    
    print('sqldeveloperpassworddecryptor.py version %s\n' % VERSION)
    print("[+] unencrypted password: %s" % options.encrypted_password)
    
    if options.db_system_id_value:
        print("[+] db.system.id value: %s" % options.db_system_id_value)
        
        # v4->v19.1 decryption
        if options.old:
            print("\n[+] encrypted password: %s" % encrypt_v4(options.encrypted_password, options.db_system_id_value))
        
        elif options.aged:
        # v19.2->v22.2 decryption
            print("\n[+] encrypted password: %s" % encrypt_v19_2(options.encrypted_password, options.db_system_id_value, parser))
    
        else:
        # from v23.1 decryption
            print("\n[+] encrypted password: %s" % encrypt_v23_1(options.encrypted_password, options.db_system_id_value, parser))

    else:
        #v3 decryption
        print("\n[+] encrypted password: %s" % encrypt_v3(options.encrypted_password, parser))
    
    return None
    
if __name__ == "__main__" :
    main()