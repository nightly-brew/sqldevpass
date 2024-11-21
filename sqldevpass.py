#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import sys
import contextlib

import sqldevpass_algo as algo

parser = argparse.ArgumentParser(
    prog = 'sqldevpass',
    description = 'Encrypt/Decrypt sql developer and plsql developer connection passwords')

parser.add_argument('-e', '--encrypt', help = 'Switch from decryption to encryption', action = 'store_true')
parser.add_argument('-p', '--password', help = 'Password string to encrypt/decrypt', nargs = 1, type=str)
parser.add_argument('-f', '--file', help = 'Path to connections file to encrypt/decrypt', nargs = 1, type=str)
parser.add_argument('-k', '--key', help = '(mandatory from algo 4 and up): Encryption key. Use either "db.system.id" attribute from "product-preferences.xml" if reading from SQL Developer folder, or the export password if reading and exported file', nargs = 1)
parser.add_argument('-a', '--algo', help = 
'''
Encryption algorythm version:\n
  - 3 for product version up to 3,\n
  - 4 for product version between 4 an d 19.1,\n
  - 19_2 for product version between 19.2 and 22.2,\n
  - 23_1 for product version 23 and up
''',
type=str,
choices = ['3', '4', '19_2', '23_1'],
required = True)
parser.add_argument('-o', '--output', help = 'Output destination file. If not specified, prints to stdout', nargs = 1, type=str)

def handle_pass(args, password):
    if args.algo == '3':
        if args.encrypt:
            return algo.encrypt_v3(password)
        else:
            return algo.decrypt_v3(password)

    elif args.algo == '4':
        if args.encrypt:
            return algo.encrypt_v4(password, args.key[0])
        else:
            return algo.decrypt_v4(password, args.key[0])

    elif args.algo == '19_2':
        if args.encrypt:
            return algo.encrypt_v19_2(password, args.key[0])
        else:
            return algo.decrypt_v19_2(password, args.key[0])

    elif args.algo == '23_1':
        if args.encrypt:
            return algo.encrypt_v23_1(password, args.key[0])
        else:
            return algo.decrypt_v23_1(password, args.key[0])

@contextlib.contextmanager
def noop():
    yield None

def main():
    args = parser.parse_args()

    if bool(args.password) == bool(args.file):
        print('Either -p/--password OR -f/--file must be specified')
        exit(1)
    
    if args.algo != '3' and (args.key is None or len(args.key) == 0):
        print('Missing encryption key, mandatory from algo 2 and up')
        exit(1)

    
    try:
        with open(args.file[0], 'r') if bool(args.file) else noop() as file, \
            open(args.output[0], 'w') if bool(args.output) else sys.stdout as output_dest:

            if file is None:
                print(handle_pass(args, args.password[0]), file = output_dest)
            else:
                data = json.load(file)

                for i in range(len(data['connections'])):
                    data['connections'][i]['info']['password'] = handle_pass(args, data['connections'][i]['info']['password'])

                print(json.dumps(data), file = output_dest)
    except (FileNotFoundError, IsADirectoryError) as e:
        print(e)
        exit(1)

    exit(0)

if __name__ == "__main__":
    main()