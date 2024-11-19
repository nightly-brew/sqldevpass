#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sqldev_pass_algo as algo

# Options definition
parser = argparse.ArgumentParser(
    prog = 'sqldev_pass',
    description = 'Encrypt/Decrypt sql developer and plsql developer connection passwords')

parser.add_argument('-m', '--mode', help = 'Operation mode', choices = ['enc', 'dec'], type=str, required = True)
parser.add_argument('-p', '--password', help = 'Password string to encrypt/decrypt', nargs = 1, type=str, required = True)
parser.add_argument('-k', '--key', help = '(mandatory from algo 2 and up): Encryption key. Use either "db.system.id" attribute from "product-preferences.xml" if reading from SQL Developer folder, or the export password if reading and exported file', nargs = 1)
parser.add_argument('-a', '--algo', help = 
'''
(mandatory) Encryption algorythm version:\n
  - 1 for product version up to 3,\n
  - 2 for product version between 4 an d 19.1,\n
  - 3 for product version between 19.2 and 22.2,\n
  - 4 for product version 23 and up
''',
type=str,
choices = ['1', '2', '3', '4'],
required = True)

def main():
    args = parser.parse_args()

    print(" >>> mode: %s" % args.mode)
    print(" >>> algo: %s" % args.algo)
    print(" >>> encryption key: %s" % args.key[0])
    print(" >>> password: %s" % args.password[0])

    if args.algo == '1':
        if args.mode == 'enc':
            print("\n [+] encrypted password: %s" % algo.encrypt_v3(args.password[0]))
        else:
            print("\n [+] decrypted password: %s" % algo.decrypt_v3(args.password[0]))

    elif args.algo == '2':
        if args.mode == 'enc':
            print("\n [+] encrypted password: %s" % algo.encrypt_v4(args.password[0], args.key[0]))
        else:
            print("\n [+] decrypted password: %s" % algo.decrypt_v4(args.password[0], args.key[0]))

    elif args.algo == '3':
        if args.mode == 'enc':
            print("\n [+] encrypted password: %s" % algo.encrypt_v19_2(args.password[0], args.key[0]))
        else:
            print("\n [+] decrypted password: %s" % algo.decrypt_v19_2(args.password[0], args.key[0]))

    elif args.algo == '4':
        if args.mode == 'enc':
            print("\n [+] encrypted password: %s" % algo.encrypt_v23_1(args.password[0], args.key[0]))
        else:
            print("\n [+] decrypted password: %s" % algo.decrypt_v23_1(args.password[0], args.key[0]))        

    exit(0)
    
if __name__ == "__main__" :
    main()