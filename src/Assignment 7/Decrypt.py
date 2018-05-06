#!/usr/bin/python
# Python Chacha20 Decrypter
# Author: ID: SLAE64 - 1525
#
# Usage: python Decrypt.py

from Crypto.Cipher import ChaCha20
import base64


def decrypt():
    encoded_shellcode = base64.b64decode("F4KWN/2CwTuRIBALnZxp1uLp6ZqnJaLPqjb6dZFC3H+jPmiUYiA=") # Encoded Execve-stack shellcode
    secret = b'G-KaPdSgVkYp3s6v9y$B&E)H@MbQeThW'
    msg_nonce = encoded_shellcode[:8]
    ciphertext = encoded_shellcode[8:]
    cipher = ChaCha20.new(key=secret, nonce=msg_nonce)
    return cipher.decrypt(ciphertext)


if __name__ == "__main__":
    shellcode = decrypt()
    encoded = ''
    for x in bytearray(shellcode):
        encoded += '\\x%02x' % x
    print encoded