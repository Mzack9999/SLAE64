echo '[+] Assembling with Nasm ... ' # Nasm shell source: file.nasm
nasm -f elf64 -o $1.o $1.nasm
echo '[+] Done!'

echo '[+] Linking ...'
ld -z execstack -o $1 $1.o
echo '[+] Done!'

# Remove object file
rm -rf $1.o

echo '[+] Dumping Shellcode ...'
objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-8 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\x/g'|paste -d '' -s |sed 's/^/"/' | sed 's/$/"/g'
echo '[+] Done!'

# Remove executable
rm -rf $1