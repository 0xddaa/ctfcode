"""
fetch the shellcode found an object file compiled by nasm
"""

import sys
import binascii

shellcode = open("asm.o","rb").read()[272:]

shellcode = shellcode[:shellcode.find("\x31\xdb\xb0\x01\xcd\x80") + 6]

print "len:"+ str(len(shellcode))
sys.stdout.write(binascii.hexlify(shellcode))
print
