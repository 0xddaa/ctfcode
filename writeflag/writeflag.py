#!/usr/bin/python2

import sys
import binascii
import os


def main(path, flag, debug):
    with open("template.asm","r") as fp:
        template = fp.read()

    l = hex(len(flag))

    if len(flag) > 0xff:
        asm = template % (l, "dx", l, flag, path)
    else:
        asm = template % (l, "dl", l, flag, path)
    with open("tmp.asm","w") as fp:
        fp.write(asm)


    os.system("nasm -f elf32 tmp.asm -o asm.o && ld asm.o -m elf_i386 -o elf")

    with open("asm.o", "rb") as fp:
        shellcode = fp.read()[272:]
    
    shellcode = shellcode[:shellcode.find("\x90\x90\x90\x90")]

    print "len:"+ str(len(shellcode))
    sys.stdout.write(binascii.hexlify(shellcode) + "\n")

    if not debug:
        os.system("rm tmp.asm asm.o elf")


if len(sys.argv) < 3:
    print "Usage: ./writeflag.py [path] [flag]"
    sys.exit(0)

debug = False
main(sys.argv[1], sys.argv[2], debug)
