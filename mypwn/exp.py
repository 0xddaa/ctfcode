#!/usr/bin/env python
import sys, os
from pwn import *

log.warning('Usage: ./exp.py [HOST] [PORT]')
prog = os.path.dirname(os.path.abspath(__file__)).split('/')[-1]
elf = ELF(prog)
if not elf: log.warning('Cannot open ' + prog)
libc = ELF('libc.so.6') if len(sys.argv) > 2 else elf.libc
if not libc: log.warning('Cannot open libc.so.6')
HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
contex.word_size = 64 if '64' in elf.arch else 32 # amd64, aarch64, powerpc64, mips64

r = remote(HOST, PORT)

r.interactive()
