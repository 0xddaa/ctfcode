#!/usr/bin/python
from pwn import *
import sys
import os

log.warning('Usage: ./exp.py [HOST] [PORT]')

try:
    elf = ELF(os.path.dirname(os.path.abspath(__file__)).split('/')[-1])
    libc = ELF('libc.so.6') if len(sys.argv) > 2 else ELF('local')
except:
    log.warning('Cannot open ELF or glibc.')
    pass

if len(sys.argv) > 2:
    HOST = sys.argv[1]
    PORT = sys.argv[2]
else:
    HOST = 'localhost'
    PORT = 5566

r = remote(HOST, PORT)

r.interactive()
