#!/usr/bin/env python
import sys, os
from pwn import *

HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
prog = os.path.dirname(os.path.abspath(__file__)).split('/')[-1]
if not os.path.exists(prog):
    log.warning('{}: No such file or directory'.format(prog))
else:
    elf = ELF(prog); context.word_size = elf.elfclass
    with context.local(log_level='ERROR'):
        libc = ELF('libc.so.6') if len(sys.argv) > 2 else elf.libc
    if not libc: log.warning('Cannot open libc.so.6')

r = remote(HOST, PORT)

r.interactive()
